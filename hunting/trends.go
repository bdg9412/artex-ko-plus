package hunting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TrendReport is a source-backed lead for a human to review before starting a
// hunt. Neither a feed mention nor KEV listing attests to an affected asset.
type TrendReport struct {
	TopicKey        string            `json:"topic_key"`
	Term            string            `json:"term"`
	Title           string            `json:"title"`
	Summary         string            `json:"summary"`
	Reason          string            `json:"reason"`
	Priority        string            `json:"priority"`
	Kind            string            `json:"kind"`
	Vendor          string            `json:"vendor,omitempty"`
	Product         string            `json:"product,omitempty"`
	PublishedAt     time.Time         `json:"published_at"`
	References      []TrendReference  `json:"references"`
	AssetMatches    []TrendAssetMatch `json:"asset_matches,omitempty"`
	AssetMatchCount int               `json:"asset_match_count,omitempty"`
}

type TrendReference struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	Title  string `json:"title"`
}

type trendFeed struct {
	name, url, linkHost string
	korean              bool
}

var trendFeeds = []trendFeed{
	{"보안뉴스", "https://cdn.boannews.com/rss/gn_rss_allArticle.xml", "boannews.com", true},
	{"데일리시큐", "https://www.dailysecu.com/rss/allArticle.xml", "dailysecu.com", true},
	{"BleepingComputer", "https://www.bleepingcomputer.com/feed/", "bleepingcomputer.com", false},
	{"The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "thehackernews.com", false},
}

const trendKEVURL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

var trendCVE = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
var trendTag = regexp.MustCompile(`<[^>]*>`)
var trendSpace = regexp.MustCompile(`\s+`)
var trendSecurity = regexp.MustCompile(`(?i)(취약점|침해|악용|공격|랜섬웨어|해킹|보안|vulnerab|exploit|ransomware|malware|breach|attack|zero.day)`)

type TrendCollector struct {
	// HTTPClient is a trusted test adapter. Production uses Researcher's
	// public-IP-pinned client and validates every redirect.
	HTTPClient *http.Client
	Now        func() time.Time
}

func trendClean(s string, max int) string {
	s = trendSpace.ReplaceAllString(html.UnescapeString(trendTag.ReplaceAllString(s, " ")), " ")
	s = strings.TrimSpace(s)
	if len([]rune(s)) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

func trendIDs(s string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range trendCVE.FindAllString(strings.ToUpper(s), -1) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) > 4 {
		return out[:4]
	}
	return out
}

func trendKey(url string) string {
	h := sha256.Sum256([]byte(url))
	return "NEWS-" + hex.EncodeToString(h[:12])
}

func trendDate(s string, korean bool) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	zone := time.UTC
	if korean {
		zone = time.FixedZone("KST", 9*60*60)
	}
	for _, layout := range []string{"Mon, 02 Jan 2006 15:04:05", "02 Jan 2006 15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, zone); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func (c TrendCollector) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c TrendCollector) get(ctx context.Context, client *http.Client, raw string, limit int64) ([]byte, error) {
	u, err := researchURL(raw)
	if err != nil {
		return nil, err
	}
	// The production client repeats this check at connect time and on redirects.
	if c.HTTPClient == nil {
		if _, err := (Researcher{}).addresses(ctx, u.Hostname()); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AegisLoop-RSS/1.0")
	req.Header.Set("Accept", "application/json, application/rss+xml, application/atom+xml, application/xml, text/xml")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("feed size limit")
	}
	return body, nil
}

type trendRSS struct {
	Items []struct {
		Title string `xml:"title"`
		Link  string `xml:"link"`
		Desc  string `xml:"description"`
		Date  string `xml:"pubDate"`
	} `xml:"channel>item"`
	Entries []struct {
		Title   string `xml:"title"`
		Summary string `xml:"summary"`
		Updated string `xml:"updated"`
		Links   []struct {
			Href string `xml:"href,attr"`
			Rel  string `xml:"rel,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

type trendKEV struct {
	Vulnerabilities []struct {
		CVE         string `json:"cveID"`
		Vendor      string `json:"vendorProject"`
		Product     string `json:"product"`
		Name        string `json:"vulnerabilityName"`
		Added       string `json:"dateAdded"`
		Description string `json:"shortDescription"`
	} `json:"vulnerabilities"`
}

// Collect reads a fixed public-source allowlist with a bounded deadline and
// returns reports plus source errors. A failed source does not hide others.
func (c TrendCollector) Collect(ctx context.Context) ([]TrendReport, []string) {
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	now := c.now()
	client := (Researcher{HTTPClient: c.HTTPClient}).client()
	defer client.CloseIdleConnections()
	reports := map[string]*TrendReport{}
	warnings := []string{}
	add := func(r TrendReport) {
		if old := reports[r.TopicKey]; old != nil {
			if r.Kind == "kev" {
				old.Kind, old.Priority, old.Title, old.Summary, old.Reason = r.Kind, r.Priority, r.Title, r.Summary, r.Reason
				old.Vendor, old.Product = r.Vendor, r.Product
			}
			if r.PublishedAt.After(old.PublishedAt) {
				old.PublishedAt = r.PublishedAt
			}
			for _, ref := range r.References {
				if len(old.References) >= 5 {
					break
				}
				found := false
				for _, existing := range old.References {
					found = found || existing.URL == ref.URL
				}
				if !found {
					old.References = append(old.References, ref)
				}
			}
			return
		}
		copy := r
		reports[r.TopicKey] = &copy
	}
	if body, err := c.get(ctx, client, trendKEVURL, 8<<20); err != nil {
		warnings = append(warnings, "CISA KEV 수집 실패")
	} else {
		var feed trendKEV
		if err := json.Unmarshal(body, &feed); err != nil || len(feed.Vulnerabilities) == 0 {
			warnings = append(warnings, "CISA KEV 형식 오류")
		} else {
			for _, v := range feed.Vulnerabilities {
				id := strings.ToUpper(strings.TrimSpace(v.CVE))
				if ids := trendIDs(id); len(ids) != 1 || ids[0] != id {
					continue
				}
				date := trendDate(v.Added, false)
				if date.IsZero() {
					continue
				}
				if date.Before(now.Add(-14*24*time.Hour)) || date.After(now.Add(24*time.Hour)) {
					continue
				}
				add(TrendReport{TopicKey: id, Term: id, Title: trendClean(v.Name, 240), Summary: trendClean(v.Description, 1200), Reason: "CISA KEV에 실제 악용 사례가 알려진 취약점으로 신규 등재. 자산 사용 여부와 로그 근거 확인 필요", Priority: "high", Kind: "kev", Vendor: trendClean(v.Vendor, 120), Product: trendClean(v.Product, 160), PublishedAt: date, References: []TrendReference{{Source: "CISA KEV", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", Title: "CISA KEV 목록"}, {Source: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + id, Title: id + " 상세"}}})
			}
		}
	}
	for _, source := range trendFeeds {
		body, err := c.get(ctx, client, source.url, 2<<20)
		if err != nil {
			warnings = append(warnings, source.name+" 수집 실패")
			continue
		}
		var feed trendRSS
		if err := xml.Unmarshal(body, &feed); err != nil || len(feed.Items)+len(feed.Entries) == 0 {
			warnings = append(warnings, source.name+" 피드 형식 오류")
			continue
		}
		addArticle := func(title, link, desc, published string) {
			title, desc = trendClean(title, 200), trendClean(desc, 1200)
			if title == "" || !trendSecurity.MatchString(title+" "+desc) {
				return
			}
			u, err := researchURL(link)
			if err != nil || (u.Hostname() != source.linkHost && !strings.HasSuffix(u.Hostname(), "."+source.linkHost)) {
				return
			}
			date := trendDate(published, source.korean)
			if date.IsZero() {
				return
			}
			if date.Before(now.Add(-7*24*time.Hour)) || date.After(now.Add(5*time.Minute)) {
				return
			}
			ids := trendIDs(title + " " + desc)
			if len(ids) == 0 {
				ids = []string{trendKey(link)}
			}
			for _, key := range ids {
				term := key
				if strings.HasPrefix(key, "NEWS-") {
					term = title
				}
				priority := "review"
				reason := "최근 보안 보도. 제품·자산 관련성과 원문을 확인한 뒤 헌팅 여부 결정"
				if strings.HasPrefix(key, "CVE-") {
					priority = "medium"
					reason = "최근 보도에서 CVE가 언급됨. 영향 제품·버전과 자산 사용 여부 확인 필요"
				}
				add(TrendReport{TopicKey: key, Term: term, Title: title, Summary: desc, Reason: reason, Priority: priority, Kind: "news", PublishedAt: date, References: []TrendReference{{Source: source.name, URL: link, Title: title}}})
			}
		}
		for i, item := range feed.Items {
			if i >= 30 {
				break
			}
			addArticle(item.Title, strings.TrimSpace(item.Link), item.Desc, item.Date)
		}
		for i, item := range feed.Entries {
			if i >= 30 {
				break
			}
			link := ""
			for _, candidate := range item.Links {
				if candidate.Rel == "" || candidate.Rel == "alternate" {
					link = candidate.Href
					break
				}
			}
			addArticle(item.Title, link, item.Summary, item.Updated)
		}
	}
	out := make([]TrendReport, 0, len(reports))
	for _, report := range reports {
		out = append(out, *report)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority == "high" || out[i].Priority == "medium" && out[j].Priority == "review"
		}
		return out[i].PublishedAt.After(out[j].PublishedAt)
	})
	if len(out) > 120 {
		out = out[:120]
	}
	return out, warnings
}
