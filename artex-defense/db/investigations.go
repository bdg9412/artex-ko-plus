package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

var ErrInvestigationNotFound = errors.New("침해 조사 기록을 찾을 수 없습니다")

// Historical investigations never depend on a newly generated retest UUID.
// Each saved record is an immutable snapshot; new evidence creates a new record.
type FindingInvestigation struct {
	ID                int64                        `json:"id,string"`
	FindingID         int64                        `json:"finding_id,string"`
	Title             string                       `json:"title"`
	Question          string                       `json:"question"`
	SourceKind        string                       `json:"source_kind"`
	SourceID          int64                        `json:"source_id,string"`
	SourceRevision    int64                        `json:"source_revision"`
	SourceSnapshot    json.RawMessage              `json:"source_snapshot"`
	Scope             investigation.Scope          `json:"scope"`
	Mapping           investigation.Mapping        `json:"mapping"`
	Plan              investigation.Plan           `json:"plan"`
	FindingSnapshot   investigation.FindingContext `json:"finding_snapshot"`
	Collection        investigation.Collection     `json:"collection"`
	Analysis          investigation.Analysis       `json:"analysis"`
	EvidenceVersion   int64                        `json:"evidence_version"`
	SourceFingerprint string                       `json:"source_fingerprint"`
	CreatedAt         time.Time                    `json:"created_at"`
	State             string                       `json:"state"`
}
type InvestigationSummary struct {
	ID         int64     `json:"id,string"`
	Title      string    `json:"title"`
	SourceKind string    `json:"source_kind"`
	Summary    string    `json:"summary"`
	CreatedAt  time.Time `json:"created_at"`
	State      string    `json:"state"`
}
type InvestigationOverview struct {
	Plan              investigation.Plan           `json:"plan"`
	Targets           []string                     `json:"targets"`
	RecommendedPath   string                       `json:"recommended_path"`
	Mapping           investigation.Mapping        `json:"mapping"`
	EvidenceVersion   int64                        `json:"evidence_version"`
	SourceFingerprint string                       `json:"source_fingerprint"`
	Investigations    []InvestigationSummary       `json:"investigations"`
	HistoryTruncated  bool                         `json:"history_truncated"`
	Context           investigation.FindingContext `json:"-"`
}

// Include source assets so host/port changes invalidate existing plans/results.
const investigationContextSQL = `jsonb_build_object('name',f.name,'vuln_class',f.vulnclass,'summary',f.summary,'evidence',f.evidence,
 'assets',COALESCE((SELECT jsonb_agg(jsonb_build_object('url',COALESCE(a.url,''),'domain',COALESCE(a.domain,''),'ip',COALESCE(a.ip,''),'port',COALESCE(a.port,0)) ORDER BY a.id)
 FROM assets a WHERE f.asset_ids @> to_jsonb(ARRAY[a.id])),'[]'::jsonb))`
const investigationFingerprintSQL = `md5(jsonb_build_array(f.evidence_version,` + investigationContextSQL + `)::text)`

func investigationContextTx(ctx context.Context, tx *sql.Tx, findingID int64) (*InvestigationOverview, error) {
	out := &InvestigationOverview{Targets: []string{}, Investigations: []InvestigationSummary{}, Mapping: investigation.DefaultMapping()}
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT f.evidence_version,`+investigationFingerprintSQL+`,`+investigationContextSQL+` FROM findings f WHERE f.id=$1`, findingID).Scan(&out.EvidenceVersion, &out.SourceFingerprint, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrFindingNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &out.Context); err != nil {
		return nil, err
	}
	out.Plan = investigation.BuildPlan(out.Context)
	seen := map[string]bool{}
	for _, asset := range out.Context.Assets {
		target := ""
		if u, e := url.Parse(asset.URL); e == nil && (u.Scheme == "http" || u.Scheme == "https") {
			target = u.Host
			if u.Path != "" && u.Path != "/" && (out.RecommendedPath == "" || len(u.Path) < len(out.RecommendedPath)) {
				out.RecommendedPath = u.Path
			}
		}
		if target == "" {
			target = asset.Domain
			if target == "" {
				target = asset.IP
			}
			if target != "" && asset.Port > 0 {
				if strings.Contains(target, ":") && !strings.HasPrefix(target, "[") {
					target = "[" + target + "]"
				}
				target = fmt.Sprintf("%s:%d", target, asset.Port)
			}
		}
		target = strings.ToLower(target)
		if target != "" && !seen[target] {
			out.Targets = append(out.Targets, target)
			seen[target] = true
		}
	}
	sort.Strings(out.Targets)
	return out, nil
}

func (d *DB) GetInvestigationOverview(ctx context.Context, findingID int64) (*InvestigationOverview, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := investigationContextTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,payload->>'title',payload->>'source_kind',payload#>>'{analysis,summary}',created_at,
 CASE WHEN evidence_version=$2 AND source_fingerprint=$3 THEN 'current' ELSE 'stale' END
 FROM finding_investigations WHERE finding_id=$1 ORDER BY id DESC LIMIT 31`, findingID, out.EvidenceVersion, out.SourceFingerprint)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item InvestigationSummary
		if err = rows.Scan(&item.ID, &item.Title, &item.SourceKind, &item.Summary, &item.CreatedAt, &item.State); err != nil {
			rows.Close()
			return nil, err
		}
		if len(out.Investigations) == 30 {
			out.HistoryTruncated = true
			break
		}
		out.Investigations = append(out.Investigations, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

type InvestigationVerification struct {
	ID         string
	Start, End time.Time
}

func (d *DB) KnownInvestigationVerifications(ctx context.Context, findingID int64) ([]InvestigationVerification, error) {
	// Match the same finding and its actual run window, not a bare header value.
	rows, err := d.QueryContext(ctx, `SELECT e.correlation_id::text,`+executionRetestSQL+` FROM finding_defense_executions e LEFT JOIN finding_retests r ON r.id=e.retest_id AND r.finding_id=e.finding_id WHERE e.finding_id=$1 ORDER BY e.id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InvestigationVerification{}
	for rows.Next() {
		var item InvestigationVerification
		var raw []byte
		if err = rows.Scan(&item.ID, &raw); err != nil {
			return nil, err
		}
		var retest FindingRetest
		if err = json.Unmarshal(raw, &retest); err != nil {
			return nil, err
		}
		if retest.StartedAt == nil || retest.FinishedAt == nil {
			continue
		}
		item.Start = retest.StartedAt.Add(-30 * time.Second)
		item.End = retest.FinishedAt.Add(time.Minute)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (d *DB) SaveFindingInvestigation(ctx context.Context, findingID int64, in FindingInvestigation) (*FindingInvestigation, error) {
	var err error
	if in.Title, err = defenseText(in.Title, "조사 제목", 1, 200); err != nil {
		return nil, err
	}
	if in.Question, err = defenseText(in.Question, "조사 질문", 0, 4000); err != nil {
		return nil, err
	}
	if in.SourceKind != "file" && in.SourceKind != "splunk" {
		return nil, ErrDefenseInvalid
	}
	if err = investigation.ValidateScope(in.Scope, time.Now()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDefenseInvalid, err)
	}
	if err = investigation.ValidateMapping(in.Mapping); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDefenseInvalid, err)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, err
	}
	current, err := investigationContextTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	if current.EvidenceVersion != in.EvidenceVersion || current.SourceFingerprint != in.SourceFingerprint {
		return nil, ErrDefenseConflict
	}
	if in.SourceKind == "splunk" {
		var revision int64
		var enabled bool
		if err = tx.QueryRowContext(ctx, `SELECT revision,enabled FROM security_sources WHERE id=$1 FOR SHARE`, in.SourceID).Scan(&revision, &enabled); err != nil {
			return nil, ErrSecuritySourceNotFound
		}
		if !enabled || revision != in.SourceRevision {
			return nil, ErrDefenseConflict
		}
	} else if in.SourceID != 0 || in.SourceRevision != 0 {
		return nil, ErrDefenseInvalid
	}
	in.ID = 0
	in.FindingID = findingID
	in.Plan = current.Plan
	in.FindingSnapshot = current.Context
	in.State = "current"
	in.CreatedAt = time.Time{}
	// Recompute from the authoritative plan and parsed collection, never a client verdict.
	in.Analysis = investigation.Analyze(in.Plan, in.Scope, in.Collection)
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	if len(raw) > 32<<20 {
		return nil, fmt.Errorf("%w: 조사 기록이 너무 큽니다", ErrDefenseInvalid)
	}
	if err = tx.QueryRowContext(ctx, `INSERT INTO finding_investigations(finding_id,evidence_version,source_fingerprint,payload) VALUES($1,$2,$3,$4) RETURNING id,created_at`, findingID, in.EvidenceVersion, in.SourceFingerprint, raw).Scan(&in.ID, &in.CreatedAt); err != nil {
		return nil, err
	}
	return &in, tx.Commit()
}

func (d *DB) GetFindingInvestigation(ctx context.Context, findingID, id int64) (*FindingInvestigation, error) {
	var raw []byte
	var created time.Time
	var state string
	err := d.QueryRowContext(ctx, `SELECT i.payload,i.created_at,CASE WHEN i.evidence_version=f.evidence_version AND i.source_fingerprint=`+investigationFingerprintSQL+` THEN 'current' ELSE 'stale' END FROM finding_investigations i JOIN findings f ON f.id=i.finding_id WHERE i.finding_id=$1 AND i.id=$2`, findingID, id).Scan(&raw, &created, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvestigationNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &FindingInvestigation{}
	if err = json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	out.ID = id
	out.FindingID = findingID
	out.CreatedAt = created
	out.State = state
	return out, nil
}
