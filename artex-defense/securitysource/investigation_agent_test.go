package securitysource

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

func TestInvestigationAgentFiltersRemainLiteralAndScoped(t *testing.T) {
	c, _ := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("query preview used network") })
	query, err := BuildInvestigationFilteredSearch(c, historicalScope(), investigation.DefaultMapping(), []string{"auth"}, InvestigationFilters{User: `a" | delete | "b`, PathContains: `a.*[x]`})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, `sourcetype="auth"`) || !strings.Contains(query, `tostring('user') = "a\" | delete | \"b"`) || !strings.Contains(query, `"a\\.\\*\\[x\\]"`) || !strings.HasSuffix(query, " | head 10001") {
		t.Fatal("unsafe generated literal or missing bounds", query)
	}
	bad := investigation.DefaultMapping()
	bad.User = ""
	if _, err = BuildInvestigationFilteredSearch(c, historicalScope(), bad, nil, InvestigationFilters{User: "alice"}); err == nil {
		t.Fatal("unmapped pivot accepted")
	}
	if _, err = BuildInvestigationFilteredSearch(c, historicalScope(), investigation.DefaultMapping(), nil, InvestigationFilters{User: "alice\n"}); err == nil {
		t.Fatal("control character accepted")
	}
}

func TestInvestigationAgentFiltersPreserveRawButExcludeUnrelatedRows(t *testing.T) {
	scope := historicalScope()
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if !strings.Contains(r.Form.Get("search"), `where tostring('user') = "alice"`) {
			t.Error("missing pivot")
		}
		at := scope.Start.Add(time.Hour).Format(time.RFC3339Nano)
		fmt.Fprintf(w, "{\"result\":{\"_time\":%q,\"id\":\"alice-1\",\"target\":\"juice-shop:3000\",\"path\":\"/ftp/a\",\"user\":\"alice\"}}\n", at)
		fmt.Fprintf(w, "{\"lastrow\":true,\"result\":{\"_time\":%q,\"id\":\"bob-1\",\"target\":\"juice-shop:3000\",\"path\":\"/ftp/b\",\"user\":\"bob\"}}\n", at)
	})
	result, err := FetchInvestigationFiltered(t.Context(), c, auth, scope, investigation.DefaultMapping(), nil, nil, InvestigationFilters{User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].ID != "alice-1" || result.Stats.Selected != 1 {
		t.Fatal("wrong identity selected", result.Events)
	}
	if len(result.Files) != 2 || !strings.Contains(result.Files[1].Content, "bob-1") {
		t.Fatal("original export changed by analysis filter")
	}
}
