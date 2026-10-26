package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestDiagnosticWorkerAssetsBoundsPermanentPromptAndKeepsIDs(t *testing.T) {
	assets := make([]*db.Asset, 13)
	for i := range assets {
		assets[i] = &db.Asset{ID: int64(i + 1), Type: "endpoint", URL: "http://lab.local/api/x", Extra: map[string]any{"body": strings.Repeat("x", 50_000)}}
	}
	assets[0].URL = "http://lab.local/?q=" + strings.Repeat("a", 600)
	got := diagnosticWorkerAssets(assets)
	ids, ok := got["asset_ids"].([]int64)
	if !ok || len(ids) != len(assets) || ids[12] != 13 {
		t.Fatalf("all asset ids must remain available: %#v", got["asset_ids"])
	}
	preview, ok := got["assets"].([]map[string]any)
	if !ok || len(preview) != 12 || preview[0]["url_omitted"] != true {
		t.Fatalf("preview must be bounded and identify long URLs: %#v", got["assets"])
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= 4096 || strings.Contains(string(b), strings.Repeat("x", 100)) {
		t.Fatalf("diagnostic asset prompt includes bulk metadata: %d bytes", len(b))
	}
}
