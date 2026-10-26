package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/guard"
	"github.com/google/uuid"
)

func TestDiagnosticArtifactToolOnlyReadsManifestVerifiedFile(t *testing.T) {
	root := t.TempDir()
	runID := uuid.NewString()
	directory := filepath.Join(root, "offensive", "diagnostics", runID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"source":"http_probe","body_preview":"lab evidence"}`)
	name := "http-probe.json"
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	secret := filepath.Join(root, "secret.txt")
	secretData := []byte("must-not-be-read")
	if err := os.WriteFile(secret, secretData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(directory, "linked.json")); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(map[string]any{"id": runID, "artifacts": []map[string]any{
		{"name": name, "sha256": hash, "size": len(data)},
		{"name": "linked.json", "sha256": fmt.Sprintf("%x", sha256.Sum256(secretData)), "size": len(secretData)},
	}})
	if err := os.WriteFile(filepath.Join(directory, "run.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	if err := g.SetDiagnosticScope([]string{"http://lab.local/"}); err != nil {
		t.Fatal(err)
	}
	if err := g.SetDiagnosticRunID(runID); err != nil {
		t.Fatal(err)
	}
	tool := diagnosticArtifactTool(g, root)
	call := func(name string) string {
		t.Helper()
		input, _ := json.Marshal(map[string]string{"name": name})
		result, err := tool.Call(context.Background(), input, nil)
		if err != nil {
			t.Fatal(err)
		}
		return result.Flatten()
	}
	if got := call(name); !strings.Contains(got, "lab evidence") || !strings.Contains(got, hash) {
		t.Fatalf("registered evidence not returned: %s", got)
	}
	for _, bad := range []string{"../secret.txt", "run.json", "linked.json", "missing.json"} {
		if got := call(bad); strings.Contains(got, "must-not-be-read") || strings.Contains(got, "lab evidence") {
			t.Errorf("unregistered path %q returned content: %s", bad, got)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := call(name); !strings.Contains(got, "해시 또는 크기") {
		t.Fatalf("tampered artifact was accepted: %s", got)
	}
}

func TestDiagnosticArtifactToolPagesVerifiedUTF8Evidence(t *testing.T) {
	root := t.TempDir()
	runID := uuid.NewString()
	directory := filepath.Join(root, "offensive", "diagnostics", runID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"text":"` + strings.Repeat("가", 4000) + `"}`)
	name := "long-evidence.json"
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	manifest, _ := json.Marshal(map[string]any{"id": runID, "artifacts": []map[string]any{
		{"name": name, "sha256": hash, "size": len(data)},
	}})
	if err := os.WriteFile(filepath.Join(directory, "run.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	g := guard.New()
	if err := g.SetDiagnosticScope([]string{"http://lab.local/"}); err != nil {
		t.Fatal(err)
	}
	if err := g.SetDiagnosticRunID(runID); err != nil {
		t.Fatal(err)
	}
	tool := diagnosticArtifactTool(g, root)
	var full strings.Builder
	for offset, pages := 0, 0; ; pages++ {
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		input, _ := json.Marshal(map[string]any{"name": name, "offset": offset})
		result, err := tool.Call(context.Background(), input, nil)
		if err != nil {
			t.Fatal(err)
		}
		var page struct {
			Content    string `json:"content"`
			Offset     int    `json:"offset"`
			NextOffset int    `json:"next_offset"`
			HasMore    bool   `json:"has_more"`
			SHA256     string `json:"sha256"`
		}
		if err := json.Unmarshal([]byte(result.Flatten()), &page); err != nil {
			t.Fatalf("decode page: %v: %s", err, result.Flatten())
		}
		if page.Offset != offset || page.NextOffset <= offset || page.NextOffset-offset > diagnosticArtifactChunkBytes || page.SHA256 != hash {
			t.Fatalf("invalid page at offset %d: %+v", offset, page)
		}
		full.WriteString(page.Content)
		if !page.HasMore {
			if page.NextOffset != len(data) {
				t.Fatalf("final offset=%d, want %d", page.NextOffset, len(data))
			}
			break
		}
		offset = page.NextOffset
	}
	if full.String() != string(data) {
		t.Fatal("paginated content does not reconstruct the verified artifact")
	}
}
