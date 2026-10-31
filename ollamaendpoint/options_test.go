package ollamaendpoint

import "testing"

func TestRemoteURLAndCredentialBoundary(t *testing.T) {
	for _, raw := range []string{"", "file:///tmp/model", "http://user:secret@host/v1", "https://host/v1?token=x", "https://host/v1#x"} {
		if _, err := NormalizeURL(raw); err == nil {
			t.Errorf("accepted unsafe/empty URL %q", raw)
		}
	}
	for _, raw := range []string{"http://MODEL-PC:11434", "http://model-pc:11434/v1/", "http://model-pc:11434/v1/chat/completions/"} {
		got, err := NormalizeURL(raw)
		if err != nil || got != "http://model-pc:11434/v1" {
			t.Fatalf("normalize %q = %q, %v", raw, got, err)
		}
	}
	auth := Options{AuthMode: "bearer"}
	if !ReuseKey(Remote, "https://a/v1", auth, "https://a/v1/", auth) {
		t.Fatal("same server lost its key")
	}
	if ReuseKey("openai", "https://a/v1", auth, "https://a/v1", auth) || ReuseKey(Remote, "https://a/v1", auth, "https://b/v1", auth) || ReuseKey(Remote, "https://a/v1", Options{}, "https://a/v1", auth) {
		t.Fatal("cross-provider/server token reuse")
	}
}

func TestRemoteLimits(t *testing.T) {
	defaults := (Options{}).Resolved()
	if defaults.MaxConcurrent != 1 || defaults.QueueTimeoutSeconds != 120 || defaults.RequestTimeoutSeconds != 600 || defaults.AuthMode != "none" {
		t.Fatalf("defaults: %+v", defaults)
	}
	for _, o := range []Options{{AuthMode: "basic"}, {MaxConcurrent: -1}, {MaxConcurrent: 9}, {QueueTimeoutSeconds: 3601}, {RequestTimeoutSeconds: 1}, {RequestTimeoutSeconds: 7201}} {
		if o.Validate() == nil {
			t.Errorf("accepted invalid limits %+v", o)
		}
	}
}
