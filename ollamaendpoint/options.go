// Package ollamaendpoint defines the connection settings shared by remote
// Ollama profiles, metadata requests and model calls.
package ollamaendpoint

import (
	"fmt"
	"net/url"
	"strings"
)

const Remote = "ollama-remote"

type Options struct {
	AuthMode              string `json:"auth_mode,omitempty"`
	MaxConcurrent         int    `json:"max_concurrent,omitempty"`
	QueueTimeoutSeconds   int    `json:"queue_timeout_seconds,omitempty"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds,omitempty"`
}

func (o Options) Resolved() Options {
	if o.AuthMode == "" {
		o.AuthMode = "none"
	}
	if o.MaxConcurrent == 0 {
		o.MaxConcurrent = 1
	}
	if o.QueueTimeoutSeconds == 0 {
		o.QueueTimeoutSeconds = 120
	}
	if o.RequestTimeoutSeconds == 0 {
		o.RequestTimeoutSeconds = 600
	}
	return o
}

func (o Options) Validate() error {
	o = o.Resolved()
	if o.AuthMode != "none" && o.AuthMode != "bearer" {
		return fmt.Errorf("remote Ollama auth_mode must be none or bearer")
	}
	if o.MaxConcurrent < 1 || o.MaxConcurrent > 8 {
		return fmt.Errorf("remote Ollama max_concurrent must be between 1 and 8")
	}
	if o.QueueTimeoutSeconds < 1 || o.QueueTimeoutSeconds > 3600 {
		return fmt.Errorf("remote Ollama queue timeout must be between 1 and 3600 seconds")
	}
	if o.RequestTimeoutSeconds < 5 || o.RequestTimeoutSeconds > 7200 {
		return fmt.Errorf("remote Ollama request timeout must be between 5 and 7200 seconds")
	}
	return nil
}

// NormalizeURL requires an explicit destination: remote mode must never silently
// fall back to the ARTEX host. Userinfo and redirects are not credential stores.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("remote Ollama requires an explicit HTTP(S) server URL without userinfo, query or fragment")
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/chat/completions")
	if !strings.HasSuffix(u.Path, "/v1") {
		u.Path += "/v1"
	}
	u.RawPath = ""
	return u.String(), nil
}

func SameServer(a, b string) bool {
	x, e1 := NormalizeURL(a)
	y, e2 := NormalizeURL(b)
	return e1 == nil && e2 == nil && x == y
}

// ReuseKey prevents a saved cloud token, or a token for another server, from
// being silently sent to a newly selected endpoint.
func ReuseKey(oldFormat, oldURL string, old Options, newURL string, next Options) bool {
	return oldFormat == Remote && old.Resolved().AuthMode == "bearer" && next.Resolved().AuthMode == "bearer" && SameServer(oldURL, newURL)
}
