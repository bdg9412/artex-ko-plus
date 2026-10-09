package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"unicode"

	"github.com/Autumn-27/artex/agent"
)

func TestShutdownContextPreservesNamedCause(t *testing.T) {
	signalCtx, signalCancel := context.WithCancel(context.Background())
	ctx, shutdown := shutdownContext(signalCtx)
	defer shutdown(nil)
	signalCancel()
	<-ctx.Done()
	if code, _, _, ok := agent.AbortReason(ctx); !ok || code != "shutdown" {
		t.Fatalf("code=%q ok=%v, want shutdown", code, ok)
	}
}

// TestPrintBannerLocalized verifies that the startup banner printed to stdout is
// Korean and carries no leftover CJK Han characters. This is the first thing a
// user sees when running ARTEX, so it must not stay in Chinese (backlog F11).
// The "[config] ..." log lines in run() are intentionally out of scope — they
// are logs, which the localization brief ranks lowest (backlog Z2).
func TestPrintBannerLocalized(t *testing.T) {
	out := captureStdout(t, func() { printBanner(":8787") })
	t.Logf("배너 샘플:\n%s", out)

	hasHangul := strings.ContainsFunc(out, func(r rune) bool {
		return unicode.Is(unicode.Hangul, r)
	})
	if !hasHangul {
		t.Fatalf("배너에 한글이 없다: %q", out)
	}

	for _, want := range []string{"자율 침투 테스트 시스템", "버전", "수신 대기", ":8787"} {
		if !strings.Contains(out, want) {
			t.Errorf("배너에 %q 가 없다: %q", want, out)
		}
	}

	for _, r := range out {
		if unicode.Is(unicode.Han, r) {
			t.Errorf("배너에 CJK 한자 잔재(%q): %q", r, out)
		}
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns whatever
// fn wrote. printBanner uses fmt.Print*, which resolves os.Stdout at call time,
// so swapping it here captures the banner.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}
