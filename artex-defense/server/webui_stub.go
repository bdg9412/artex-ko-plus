//go:build !embedui

package server

import "net/http"

// webuiHandler is the no-embed stub (default build). The frontend is NOT bundled
// into this binary — run it separately with `cd web && npm run dev` during
// development. Build the bundled single-binary with:
//
//	cd web && npm run build:static     # produces web/out
//	cp -r web/out server/webui/dist    # (or use the build script)
//	go build -tags embedui ./cmd/artex
func (s *Server) webuiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "이 바이너리에는 프런트엔드가 내장되어 있지 않습니다(개발 시에는 next dev 로 실행하고, 배포용은 -tags embedui 로 빌드하세요).", http.StatusNotFound)
	})
}
