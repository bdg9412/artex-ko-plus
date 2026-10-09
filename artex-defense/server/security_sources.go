package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
)

func (s *Server) registerSecuritySources(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/purple/sources", s.listSecuritySources)
	mux.HandleFunc("POST /api/purple/sources", s.saveSecuritySource)
	mux.HandleFunc("PUT /api/purple/sources/{sourceID}", s.saveSecuritySource)
	mux.HandleFunc("POST /api/purple/sources/{sourceID}/test", s.testSecuritySource)
}
func (s *Server) sourceCipher() (cipher.AEAD, error) {
	if len(s.jwtKey) == 0 {
		return nil, errors.New("연결 인증 정보 암호화 키가 없습니다")
	}
	key := sha256.Sum256(append([]byte("artex-security-sources/v1\x00"), s.jwtKey...))
	block, e := aes.NewCipher(key[:])
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func (s *Server) encryptSourceCredentials(c securitysource.Credentials) ([]byte, error) {
	a, e := s.sourceCipher()
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, raw, []byte("security-source-credentials/v1")), nil
}
func (s *Server) securitySourceCredentials(source *db.SecuritySource) (securitysource.Credentials, error) {
	c := securitysource.Credentials{}
	a, e := s.sourceCipher()
	if e != nil {
		return c, e
	}
	if len(source.SecretCipher) < a.NonceSize() {
		return c, errors.New("저장된 인증 정보를 읽지 못했습니다. 다시 입력해 주세요")
	}
	nonce := source.SecretCipher[:a.NonceSize()]
	raw, e := a.Open(nil, nonce, source.SecretCipher[a.NonceSize():], []byte("security-source-credentials/v1"))
	if e != nil {
		return c, errors.New("저장된 인증 정보를 복호화하지 못했습니다. 다시 입력해 주세요")
	}
	if json.Unmarshal(raw, &c) != nil {
		return c, errors.New("연결 인증 정보 형식이 올바르지 않습니다")
	}
	return c, securitysource.ValidateCredentials(c)
}
func sourceError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, securitysource.ErrInvalid), errors.Is(e, db.ErrDefenseInvalid):
		writeErr(w, 400, e.Error())
	case errors.Is(e, db.ErrDefenseConflict):
		writeErr(w, 409, "연결 설정이 변경됐습니다. 새로고침 후 다시 저장해 주세요")
	case errors.Is(e, db.ErrSecuritySourceNotFound):
		writeErr(w, 404, e.Error())
	default:
		writeErr(w, 500, "보안 로그 연결을 처리하지 못했습니다")
	}
}
func (s *Server) listSecuritySources(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rows, e := pg.ListSecuritySources(r.Context())
	if e != nil {
		sourceError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sources": rows})
}
func (s *Server) saveSecuritySource(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name             string                `json:"name"`
		Config           securitysource.Config `json:"config"`
		Enabled          bool                  `json:"enabled"`
		ExpectedRevision int64                 `json:"expected_revision"`
		Username         string                `json:"username"`
		Password         string                `json:"password"`
		Token            string                `json:"token"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 64<<10) {
		return
	}
	var id int64
	if r.Method == http.MethodPut {
		var ok bool
		id, ok = pathInt(r, "sourceID")
		if !ok || id <= 0 {
			writeErr(w, 400, "연결 ID를 확인해 주세요")
			return
		}
	}
	cfg, e := securitysource.Validate(in.Config)
	if e != nil {
		sourceError(w, e)
		return
	}
	var encrypted []byte
	if in.Username != "" || in.Password != "" || in.Token != "" {
		c := securitysource.Credentials{Username: in.Username, Password: in.Password, Token: in.Token}
		if e = securitysource.ValidateCredentials(c); e != nil {
			sourceError(w, e)
			return
		}
		encrypted, e = s.encryptSourceCredentials(c)
		if e != nil {
			sourceError(w, e)
			return
		}
	}
	if id == 0 && len(encrypted) == 0 {
		writeErr(w, 400, "연결 인증 정보를 입력해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// Credentials are never silently forwarded to a changed endpoint.
	if id > 0 && len(encrypted) == 0 {
		old, e := pg.GetSecuritySource(r.Context(), id)
		if e != nil {
			sourceError(w, e)
			return
		}
		if old.Config.BaseURL != cfg.BaseURL {
			writeErr(w, 400, "연결 주소를 변경할 때 인증 정보를 다시 입력해 주세요")
			return
		}
	}
	out, e := pg.SaveSecuritySource(r.Context(), id, in.ExpectedRevision, in.Name, cfg, in.Enabled, encrypted)
	if e != nil {
		sourceError(w, e)
		return
	}
	code := 200
	if id == 0 {
		code = 201
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, code, out)
}
func (s *Server) testSecuritySource(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "sourceID")
	if !ok || id <= 0 {
		writeErr(w, 400, "연결 ID를 확인해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	source, e := pg.GetSecuritySource(r.Context(), id)
	if e != nil {
		sourceError(w, e)
		return
	}
	auth, e := s.securitySourceCredentials(source)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if e = securitysource.Test(ctx, source.Config, auth); e != nil {
		writeErr(w, 502, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "detail": "Splunk 관리 API 연결과 인증을 확인했습니다. 실제 로그·경보 조회는 진단 실행별로 검증합니다"})
}
