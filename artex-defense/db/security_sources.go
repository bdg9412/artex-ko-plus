package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/securitysource"
)

var ErrSecuritySourceNotFound = errors.New("보안 로그 연결을 찾을 수 없습니다")

type SecuritySource struct {
	ID            int64                 `json:"id,string"`
	Name          string                `json:"name"`
	Revision      int64                 `json:"revision"`
	Config        securitysource.Config `json:"config"`
	Enabled       bool                  `json:"enabled"`
	CredentialSet bool                  `json:"credential_set"`
	SecretCipher  []byte                `json:"-"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

const securitySourceColumns = `id,name,revision,config,secret_cipher,enabled,updated_at`

func scanSecuritySource(row interface{ Scan(...any) error }) (*SecuritySource, error) {
	s := &SecuritySource{}
	var raw []byte
	if e := row.Scan(&s.ID, &s.Name, &s.Revision, &raw, &s.SecretCipher, &s.Enabled, &s.UpdatedAt); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return nil, ErrSecuritySourceNotFound
		}
		return nil, e
	}
	if e := json.Unmarshal(raw, &s.Config); e != nil {
		return nil, e
	}
	s.CredentialSet = len(s.SecretCipher) > 0
	return s, nil
}
func (d *DB) GetSecuritySource(ctx context.Context, id int64) (*SecuritySource, error) {
	return scanSecuritySource(d.QueryRowContext(ctx, `SELECT `+securitySourceColumns+` FROM security_sources WHERE id=$1`, id))
}
func (d *DB) ListSecuritySources(ctx context.Context) ([]*SecuritySource, error) {
	rows, e := d.QueryContext(ctx, `SELECT `+securitySourceColumns+` FROM security_sources ORDER BY id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []*SecuritySource{}
	for rows.Next() {
		s, e := scanSecuritySource(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (d *DB) SaveSecuritySource(ctx context.Context, id, expected int64, name string, cfg securitysource.Config, enabled bool, cipher []byte) (*SecuritySource, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || strings.ContainsRune(name, 0) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 120 {
		return nil, ErrDefenseInvalid
	}
	var e error
	cfg, e = securitysource.Validate(cfg)
	if e != nil {
		return nil, e
	}
	if id < 0 || expected < 0 {
		return nil, ErrDefenseInvalid
	}
	tx, e := d.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if id == 0 {
		if expected != 0 || len(cipher) == 0 {
			return nil, ErrDefenseInvalid
		}
		raw, _ := json.Marshal(cfg)
		s, e := scanSecuritySource(tx.QueryRowContext(ctx, `INSERT INTO security_sources(name,revision,config,secret_cipher,enabled) VALUES($1,1,$2,$3,$4) RETURNING `+securitySourceColumns, name, raw, cipher, enabled))
		if e != nil {
			return nil, e
		}
		return s, tx.Commit()
	}
	old, e := scanSecuritySource(tx.QueryRowContext(ctx, `SELECT `+securitySourceColumns+` FROM security_sources WHERE id=$1 FOR UPDATE`, id))
	if e != nil {
		return nil, e
	}
	if old.Revision != expected {
		return nil, ErrDefenseConflict
	}
	if len(cipher) == 0 {
		if old.Config.BaseURL != cfg.BaseURL {
			return nil, errors.New("연결 주소를 변경할 때 인증 정보를 다시 입력해 주세요")
		}
		cipher = old.SecretCipher
	}
	if old.Name == name && old.Config == cfg && old.Enabled == enabled && string(old.SecretCipher) == string(cipher) {
		return old, tx.Commit()
	}
	raw, _ := json.Marshal(cfg)
	s, e := scanSecuritySource(tx.QueryRowContext(ctx, `UPDATE security_sources SET name=$2,revision=revision+1,config=$3,secret_cipher=$4,enabled=$5,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+securitySourceColumns, id, name, raw, cipher, enabled))
	if e != nil {
		return nil, e
	}
	return s, tx.Commit()
}
