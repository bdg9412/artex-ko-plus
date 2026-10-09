package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvestigationRunNotFound = errors.New("침해 조사 실행을 찾을 수 없습니다")
	ErrInvestigationRunInactive = errors.New("침해 조사 실행이 종료되었거나 아직 시작되지 않았습니다")
)

// Runs refer to immutable, locally collected evidence. They never rewrite the
// base investigation; tool evidence and the model's inferences are separate.
type InvestigationRun struct {
	ID              int64                   `json:"id,string"`
	FindingID       int64                   `json:"finding_id,string"`
	InvestigationID int64                   `json:"investigation_id,string"`
	Status          string                  `json:"status"`
	Options         json.RawMessage         `json:"options"`
	Events          []InvestigationRunEvent `json:"events"`
	Result          json.RawMessage         `json:"result"`
	Usage           InvestigationRunUsage   `json:"usage"`
	Error           string                  `json:"error"`
	CreatedAt       time.Time               `json:"created_at"`
	StartedAt       *time.Time              `json:"started_at"`
	FinishedAt      *time.Time              `json:"finished_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
}

type InvestigationRunEvent struct {
	Sequence  int             `json:"sequence"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}

// Usage is cumulative. Updates cannot decrease counters and erase spent budget.
type InvestigationRunUsage struct {
	ModelCalls   int64 `json:"model_calls"`
	Queries      int64 `json:"queries"`
	Rounds       int64 `json:"rounds"`
	ToolCalls    int64 `json:"tool_calls"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type InvestigationRunSummary struct {
	ID              int64                 `json:"id,string"`
	FindingID       int64                 `json:"finding_id,string"`
	InvestigationID int64                 `json:"investigation_id,string"`
	Status          string                `json:"status"`
	Usage           InvestigationRunUsage `json:"usage"`
	Error           string                `json:"error"`
	CreatedAt       time.Time             `json:"created_at"`
	StartedAt       *time.Time            `json:"started_at"`
	FinishedAt      *time.Time            `json:"finished_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

const investigationRunCols = `id,finding_id,investigation_id,status,options,events,result,rounds,model_calls,queries,tool_calls,input_tokens,output_tokens,error,created_at,started_at,finished_at,updated_at`

func scanInvestigationRun(row interface{ Scan(...any) error }) (*InvestigationRun, error) {
	r := &InvestigationRun{}
	var events []byte
	err := row.Scan(&r.ID, &r.FindingID, &r.InvestigationID, &r.Status, &r.Options, &events, &r.Result,
		&r.Usage.Rounds, &r.Usage.ModelCalls, &r.Usage.Queries, &r.Usage.ToolCalls, &r.Usage.InputTokens, &r.Usage.OutputTokens,
		&r.Error, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvestigationRunNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(events, &r.Events); err != nil {
		return nil, err
	}
	return r, nil
}

func investigationRunObject(raw json.RawMessage, maxBytes int) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	var object map[string]json.RawMessage
	if len(raw) > maxBytes || json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, fmt.Errorf("%w: 조사 실행 데이터는 크기 제한 안의 JSON 객체여야 합니다", ErrDefenseInvalid)
	}
	return raw, nil
}

func (u InvestigationRunUsage) valid() bool {
	return u.Rounds >= 0 && u.ModelCalls >= 0 && u.Queries >= 0 && u.ToolCalls >= 0 && u.InputTokens >= 0 && u.OutputTokens >= 0
}

func (u InvestigationRunUsage) contains(previous InvestigationRunUsage) bool {
	return u.valid() && u.Rounds >= previous.Rounds && u.ModelCalls >= previous.ModelCalls && u.Queries >= previous.Queries && u.ToolCalls >= previous.ToolCalls &&
		u.InputTokens >= previous.InputTokens && u.OutputTokens >= previous.OutputTokens
}

func investigationRunTerminal(status string) bool {
	switch status {
	case "completed", "insufficient_data", "budget_exhausted", "cancelled", "model_error", "interrupted":
		return true
	}
	return false
}

// One active run per finding prevents accidental duplicate model/Splunk work.
// created is false only when the same base already has an active run.
func (d *DB) CreateInvestigationRun(ctx context.Context, findingID, baseID int64, options json.RawMessage) (*InvestigationRun, bool, error) {
	options, err := investigationRunObject(options, 64<<10)
	if err != nil {
		return nil, false, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if err = LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, false, err
	}
	var current bool
	err = tx.QueryRowContext(ctx, `SELECT i.evidence_version=f.evidence_version AND i.source_fingerprint=`+investigationFingerprintSQL+`
 FROM finding_investigations i JOIN findings f ON f.id=i.finding_id WHERE i.finding_id=$1 AND i.id=$2`, findingID, baseID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrInvestigationNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if !current {
		return nil, false, ErrDefenseConflict
	}
	existing, err := scanInvestigationRun(tx.QueryRowContext(ctx, `SELECT `+investigationRunCols+` FROM finding_investigation_runs WHERE finding_id=$1 AND status IN ('queued','running')`, findingID))
	if err == nil {
		if existing.InvestigationID != baseID {
			return nil, false, ErrDefenseConflict
		}
		return existing, false, tx.Commit()
	}
	if !errors.Is(err, ErrInvestigationRunNotFound) {
		return nil, false, err
	}
	out, err := scanInvestigationRun(tx.QueryRowContext(ctx, `INSERT INTO finding_investigation_runs(finding_id,investigation_id,options) VALUES($1,$2,$3) RETURNING `+investigationRunCols, findingID, baseID, options))
	if err != nil {
		return nil, false, err
	}
	return out, true, tx.Commit()
}

func (d *DB) StartInvestigationRun(ctx context.Context, id int64) (bool, error) {
	result, err := d.ExecContext(ctx, `UPDATE finding_investigation_runs SET status='running',started_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND status='queued'`, id)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// Append is atomic and bounded. Previously saved query responses retain their
// evidence references, bytes, and timestamps even if a later model call fails.
func (d *DB) AppendInvestigationRunEvent(ctx context.Context, id int64, kind string, payload json.RawMessage, usage InvestigationRunUsage) (*InvestigationRunEvent, error) {
	kind = strings.TrimSpace(kind)
	if len(kind) == 0 || len(kind) > 80 || !usage.valid() {
		return nil, ErrDefenseInvalid
	}
	payload, err := investigationRunObject(payload, 16<<20)
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var status string
	var count, size int
	var previous InvestigationRunUsage
	err = tx.QueryRowContext(ctx, `SELECT status,jsonb_array_length(events),octet_length(events::text)+octet_length(options::text),rounds,model_calls,queries,tool_calls,input_tokens,output_tokens FROM finding_investigation_runs WHERE id=$1 FOR UPDATE`, id).
		Scan(&status, &count, &size, &previous.Rounds, &previous.ModelCalls, &previous.Queries, &previous.ToolCalls, &previous.InputTokens, &previous.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvestigationRunNotFound
	}
	if err != nil {
		return nil, err
	}
	if status != "running" {
		return nil, ErrInvestigationRunInactive
	}
	if !usage.contains(previous) {
		return nil, fmt.Errorf("%w: 조사 실행 사용량은 감소할 수 없습니다", ErrDefenseInvalid)
	}
	out := &InvestigationRunEvent{Sequence: count + 1, Kind: kind, Payload: payload}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&out.CreatedAt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal([]InvestigationRunEvent{*out})
	if err != nil {
		return nil, err
	}
	if count >= 256 || size+len(raw) > 24<<20 {
		return nil, fmt.Errorf("%w: 조사 실행 기록 저장 한도에 도달했습니다", ErrDefenseInvalid)
	}
	_, err = tx.ExecContext(ctx, `UPDATE finding_investigation_runs SET events=events || $2::jsonb,rounds=$3,tool_calls=$4,input_tokens=$5,output_tokens=$6,updated_at=$7,model_calls=$8,queries=$9 WHERE id=$1`, id, raw, usage.Rounds, usage.ToolCalls, usage.InputTokens, usage.OutputTokens, out.CreatedAt, usage.ModelCalls, usage.Queries)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// A terminal run is sealed. A late worker cannot overwrite cancellation or a
// restart interruption, and cannot replace a previously recorded conclusion.
func (d *DB) FinishInvestigationRun(ctx context.Context, id int64, status string, result json.RawMessage, errorMessage string, usage InvestigationRunUsage) (bool, error) {
	if !investigationRunTerminal(status) || !usage.valid() {
		return false, ErrDefenseInvalid
	}
	result, err := investigationRunObject(result, 32<<20)
	if err != nil {
		return false, err
	}
	if errorMessage, err = defenseText(errorMessage, "조사 실행 오류", 0, 8000); err != nil {
		return false, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var previous InvestigationRunUsage
	var previousStatus string
	var size int
	err = tx.QueryRowContext(ctx, `SELECT status,octet_length(events::text)+octet_length(options::text),rounds,model_calls,queries,tool_calls,input_tokens,output_tokens FROM finding_investigation_runs WHERE id=$1 FOR UPDATE`, id).
		Scan(&previousStatus, &size, &previous.Rounds, &previous.ModelCalls, &previous.Queries, &previous.ToolCalls, &previous.InputTokens, &previous.OutputTokens)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrInvestigationRunNotFound
	}
	if err != nil {
		return false, err
	}
	if investigationRunTerminal(previousStatus) {
		return false, nil
	}
	if !usage.contains(previous) || size+len(result) > 24<<20 {
		return false, fmt.Errorf("%w: 조사 실행 사용량 또는 저장 한도를 확인해 주세요", ErrDefenseInvalid)
	}
	_, err = tx.ExecContext(ctx, `UPDATE finding_investigation_runs SET status=$2,result=$3,error=$4,rounds=$5,tool_calls=$6,input_tokens=$7,output_tokens=$8,model_calls=$9,queries=$10,finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, id, status, result, errorMessage, usage.Rounds, usage.ToolCalls, usage.InputTokens, usage.OutputTokens, usage.ModelCalls, usage.Queries)
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (d *DB) CancelInvestigationRun(ctx context.Context, findingID, id int64) (*InvestigationRun, error) {
	_, err := d.ExecContext(ctx, `UPDATE finding_investigation_runs SET status='cancelled',error='사용자가 조사를 중단했습니다',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE finding_id=$1 AND id=$2 AND status IN ('queued','running')`, findingID, id)
	if err != nil {
		return nil, err
	}
	return d.GetInvestigationRun(ctx, findingID, id)
}

// Call once before accepting work after a process restart. Partial evidence is
// retained; interrupted work is never silently restarted and charged again.
func (d *DB) RecoverInvestigationRuns(ctx context.Context) (int64, error) {
	result, err := d.ExecContext(ctx, `UPDATE finding_investigation_runs SET status='interrupted',error='서비스 재시작으로 조사가 중단되었습니다. 저장된 근거를 확인한 뒤 다시 시작해 주세요',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE status IN ('queued','running')`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (d *DB) GetInvestigationRun(ctx context.Context, findingID, id int64) (*InvestigationRun, error) {
	return scanInvestigationRun(d.QueryRowContext(ctx, `SELECT `+investigationRunCols+` FROM finding_investigation_runs WHERE finding_id=$1 AND id=$2`, findingID, id))
}

// A baseID of zero lists the finding's latest 30 runs across evidence uploads.
// Summaries intentionally omit options, raw tool evidence, and model output.
func (d *DB) ListInvestigationRuns(ctx context.Context, findingID, baseID int64) ([]InvestigationRunSummary, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,finding_id,investigation_id,status,rounds,model_calls,queries,tool_calls,input_tokens,output_tokens,error,created_at,started_at,finished_at,updated_at FROM finding_investigation_runs WHERE finding_id=$1 AND ($2=0 OR investigation_id=$2) ORDER BY id DESC LIMIT 30`, findingID, baseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InvestigationRunSummary{}
	for rows.Next() {
		var r InvestigationRunSummary
		if err = rows.Scan(&r.ID, &r.FindingID, &r.InvestigationID, &r.Status,
			&r.Usage.Rounds, &r.Usage.ModelCalls, &r.Usage.Queries, &r.Usage.ToolCalls, &r.Usage.InputTokens, &r.Usage.OutputTokens,
			&r.Error, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
