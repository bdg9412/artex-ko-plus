package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/defenseeval"
)

var ErrDefenseReplayNotFound = errors.New("로그 재생 기록을 찾을 수 없습니다")

type DefenseReplayInput struct {
	PlanRevision              int64  `json:"plan_revision"`
	ExpectedEvidenceVersion   *int64 `json:"expected_evidence_version"`
	ExpectedSourceFingerprint string `json:"expected_source_fingerprint"`
	TargetLogs                string `json:"target_logs"`
	ControlLogs               string `json:"control_logs"`
	Notes                     string `json:"notes"`
}

// DefenseReplay stores an evaluator result, never a live detection or prevention
// claim. Raw input is available only in the explicit authenticated export.
type DefenseReplay struct {
	ID                   int64               `json:"id,string"`
	FindingID            int64               `json:"finding_id,string"`
	PlanRevision         int64               `json:"plan_revision"`
	EvidenceVersion      int64               `json:"evidence_version"`
	SourceFingerprint    string              `json:"source_fingerprint"`
	PlanSnapshot         DefensePlan         `json:"plan_snapshot"`
	RuleSHA256           string              `json:"rule_sha256"`
	TargetSHA256         string              `json:"target_sha256"`
	ControlSHA256        string              `json:"control_sha256"`
	EvaluatorVersion     string              `json:"evaluator_version"`
	Result               *defenseeval.Result `json:"result"`
	Notes                string              `json:"notes"`
	CreatedAt            time.Time           `json:"created_at"`
	State                string              `json:"state"`
	EvaluationsTruncated bool                `json:"evaluations_truncated"`
}

type DefenseReplayExport struct {
	*DefenseReplay
	TargetLogs  string `json:"target_logs"`
	ControlLogs string `json:"control_logs"`
}

const defenseReplayPreviewLimit = 50

func previewDefenseReplay(run *DefenseReplay) *DefenseReplay {
	if run.Result != nil && len(run.Result.Evaluations) > defenseReplayPreviewLimit {
		result := *run.Result
		result.Evaluations = append([]defenseeval.Evaluation(nil), result.Evaluations[:defenseReplayPreviewLimit]...)
		run.Result = &result
		run.EvaluationsTruncated = true
	}
	return run
}

func replayHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizeDefenseReplay(in DefenseReplayInput) (DefenseReplayInput, error) {
	if in.PlanRevision <= 0 || in.ExpectedEvidenceVersion == nil || *in.ExpectedEvidenceVersion < 0 {
		return in, fmt.Errorf("%w: 계획 및 증거 버전을 확인해 주세요", ErrDefenseInvalid)
	}
	if raw, err := hex.DecodeString(in.ExpectedSourceFingerprint); err != nil || len(raw) != 16 {
		return in, fmt.Errorf("%w: 원본 증거 식별자를 확인해 주세요", ErrDefenseInvalid)
	}
	if len(in.TargetLogs)+len(in.ControlLogs) > defenseeval.MaxCombinedLogBytes {
		return in, fmt.Errorf("%w: 두 로그의 합계는 1 MiB 이하여야 합니다", ErrDefenseInvalid)
	}
	var err error
	in.Notes, err = defenseText(in.Notes, "메모", 0, 4000)
	return in, err
}

// RunDefenseReplay reads the server-held rule and evaluates it before taking
// write locks. The save then rechecks the plan and source under the same task /
// finding locks used by evidence edits and archive queueing. Caller-supplied
// verdicts, rule replacements, filesystem paths, and URLs are never accepted.
func (d *DB) RunDefenseReplay(ctx context.Context, findingID int64, in DefenseReplayInput) (*DefenseReplay, error) {
	in, err := normalizeDefenseReplay(in)
	if err != nil {
		return nil, err
	}
	state, err := d.GetFindingDefense(ctx, findingID)
	if err != nil {
		return nil, err
	}
	if state.Plan == nil || state.Plan.Revision != in.PlanRevision || state.EvidenceVersion != *in.ExpectedEvidenceVersion || state.SourceFingerprint != in.ExpectedSourceFingerprint {
		return nil, ErrDefenseConflict
	}
	if state.Plan.RuleFormat != "event_filter" {
		return nil, fmt.Errorf("%w: 로그 재생에는 event_filter 형식의 규칙이 필요합니다", ErrDefenseInvalid)
	}
	result, err := defenseeval.Evaluate(state.Plan.RuleText, in.TargetLogs, in.ControlLogs)
	if err != nil {
		if errors.Is(err, defenseeval.ErrInvalid) {
			return nil, fmt.Errorf("%w: %v", ErrDefenseInvalid, err)
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.saveDefenseReplay(ctx, findingID, in, state.Plan, result)
}

func (d *DB) saveDefenseReplay(ctx context.Context, findingID int64, in DefenseReplayInput, plan *DefensePlan, result *defenseeval.Result) (*DefenseReplay, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, err
	}
	var version int64
	var fingerprint string
	if err := tx.QueryRowContext(ctx, `SELECT f.evidence_version,`+defenseSourceFingerprintSQL+` FROM findings f WHERE f.id=$1`, findingID).Scan(&version, &fingerprint); err != nil {
		return nil, err
	}
	current, err := scanDefensePlan(tx.QueryRowContext(ctx, `SELECT `+defensePlanColumns+` FROM finding_defense_plans WHERE finding_id=$1`, findingID))
	if err != nil {
		return nil, err
	}
	if current == nil || current.Revision != plan.Revision || current.Revision != in.PlanRevision || version != *in.ExpectedEvidenceVersion || fingerprint != in.ExpectedSourceFingerprint {
		return nil, ErrDefenseConflict
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	out := &DefenseReplay{FindingID: findingID, PlanRevision: plan.Revision, EvidenceVersion: version, SourceFingerprint: fingerprint,
		PlanSnapshot: *plan, RuleSHA256: replayHash(plan.RuleText), TargetSHA256: replayHash(in.TargetLogs), ControlSHA256: replayHash(in.ControlLogs),
		EvaluatorVersion: defenseeval.EngineVersion, Result: result, Notes: in.Notes, State: "current"}
	err = tx.QueryRowContext(ctx, `INSERT INTO finding_defense_replays
	(finding_id,plan_revision,evidence_version,source_fingerprint,plan_snapshot,target_logs,control_logs,rule_sha256,target_sha256,control_sha256,evaluator_version,result,notes)
	VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id,created_at`,
		findingID, plan.Revision, version, fingerprint, planJSON, in.TargetLogs, in.ControlLogs, out.RuleSHA256, out.TargetSHA256, out.ControlSHA256, out.EvaluatorVersion, resultJSON, in.Notes).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return previewDefenseReplay(out), tx.Commit()
}

const defenseReplayColumns = `r.id,r.finding_id,r.plan_revision,r.evidence_version,r.source_fingerprint,r.plan_snapshot,r.rule_sha256,r.target_sha256,r.control_sha256,r.evaluator_version,r.result,r.notes,r.created_at`
const defenseReplayStateSQL = `CASE WHEN p.revision=r.plan_revision AND f.evidence_version=r.evidence_version AND ` + defenseSourceFingerprintSQL + `=r.source_fingerprint THEN 'current' ELSE 'stale' END`
const defenseReplayJoin = ` FROM finding_defense_replays r JOIN findings f ON f.id=r.finding_id LEFT JOIN finding_defense_plans p ON p.finding_id=f.id `

func scanDefenseReplay(row interface{ Scan(...any) error }, rawInputs bool) (*DefenseReplayExport, error) {
	out := &DefenseReplayExport{DefenseReplay: &DefenseReplay{}}
	r := out.DefenseReplay
	var planJSON, resultJSON []byte
	args := []any{&r.ID, &r.FindingID, &r.PlanRevision, &r.EvidenceVersion, &r.SourceFingerprint, &planJSON, &r.RuleSHA256, &r.TargetSHA256, &r.ControlSHA256, &r.EvaluatorVersion, &resultJSON, &r.Notes, &r.CreatedAt, &r.State}
	if rawInputs {
		args = append(args, &out.TargetLogs, &out.ControlLogs)
	}
	if err := row.Scan(args...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(planJSON, &r.PlanSnapshot); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(resultJSON, &r.Result); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DB) ListDefenseReplays(ctx context.Context, findingID int64) ([]*DefenseReplay, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE id=$1)`, findingID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrFindingNotFound
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+defenseReplayColumns+`,`+defenseReplayStateSQL+defenseReplayJoin+`WHERE f.id=$1 ORDER BY r.id DESC LIMIT 50`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DefenseReplay{}
	for rows.Next() {
		r, err := scanDefenseReplay(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, previewDefenseReplay(r.DefenseReplay))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func (d *DB) ExportDefenseReplay(ctx context.Context, findingID, runID int64) (*DefenseReplayExport, error) {
	out, err := scanDefenseReplay(d.QueryRowContext(ctx, `SELECT `+defenseReplayColumns+`,`+defenseReplayStateSQL+`,r.target_logs,r.control_logs`+defenseReplayJoin+`WHERE f.id=$1 AND r.id=$2`, findingID, runID), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDefenseReplayNotFound
	}
	return out, err
}
