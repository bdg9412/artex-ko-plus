package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrDefenseConflict = errors.New("방어 계획 또는 원본 증거가 변경됐습니다. 새로고침 후 다시 저장해 주세요")
	ErrDefenseInvalid  = errors.New("방어 검증 입력이 올바르지 않습니다")
)

type DefensePlan struct {
	FindingID   int64     `json:"finding_id,string"`
	Revision    int64     `json:"revision"`
	Hypothesis  string    `json:"hypothesis"`
	LogSource   string    `json:"log_source"`
	RuleFormat  string    `json:"rule_format"`
	RuleText    string    `json:"rule_text"`
	Remediation string    `json:"remediation"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DefensePlanInput struct {
	Hypothesis       string `json:"hypothesis"`
	LogSource        string `json:"log_source"`
	RuleFormat       string `json:"rule_format"`
	RuleText         string `json:"rule_text"`
	Remediation      string `json:"remediation"`
	ExpectedRevision int64  `json:"expected_revision"`
}

// DefenseValidation is an append-only manual observation. PlanSnapshot keeps
// the rule and hypothesis visible after a later plan edit. No outcome here is
// inferred from a rule, LLM response, or the finding's lifecycle status.
type DefenseValidation struct {
	ID                int64       `json:"id,string"`
	FindingID         int64       `json:"finding_id,string"`
	PlanRevision      int64       `json:"plan_revision"`
	EvidenceVersion   int64       `json:"evidence_version"`
	SourceFingerprint string      `json:"source_fingerprint"`
	PlanSnapshot      DefensePlan `json:"plan_snapshot"`
	Detection         string      `json:"detection"`
	Prevention        string      `json:"prevention"`
	Evidence          string      `json:"evidence"`
	ObservedAt        time.Time   `json:"observed_at"`
	Notes             string      `json:"notes"`
	CreatedAt         time.Time   `json:"created_at"`
}

type DefenseValidationInput struct {
	PlanRevision              int64     `json:"plan_revision"`
	ExpectedEvidenceVersion   *int64    `json:"expected_evidence_version"`
	ExpectedSourceFingerprint string    `json:"expected_source_fingerprint"`
	Detection                 string    `json:"detection"`
	Prevention                string    `json:"prevention"`
	Evidence                  string    `json:"evidence"`
	ObservedAt                time.Time `json:"observed_at"`
	Notes                     string    `json:"notes"`
}

type FindingDefense struct {
	Plan              *DefensePlan         `json:"plan"`
	Validations       []*DefenseValidation `json:"validations"`
	State             string               `json:"state"`
	EvidenceVersion   int64                `json:"evidence_version"`
	SourceFingerprint string               `json:"source_fingerprint"`
}

func defenseText(value, field string, min, max int) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return "", fmt.Errorf("%w: %s에 올바른 텍스트를 입력해 주세요", ErrDefenseInvalid, field)
	}
	if n := utf8.RuneCountInString(value); n < min || n > max {
		return "", fmt.Errorf("%w: %s는 %d~%d자로 입력해 주세요", ErrDefenseInvalid, field, min, max)
	}
	return value, nil
}

func normalizeDefensePlan(in DefensePlanInput) (DefensePlanInput, error) {
	if in.ExpectedRevision < 0 || (in.RuleFormat != "query" && in.RuleFormat != "sigma" && in.RuleFormat != "other" && in.RuleFormat != "event_filter") {
		return in, fmt.Errorf("%w: 계획 버전 또는 규칙 형식을 확인해 주세요", ErrDefenseInvalid)
	}
	fields := []struct {
		value    *string
		name     string
		min, max int
	}{
		{&in.Hypothesis, "검증 가설", 1, 4000}, {&in.LogSource, "로그 소스", 0, 2000},
		{&in.RuleText, "탐지 규칙", 0, 32000}, {&in.Remediation, "개선 조치", 0, 8000},
	}
	for _, f := range fields {
		v, err := defenseText(*f.value, f.name, f.min, f.max)
		if err != nil {
			return in, err
		}
		*f.value = v
	}
	return in, nil
}

func normalizeDefenseValidation(in DefenseValidationInput, now time.Time) (DefenseValidationInput, error) {
	if in.PlanRevision <= 0 || in.ExpectedEvidenceVersion == nil || *in.ExpectedEvidenceVersion < 0 {
		return in, fmt.Errorf("%w: 계획 및 증거 버전을 확인해 주세요", ErrDefenseInvalid)
	}
	if raw, err := hex.DecodeString(in.ExpectedSourceFingerprint); err != nil || len(raw) != 16 {
		return in, fmt.Errorf("%w: 원본 증거 식별자를 확인해 주세요", ErrDefenseInvalid)
	}
	if in.Detection != "detected" && in.Detection != "missed" && in.Detection != "not_tested" {
		return in, fmt.Errorf("%w: 탐지 결과를 선택해 주세요", ErrDefenseInvalid)
	}
	if in.Prevention != "blocked" && in.Prevention != "not_blocked" && in.Prevention != "not_tested" {
		return in, fmt.Errorf("%w: 차단 결과를 선택해 주세요", ErrDefenseInvalid)
	}
	if in.Detection == "not_tested" && in.Prevention == "not_tested" {
		return in, fmt.Errorf("%w: 탐지 또는 차단 중 하나 이상의 관찰 결과가 필요합니다", ErrDefenseInvalid)
	}
	if in.ObservedAt.IsZero() || in.ObservedAt.Year() < 1970 || in.ObservedAt.After(now.Add(5*time.Minute)) {
		return in, fmt.Errorf("%w: 관찰 시각은 1970년 이후여야 하며 현재보다 5분 넘게 미래일 수 없습니다", ErrDefenseInvalid)
	}
	var err error
	if in.Evidence, err = defenseText(in.Evidence, "관찰 증거", 1, 32000); err != nil {
		return in, err
	}
	if in.Notes, err = defenseText(in.Notes, "메모", 0, 4000); err != nil {
		return in, err
	}
	in.ObservedAt = in.ObservedAt.UTC()
	return in, nil
}

const defenseSourceFingerprintSQL = `md5(jsonb_build_array(f.vulnclass,f.name,f.summary,f.evidence,f.asset_ids,f.evidence_version)::text)`

const defensePlanColumns = `finding_id, revision, hypothesis, log_source, rule_format, rule_text, remediation, updated_at`
const defenseValidationColumns = `id, finding_id, plan_revision, evidence_version, source_fingerprint, plan_snapshot, detection, prevention, evidence, observed_at, notes, created_at`

func scanDefensePlan(row interface{ Scan(...any) error }) (*DefensePlan, error) {
	p := &DefensePlan{}
	err := row.Scan(&p.FindingID, &p.Revision, &p.Hypothesis, &p.LogSource, &p.RuleFormat, &p.RuleText, &p.Remediation, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

func scanDefenseValidation(row interface{ Scan(...any) error }) (*DefenseValidation, error) {
	v := &DefenseValidation{}
	var snapshot []byte
	if err := row.Scan(&v.ID, &v.FindingID, &v.PlanRevision, &v.EvidenceVersion, &v.SourceFingerprint, &snapshot, &v.Detection, &v.Prevention, &v.Evidence, &v.ObservedAt, &v.Notes, &v.CreatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(snapshot, &v.PlanSnapshot); err != nil {
		return nil, err
	}
	return v, nil
}

func defenseState(plan *DefensePlan, latest *DefenseValidation, evidenceVersion int64, sourceFingerprint string) string {
	if plan == nil {
		return "unplanned"
	}
	if latest == nil {
		return "untested"
	}
	if latest.PlanRevision != plan.Revision || latest.EvidenceVersion != evidenceVersion || latest.SourceFingerprint != sourceFingerprint {
		return "stale"
	}
	return "current"
}

func (d *DB) GetFindingDefense(ctx context.Context, findingID int64) (*FindingDefense, error) {
	// One MVCC snapshot for the plan, source version, and history. A concurrent
	// edit cannot accidentally pair the old plan with a newly recorded result.
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := findingDefenseTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func findingDefenseTx(ctx context.Context, tx *sql.Tx, findingID int64) (*FindingDefense, error) {
	var err error
	out := &FindingDefense{Validations: []*DefenseValidation{}}
	if err = tx.QueryRowContext(ctx, `SELECT f.evidence_version, `+defenseSourceFingerprintSQL+` FROM findings f WHERE f.id=$1`, findingID).Scan(&out.EvidenceVersion, &out.SourceFingerprint); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	out.Plan, err = scanDefensePlan(tx.QueryRowContext(ctx, `SELECT `+defensePlanColumns+` FROM finding_defense_plans WHERE finding_id=$1`, findingID))
	if err != nil {
		return nil, err
	}
	// ID is append order, not the user-supplied observation time. A newly
	// submitted missed result must supersede an earlier detected result.
	rows, err := tx.QueryContext(ctx, `SELECT `+defenseValidationColumns+` FROM finding_defense_validations WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		v, err := scanDefenseValidation(rows)
		if err != nil {
			return nil, err
		}
		out.Validations = append(out.Validations, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var latest *DefenseValidation
	if len(out.Validations) > 0 {
		latest = out.Validations[0]
	}
	out.State = defenseState(out.Plan, latest, out.EvidenceVersion, out.SourceFingerprint)
	return out, nil
}

// SaveDefensePlan serializes all writes on the parent finding, including the
// no-plan-yet case; locking only a missing plan row cannot prevent lost creates.
func (d *DB) SaveDefensePlan(ctx context.Context, findingID int64, in DefensePlanInput) (*FindingDefense, error) {
	in, err := normalizeDefensePlan(in)
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, err
	}
	var version int64
	var sourceFingerprint string
	if err := tx.QueryRowContext(ctx, `SELECT f.evidence_version, `+defenseSourceFingerprintSQL+` FROM findings f WHERE f.id=$1`, findingID).Scan(&version, &sourceFingerprint); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	old, err := scanDefensePlan(tx.QueryRowContext(ctx, `SELECT `+defensePlanColumns+` FROM finding_defense_plans WHERE finding_id=$1`, findingID))
	if err != nil {
		return nil, err
	}
	if (old == nil && in.ExpectedRevision != 0) || (old != nil && old.Revision != in.ExpectedRevision) {
		return nil, ErrDefenseConflict
	}
	if old != nil && old.Hypothesis == in.Hypothesis && old.LogSource == in.LogSource && old.RuleFormat == in.RuleFormat && old.RuleText == in.RuleText && old.Remediation == in.Remediation {
		out, err := findingDefenseTx(ctx, tx, findingID)
		if err != nil {
			return nil, err
		}
		return out, tx.Commit()
	}
	_, err = scanDefensePlan(tx.QueryRowContext(ctx, `INSERT INTO finding_defense_plans(finding_id,revision,hypothesis,log_source,rule_format,rule_text,remediation)
	VALUES($1,1,$2,$3,$4,$5,$6) ON CONFLICT(finding_id) DO UPDATE SET revision=finding_defense_plans.revision+1,
	hypothesis=EXCLUDED.hypothesis, log_source=EXCLUDED.log_source, rule_format=EXCLUDED.rule_format,
	rule_text=EXCLUDED.rule_text, remediation=EXCLUDED.remediation, updated_at=clock_timestamp() RETURNING `+defensePlanColumns,
		findingID, in.Hypothesis, in.LogSource, in.RuleFormat, in.RuleText, in.Remediation))
	if err != nil {
		return nil, err
	}
	out, err := findingDefenseTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func (d *DB) AddDefenseValidation(ctx context.Context, findingID int64, in DefenseValidationInput) (*FindingDefense, error) {
	in, err := normalizeDefenseValidation(in, time.Now())
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, err
	}
	var version int64
	var sourceFingerprint string
	if err := tx.QueryRowContext(ctx, `SELECT f.evidence_version, `+defenseSourceFingerprintSQL+` FROM findings f WHERE f.id=$1`, findingID).Scan(&version, &sourceFingerprint); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	p, err := scanDefensePlan(tx.QueryRowContext(ctx, `SELECT `+defensePlanColumns+` FROM finding_defense_plans WHERE finding_id=$1`, findingID))
	if err != nil {
		return nil, err
	}
	if p == nil || p.Revision != in.PlanRevision || (version != *in.ExpectedEvidenceVersion) || sourceFingerprint != in.ExpectedSourceFingerprint {
		return nil, ErrDefenseConflict
	}
	snapshot, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	_, err = scanDefenseValidation(tx.QueryRowContext(ctx, `INSERT INTO finding_defense_validations
	(finding_id,plan_revision,evidence_version,source_fingerprint,plan_snapshot,detection,prevention,evidence,observed_at,notes)
	VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+defenseValidationColumns,
		findingID, p.Revision, version, sourceFingerprint, snapshot, in.Detection, in.Prevention, in.Evidence, in.ObservedAt, in.Notes))
	if err != nil {
		return nil, err
	}
	out, err := findingDefenseTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

type PurpleStats struct {
	TotalFindings           int64 `json:"total_findings"`
	Planned                 int64 `json:"planned"`
	Validated               int64 `json:"validated"`
	NeedsRevalidation       int64 `json:"needs_revalidation"`
	Detected                int64 `json:"detected"`
	Missed                  int64 `json:"missed"`
	Blocked                 int64 `json:"blocked"`
	Replayed                int64 `json:"replayed"`
	ReplayPassed            int64 `json:"replay_passed"`
	ReplayNeedsRevalidation int64 `json:"replay_needs_revalidation"`
	ExecutionTotal          int64 `json:"execution_total"`
	ExecutionDetected       int64 `json:"execution_detected"`
	ExecutionMissed         int64 `json:"execution_missed"`
	ExecutionBlocked        int64 `json:"execution_blocked"`
	ExecutionInconclusive   int64 `json:"execution_inconclusive"`
}

type PurpleItem struct {
	FindingID           int64     `json:"finding_id,string"`
	Name                string    `json:"name"`
	VulnClass           string    `json:"vulnclass"`
	Severity            string    `json:"severity"`
	FindingStatus       string    `json:"finding_status"`
	State               string    `json:"state"`
	PlanRevision        int64     `json:"plan_revision"`
	Detection           string    `json:"detection"`
	Prevention          string    `json:"prevention"`
	UpdatedAt           time.Time `json:"updated_at"`
	ReplayState         string    `json:"replay_state"`
	ReplayVerdict       string    `json:"replay_verdict"`
	ExecutionState      string    `json:"execution_state"`
	ExecutionStatus     string    `json:"execution_status"`
	ExecutionDetection  string    `json:"execution_detection"`
	ExecutionPrevention string    `json:"execution_prevention"`
	ExecutionID         string    `json:"execution_id"`
}

type PurpleOverview struct {
	Stats PurpleStats   `json:"stats"`
	Items []*PurpleItem `json:"items"`
	Total int64         `json:"total"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
}

const purpleOverviewCTE = `WITH overview AS (
 SELECT f.id AS finding_id, f.name, f.vulnclass, f.severity, f.status AS finding_status,
 CASE WHEN p.finding_id IS NULL THEN 'unplanned' WHEN v.id IS NULL THEN 'untested'
 WHEN v.plan_revision=p.revision AND v.evidence_version=f.evidence_version AND v.source_fingerprint=` + defenseSourceFingerprintSQL + ` THEN 'current' ELSE 'stale' END AS state,
 COALESCE(p.revision,0) AS plan_revision, COALESCE(v.detection,'not_tested') AS detection,
 COALESCE(v.prevention,'not_tested') AS prevention, GREATEST(f.created_at,p.updated_at,v.created_at,r.created_at,x.created_at) AS updated_at,
 CASE WHEN r.id IS NULL THEN 'none' WHEN r.plan_revision=p.revision AND r.evidence_version=f.evidence_version
 AND r.source_fingerprint=` + defenseSourceFingerprintSQL + ` THEN 'current' ELSE 'stale' END AS replay_state,
 COALESCE(r.result->>'verdict','') AS replay_verdict, COALESCE(x.state,'none') AS execution_state,
 COALESCE(x.status,'') AS execution_status, COALESCE(x.detection,'') AS execution_detection,
 COALESCE(x.prevention,'') AS execution_prevention, COALESCE(x.id::text,'') AS execution_id
 FROM findings f LEFT JOIN finding_defense_plans p ON p.finding_id=f.id
 LEFT JOIN LATERAL (SELECT id,plan_revision,evidence_version,source_fingerprint,detection,prevention,created_at
 FROM finding_defense_validations WHERE finding_id=f.id ORDER BY id DESC LIMIT 1) v ON true
 LEFT JOIN LATERAL (SELECT id,plan_revision,evidence_version,source_fingerprint,result,created_at
 FROM finding_defense_replays WHERE finding_id=f.id ORDER BY id DESC LIMIT 1) r ON true
 LEFT JOIN LATERAL (
 SELECT e.id,e.created_at,` + executionStateSQL + ` AS state,
 CASE WHEN e.retest_snapshot->>'status' IN ('completed','failed','stopped') THEN e.retest_snapshot->>'status'
 ELSE COALESCE(rr.status,e.retest_snapshot->>'status','unknown') END AS status,
 aa.detection,aa.prevention
 FROM finding_defense_executions e LEFT JOIN security_sources s ON s.id=e.source_id
 LEFT JOIN finding_retests rr ON rr.id=e.retest_id AND rr.finding_id=e.finding_id
 LEFT JOIN LATERAL(SELECT detection,prevention FROM finding_defense_assessments WHERE execution_id=e.id ORDER BY id DESC LIMIT 1) aa ON true
 WHERE e.finding_id=f.id ORDER BY e.id DESC LIMIT 1
 ) x ON true
 ) `

func (d *DB) GetPurpleOverview(ctx context.Context, page, limit int) (*PurpleOverview, error) {
	if page < 1 || page > 1000000 || limit < 1 || limit > 100 {
		return nil, ErrDefenseInvalid
	}
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := &PurpleOverview{Items: []*PurpleItem{}, Page: page, Limit: limit}
	s := &out.Stats
	err = tx.QueryRowContext(ctx, purpleOverviewCTE+`SELECT count(*),count(*) FILTER(WHERE plan_revision>0),
	count(*) FILTER(WHERE state='current'),count(*) FILTER(WHERE state='stale'),
	count(*) FILTER(WHERE state='current' AND detection='detected'),count(*) FILTER(WHERE state='current' AND detection='missed'),
	count(*) FILTER(WHERE state='current' AND prevention='blocked'),
	count(*) FILTER(WHERE replay_state<>'none'),count(*) FILTER(WHERE replay_state='current' AND replay_verdict='pass'),
	count(*) FILTER(WHERE replay_state='stale'),count(*) FILTER(WHERE execution_state<>'none'),
	count(*) FILTER(WHERE execution_state='current' AND execution_status='completed' AND execution_detection='detected'),
	count(*) FILTER(WHERE execution_state='current' AND execution_status='completed' AND execution_detection='missed'),
	count(*) FILTER(WHERE execution_state='current' AND execution_status='completed' AND execution_prevention='blocked'),
	count(*) FILTER(WHERE execution_state='current' AND (execution_status<>'completed' OR execution_detection IN ('','inconclusive') OR execution_prevention IN ('','inconclusive'))) FROM overview`).Scan(
		&s.TotalFindings, &s.Planned, &s.Validated, &s.NeedsRevalidation, &s.Detected, &s.Missed, &s.Blocked, &s.Replayed, &s.ReplayPassed, &s.ReplayNeedsRevalidation, &s.ExecutionTotal, &s.ExecutionDetected, &s.ExecutionMissed, &s.ExecutionBlocked, &s.ExecutionInconclusive)
	if err != nil {
		return nil, err
	}
	out.Total = s.TotalFindings
	rows, err := tx.QueryContext(ctx, purpleOverviewCTE+`SELECT finding_id,name,vulnclass,severity,finding_status,state,plan_revision,detection,prevention,updated_at,replay_state,replay_verdict,execution_state,execution_status,execution_detection,execution_prevention,execution_id
	FROM overview ORDER BY updated_at DESC,finding_id DESC LIMIT $1 OFFSET $2`, limit, int64(page-1)*int64(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		item := &PurpleItem{}
		if err := rows.Scan(&item.FindingID, &item.Name, &item.VulnClass, &item.Severity, &item.FindingStatus, &item.State, &item.PlanRevision, &item.Detection, &item.Prevention, &item.UpdatedAt, &item.ReplayState, &item.ReplayVerdict, &item.ExecutionState, &item.ExecutionStatus, &item.ExecutionDetection, &item.ExecutionPrevention, &item.ExecutionID); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
