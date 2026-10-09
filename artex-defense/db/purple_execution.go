package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/securitysource"
	"github.com/google/uuid"
)

var ErrDefenseExecutionNotFound = errors.New("방어 검증 실행을 찾을 수 없습니다")

type DefenseExecutionInput struct {
	SourceKind                string                     `json:"source_kind"`
	FileConfig                *securitysource.FileConfig `json:"file_config,omitempty"`
	SourceID                  int64                      `json:"source_id,string"`
	PlanRevision              int64                      `json:"plan_revision"`
	ExpectedEvidenceVersion   *int64                     `json:"expected_evidence_version"`
	ExpectedSourceFingerprint string                     `json:"expected_source_fingerprint"`
	BaselineID                *int64                     `json:"baseline_id,string,omitempty"`
	RemediationNote           string                     `json:"remediation_note"`
}

type DefenseExecution struct {
	ID                   int64                `json:"id,string"`
	FindingID            int64                `json:"finding_id,string"`
	SourceID             int64                `json:"source_id,string"`
	SourceKind           string               `json:"source_kind"`
	RetestID             int64                `json:"retest_id"`
	CorrelationID        string               `json:"correlation_id"`
	SourceRevision       int64                `json:"source_revision"`
	SourceSnapshot       json.RawMessage      `json:"source_snapshot"`
	DiagnosisSnapshot    json.RawMessage      `json:"diagnosis_snapshot,omitempty"`
	PlanSnapshot         DefensePlan          `json:"plan_snapshot"`
	EvidenceVersion      int64                `json:"evidence_version"`
	SourceFingerprint    string               `json:"source_fingerprint"`
	BaselineID           *int64               `json:"baseline_id,string,omitempty"`
	RemediationNote      string               `json:"remediation_note"`
	CreatedAt            time.Time            `json:"created_at"`
	Retest               *FindingRetest       `json:"retest"`
	Assessments          []*DefenseAssessment `json:"assessments"`
	State                string               `json:"state"`
	AssessmentsTruncated bool                 `json:"assessments_truncated"`
}

type DefenseAssessment struct {
	ID                int64                       `json:"id,string"`
	ExecutionID       int64                       `json:"execution_id,string"`
	Detection         string                      `json:"detection"`
	Prevention        string                      `json:"prevention"`
	Reasons           []string                    `json:"reasons"`
	Recommendations   []string                    `json:"recommendations"`
	Diagnostics       []securitysource.Diagnostic `json:"diagnostics"`
	Evidence          *securitysource.Evidence    `json:"evidence"`
	CreatedAt         time.Time                   `json:"created_at"`
	EventCount        int                         `json:"event_count"`
	AuditCount        int                         `json:"audit_count"`
	AlertCount        int                         `json:"alert_count"`
	EvidenceTruncated bool                        `json:"evidence_truncated"`
}

type DefenseComparison struct {
	Baseline   *DefenseExecution `json:"baseline"`
	Current    *DefenseExecution `json:"current"`
	Comparable bool              `json:"comparable"`
	Reasons    []string          `json:"reasons"`
}

const executionRetestSQL = `CASE WHEN e.retest_snapshot->>'status' IN ('completed','failed','stopped') THEN e.retest_snapshot ELSE COALESCE(to_jsonb(r)-'snapshot',e.retest_snapshot) END`

// Scope freshness also follows the actual target records, not just asset IDs.
// Only execution-relevant fields participate: discovery timestamps, constraint
// provenance and other mutable metadata must not invalidate an observation.
const executionCurrentScopeSQL = `jsonb_build_object('vulnclass',f.vulnclass,
 'assets',COALESCE((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('id',a.id,'type',a.type,'domain',a.domain,'ip',a.ip,'port',a.port,'url',a.url,'method',a.method)) ORDER BY a.id)
 FROM assets a WHERE f.asset_ids @> to_jsonb(ARRAY[a.id])),'[]'::jsonb),
 'constraints',COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',c.kind,'text',c.text) ORDER BY c.kind,c.text)
 FROM task_constraints c JOIN tasks t ON t.exploration_id=c.exploration_id WHERE t.id=f.task_id),'[]'::jsonb))`

const executionSnapshotScopeSQL = `CASE WHEN jsonb_typeof(e.diagnosis_snapshot->'finding')='object'
 AND jsonb_typeof(e.diagnosis_snapshot->'assets')='array' AND jsonb_typeof(e.diagnosis_snapshot->'constraints')='array'
 THEN jsonb_build_object('vulnclass',e.diagnosis_snapshot#>'{finding,vulnclass}',
 'assets',COALESCE((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('id',a->'id','type',a->'type','domain',a->'domain','ip',a->'ip','port',a->'port','url',a->'url','method',a->'method')) ORDER BY (a->>'id')::bigint)
 FROM jsonb_array_elements(e.diagnosis_snapshot->'assets') a),'[]'::jsonb),
 'constraints',COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',c->'kind','text',c->'text') ORDER BY c->>'kind',c->>'text')
 FROM jsonb_array_elements(e.diagnosis_snapshot->'constraints') c),'[]'::jsonb)) END`

const executionStateSQL = `CASE WHEN ((e.source_kind='file' AND e.source_id=0 AND e.source_revision=1 AND e.source_snapshot->>'kind'='file') OR (e.source_kind='splunk' AND s.enabled AND s.revision=e.source_revision AND s.config=e.source_snapshot->'config')) AND p.revision=(e.plan_snapshot->>'revision')::bigint AND f.evidence_version=e.evidence_version AND ` + defenseSourceFingerprintSQL + `=e.source_fingerprint AND ` + executionCurrentScopeSQL + `=` + executionSnapshotScopeSQL + ` THEN 'current' ELSE 'stale' END`
const executionSelect = `SELECT e.id,e.finding_id,e.source_id,e.source_kind,e.retest_id,e.correlation_id::text,e.source_revision,e.source_snapshot,e.diagnosis_snapshot,e.plan_snapshot,e.evidence_version,e.source_fingerprint,e.baseline_id,e.remediation_note,e.created_at,` + executionRetestSQL + `,` + executionStateSQL + `
 FROM finding_defense_executions e JOIN findings f ON f.id=e.finding_id
 LEFT JOIN finding_defense_plans p ON p.finding_id=f.id LEFT JOIN security_sources s ON s.id=e.source_id
 LEFT JOIN finding_retests r ON r.id=e.retest_id AND r.finding_id=e.finding_id `

func scanDefenseExecution(row interface{ Scan(...any) error }) (*DefenseExecution, error) {
	out := &DefenseExecution{Assessments: []*DefenseAssessment{}}
	var plan, retest []byte
	if err := row.Scan(&out.ID, &out.FindingID, &out.SourceID, &out.SourceKind, &out.RetestID, &out.CorrelationID, &out.SourceRevision, &out.SourceSnapshot, &out.DiagnosisSnapshot, &plan, &out.EvidenceVersion, &out.SourceFingerprint, &out.BaselineID, &out.RemediationNote, &out.CreatedAt, &retest, &out.State); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(plan, &out.PlanSnapshot); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(retest, &out.Retest); err != nil {
		return nil, err
	}
	if out.Retest != nil {
		out.Retest.Snapshot = nil
	}
	return out, nil
}

func scanDefenseAssessment(row interface{ Scan(...any) error }) (*DefenseAssessment, error) {
	out := &DefenseAssessment{}
	var reasons, recommendations, diagnostics, evidence []byte
	if err := row.Scan(&out.ID, &out.ExecutionID, &out.Detection, &out.Prevention, &reasons, &recommendations, &diagnostics, &evidence, &out.CreatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(reasons, &out.Reasons); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(recommendations, &out.Recommendations); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(diagnostics, &out.Diagnostics); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(evidence, &out.Evidence); err != nil {
		return nil, err
	}
	countDefenseEvidence(out)
	return out, nil
}

func loadDefenseAssessmentsTx(ctx context.Context, tx *sql.Tx, e *DefenseExecution, preview bool) error {
	query := `SELECT id,execution_id,detection,prevention,reasons,recommendations,diagnostics,evidence,created_at FROM finding_defense_assessments WHERE execution_id=$1 ORDER BY id DESC`
	if preview {
		query += ` LIMIT 6`
	}
	rows, err := tx.QueryContext(ctx, query, e.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if preview && len(e.Assessments) == 5 {
			e.AssessmentsTruncated = true
			break
		}
		a, err := scanDefenseAssessment(rows)
		if err != nil {
			return err
		}
		if preview {
			a = previewDefenseAssessment(a)
		}
		e.Assessments = append(e.Assessments, a)
	}
	return rows.Err()
}

func getDefenseExecutionTx(ctx context.Context, tx *sql.Tx, findingID, id int64) (*DefenseExecution, error) {
	e, err := getDefenseExecutionMetadataTx(ctx, tx, findingID, id)
	if err != nil {
		return nil, err
	}
	if err := loadDefenseAssessmentsTx(ctx, tx, e, false); err != nil {
		return nil, err
	}
	return e, nil
}

func getDefenseExecutionMetadataTx(ctx context.Context, tx *sql.Tx, findingID, id int64) (*DefenseExecution, error) {
	e, err := scanDefenseExecution(tx.QueryRowContext(ctx, executionSelect+`WHERE e.finding_id=$1 AND e.id=$2`, findingID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDefenseExecutionNotFound
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

func createDefenseExecutionTx(ctx context.Context, tx *sql.Tx, findingID int64, retest *FindingRetest, in DefenseExecutionInput) (*DefenseExecution, error) {
	if retest == nil || retest.ID <= 0 || retest.FindingID != findingID || in.PlanRevision <= 0 || in.ExpectedEvidenceVersion == nil || *in.ExpectedEvidenceVersion < 0 {
		return nil, fmt.Errorf("%w: 실행 입력과 증거 버전을 확인해 주세요", ErrDefenseInvalid)
	}
	if in.SourceKind == "" {
		in.SourceKind = "splunk"
	}
	if in.SourceKind != "splunk" && in.SourceKind != "file" || in.SourceKind == "file" && (in.SourceID != 0 || in.FileConfig == nil) || in.SourceKind == "splunk" && (in.SourceID <= 0 || in.FileConfig != nil) {
		return nil, fmt.Errorf("%w: 실행 증거 소스 종류와 설정을 확인해 주세요", ErrDefenseInvalid)
	}
	var err error
	in.RemediationNote, err = defenseText(in.RemediationNote, "개선 조치 설명", 0, 8000)
	if err != nil {
		return nil, err
	}
	if in.BaselineID != nil && (*in.BaselineID <= 0 || in.RemediationNote == "") {
		return nil, fmt.Errorf("%w: 기준 실행과 개선 조치 설명이 필요합니다", ErrDefenseInvalid)
	}
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, err
	}
	state, err := findingDefenseTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	if state.Plan == nil || state.Plan.Revision != in.PlanRevision || state.EvidenceVersion != *in.ExpectedEvidenceVersion || state.SourceFingerprint != in.ExpectedSourceFingerprint {
		return nil, ErrDefenseConflict
	}
	var source json.RawMessage
	var revision int64
	if in.SourceKind == "file" {
		config, err := securitysource.ValidateFileConfig(*in.FileConfig)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDefenseInvalid, err)
		}
		revision = 1
		source, err = json.Marshal(map[string]any{"kind": "file", "name": config.Label, "config": config, "revision": revision})
		if err != nil {
			return nil, err
		}
	} else {
		var enabled, credentialSet bool
		err = tx.QueryRowContext(ctx, `SELECT jsonb_build_object('id',id::text,'name',name,'revision',revision,'config',config,'enabled',enabled,'credential_set',octet_length(secret_cipher)>0,'updated_at',updated_at),revision,enabled,octet_length(secret_cipher)>0 FROM security_sources WHERE id=$1 FOR SHARE`, in.SourceID).Scan(&source, &revision, &enabled, &credentialSet)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: 증거 소스를 찾을 수 없습니다", ErrDefenseInvalid)
		}
		if err != nil {
			return nil, err
		}
		if !enabled || !credentialSet {
			return nil, fmt.Errorf("%w: 활성화되고 인증 정보가 설정된 증거 소스가 필요합니다", ErrDefenseInvalid)
		}
		var publicSource struct {
			Config securitysource.Config `json:"config"`
		}
		if err := json.Unmarshal(source, &publicSource); err != nil {
			return nil, err
		}
		if _, err := securitysource.Validate(publicSource.Config); err != nil {
			return nil, fmt.Errorf("%w: 증거 소스 설정을 확인해 주세요", ErrDefenseInvalid)
		}
	}
	if in.BaselineID != nil {
		baseline, err := getDefenseExecutionMetadataTx(ctx, tx, findingID, *in.BaselineID)
		if err != nil {
			return nil, err
		}
		var assessed bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM finding_defense_assessments WHERE execution_id=$1)`, baseline.ID).Scan(&assessed); err != nil {
			return nil, err
		}
		if baseline.Retest == nil || baseline.Retest.FinishedAt == nil || baseline.Retest.FinishedAt.After(retest.CreatedAt) || !assessed {
			return nil, fmt.Errorf("%w: 종료되고 판정이 저장된 이전 실행만 기준으로 사용할 수 있습니다", ErrDefenseInvalid)
		}
	}
	var diagnosis json.RawMessage
	err = tx.QueryRowContext(ctx, `SELECT jsonb_build_object('finding',snapshot->'finding','constraints',COALESCE(snapshot->'constraints','[]'::jsonb),
	'assets',COALESCE((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('id',a->'id','type',a->'type','domain',a->'domain','ip',a->'ip','port',a->'port','url',a->'url','method',a->'method')) ORDER BY (a->>'id')::bigint)
	FROM jsonb_array_elements(COALESCE(NULLIF(snapshot->'assets','null'::jsonb),'[]'::jsonb)) a),'[]'::jsonb)) FROM finding_retests WHERE id=$1 AND finding_id=$2`, retest.ID, findingID).Scan(&diagnosis)
	if err != nil {
		return nil, err
	}
	copyRetest := *retest
	copyRetest.Snapshot = nil
	rawRetest, err := json.Marshal(&copyRetest)
	if err != nil {
		return nil, err
	}
	rawPlan, err := json.Marshal(state.Plan)
	if err != nil {
		return nil, err
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO finding_defense_executions(finding_id,source_id,source_revision,source_snapshot,retest_id,retest_snapshot,diagnosis_snapshot,correlation_id,plan_snapshot,evidence_version,source_fingerprint,baseline_id,remediation_note,source_kind)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`, findingID, in.SourceID, revision, source, retest.ID, rawRetest, diagnosis, uuid.NewString(), rawPlan, state.EvidenceVersion, state.SourceFingerprint, in.BaselineID, in.RemediationNote, in.SourceKind).Scan(&id)
	if err != nil {
		return nil, err
	}
	return getDefenseExecutionTx(ctx, tx, findingID, id)
}

// The first terminal snapshot is frozen. The trigger covers conversation
// deletion/recovery too, while this helper makes the transaction hook explicit.
func snapshotDefenseRetestTx(ctx context.Context, tx *sql.Tx, retestID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE finding_defense_executions e SET retest_snapshot=to_jsonb(r)-'snapshot' FROM finding_retests r
	WHERE e.retest_id=$1 AND r.id=e.retest_id AND COALESCE(e.retest_snapshot->>'status','') NOT IN ('completed','failed','stopped')`, retestID)
	return err
}

func (d *DB) GetDefenseExecution(ctx context.Context, findingID, id int64) (*DefenseExecution, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	e, err := getDefenseExecutionTx(ctx, tx, findingID, id)
	if err != nil {
		return nil, err
	}
	return e, tx.Commit()
}

// Collection preparation needs the frozen source and retest, not every prior
// uploaded file. Full raw history remains available only through the export read.
func (d *DB) GetDefenseExecutionForCollection(ctx context.Context, findingID, id int64) (*DefenseExecution, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	e, err := getDefenseExecutionMetadataTx(ctx, tx, findingID, id)
	if err != nil {
		return nil, err
	}
	return e, tx.Commit()
}

func (d *DB) ListDefenseExecutions(ctx context.Context, findingID int64) ([]*DefenseExecution, error) {
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
	rows, err := tx.QueryContext(ctx, executionSelect+`WHERE e.finding_id=$1 ORDER BY e.id DESC LIMIT 30`, findingID)
	if err != nil {
		return nil, err
	}
	out := []*DefenseExecution{}
	for rows.Next() {
		e, err := scanDefenseExecution(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, e := range out {
		e.DiagnosisSnapshot = nil
		if err := loadDefenseAssessmentsTx(ctx, tx, e, true); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

func (d *DB) DefenseExecutionForRetest(ctx context.Context, retestID int64) (*DefenseExecution, error) {
	var findingID, id int64
	err := d.QueryRowContext(ctx, `SELECT finding_id,id FROM finding_defense_executions WHERE retest_id=$1`, retestID).Scan(&findingID, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return d.GetDefenseExecution(ctx, findingID, id)
}

func countDefenseEvidence(a *DefenseAssessment) {
	a.EventCount, a.AuditCount, a.AlertCount = 0, 0, 0
	if a.Evidence == nil {
		return
	}
	a.EventCount = len(a.Evidence.Events)
	for _, event := range a.Evidence.Events {
		switch event.Kind {
		case "audit":
			a.AuditCount++
		case "alert":
			a.AlertCount++
		}
	}
}

func previewDefenseAssessment(a *DefenseAssessment) *DefenseAssessment {
	if a.Evidence == nil {
		return a
	}
	copy := *a
	ev := *a.Evidence
	limit := len(ev.Events)
	if limit > 20 {
		limit = 20
	}
	ev.Events = append([]securitysource.Event{}, ev.Events[:limit]...)
	for i := range ev.Events {
		ev.Events[i].Raw = nil
	}
	copy.Evidence = &ev
	copy.EvidenceTruncated = len(a.Evidence.Events) > limit
	for _, event := range a.Evidence.Events {
		if len(event.Raw) > 0 {
			copy.EvidenceTruncated = true
			break
		}
	}
	if ev.Upload != nil {
		upload := *ev.Upload
		upload.Files = append([]securitysource.UploadedFileEvidence{}, ev.Upload.Files...)
		for i := range upload.Files {
			if upload.Files[i].Content != "" {
				copy.EvidenceTruncated = true
			}
			upload.Files[i].Content = ""
		}
		ev.Upload = &upload
	}
	return &copy
}

// assessDefenseEvidence does not read a model verdict or HTTP status. Only a
// completed test and correlated source artifacts can support its conclusions.
func assessDefenseEvidence(e *DefenseExecution, evidence *securitysource.Evidence) (*DefenseAssessment, error) {
	if e == nil || evidence == nil || evidence.CollectedAt.IsZero() || evidence.WindowStart.IsZero() || !evidence.WindowEnd.After(evidence.WindowStart) || evidence.WindowEnd.Sub(evidence.WindowStart) > 24*time.Hour || evidence.CollectedAt.Before(evidence.WindowEnd) || evidence.CollectedAt.After(time.Now().Add(5*time.Minute)) || len(evidence.Events) > 400 {
		return nil, fmt.Errorf("%w: 증거 수집 시각·조회 범위·이벤트 수를 확인해 주세요", ErrDefenseInvalid)
	}
	if _, err := uuid.Parse(e.CorrelationID); err != nil {
		return nil, fmt.Errorf("%w: 실행 상관 ID가 올바르지 않습니다", ErrDefenseInvalid)
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: 증거 형식이 올바르지 않습니다", ErrDefenseInvalid)
	}
	maxBytes := 16 << 20
	if e.SourceKind == "file" {
		maxBytes = 32 << 20
	}
	if len(raw) > maxBytes || defenseJSONContainsNUL(raw) {
		return nil, fmt.Errorf("%w: 증거 크기나 문자를 확인해 주세요", ErrDefenseInvalid)
	}
	if err := validateDefenseEvidenceSource(e, evidence); err != nil {
		return nil, err
	}
	out := &DefenseAssessment{ExecutionID: e.ID, Detection: "inconclusive", Prevention: "inconclusive", Reasons: []string{}, Recommendations: []string{}, Diagnostics: append([]securitysource.Diagnostic{}, evidence.Diagnostics...), Evidence: evidence}
	reliable := true
	add := func(code, certainty, reason, recommendation string) {
		out.Reasons = append(out.Reasons, reason)
		out.Recommendations = append(out.Recommendations, recommendation)
		out.Diagnostics = append(out.Diagnostics, securitysource.Diagnostic{Code: code, Certainty: certainty, Message: reason, Recommendation: recommendation})
	}
	for _, diagnostic := range evidence.Diagnostics {
		out.Reasons = append(out.Reasons, diagnostic.Message)
		out.Recommendations = append(out.Recommendations, diagnostic.Recommendation)
	}
	if evidence.Upload != nil {
		add("file_coverage_attested", "observed", "파일 판정은 업로더가 확인한 로그 출처·조회 범위에 의존하며 독립적으로 검증한 수집 결과가 아닙니다", "원본 로그 시스템에서 조회 조건과 시간 범위를 확인하고 내보낸 파일을 보관하세요")
		if !evidence.Upload.CoverageComplete {
			reliable = false
			add("file_coverage_unconfirmed", "observed", "전체 조회 범위가 포함됐다는 업로더 확인이 없습니다", "감사·경보 로그가 실행 전체 시간 범위를 포함하는지 확인한 뒤 다시 업로드하세요")
		}
		hasAudit, hasAlert := false, false
		for _, file := range evidence.Upload.Files {
			hasAudit = hasAudit || file.Kind == "audit"
			hasAlert = hasAlert || file.Kind == "alert"
		}
		if !hasAudit {
			reliable = false
			add("audit_file_missing", "observed", "감사 로그 파일이 제공되지 않았습니다", "실행 상관 ID와 조치 필드가 포함된 원본 감사 로그를 업로드하세요")
		}
		if !hasAlert && !evidence.Upload.NoAlerts {
			reliable = false
			add("alert_export_unconfirmed", "observed", "경보 파일도 경보 0건 확인도 제공되지 않았습니다", "같은 범위의 경보 파일을 업로드하거나 원본 조회에서 경보가 0건임을 확인하세요")
		}
	}
	if e.Retest == nil || e.Retest.Status != "completed" || e.Retest.FinishedAt == nil || e.Retest.Error != "" {
		reliable = false
		add("retest_incomplete", "observed", "재검증이 정상 완료되지 않아 방어 판정을 보류합니다", "재검증 실행 상태와 오류를 확인하고 정상 완료된 실행의 증거를 다시 수집하세요")
	}
	if !evidence.Complete || len(evidence.Warnings) > 0 {
		reliable = false
		add("evidence_incomplete", "observed", "로그 조회가 불완전하거나 수집 경고가 있습니다", "로그 조회 범위·내보내기 한도·수집기 상태를 확인한 뒤 동일 실행의 증거를 다시 제출하세요")
	}
	if e.Retest != nil {
		start := e.Retest.CreatedAt
		if e.Retest.StartedAt != nil {
			start = *e.Retest.StartedAt
		}
		if start.IsZero() || evidence.WindowStart.After(start.Add(-30*time.Second)) || e.Retest.FinishedAt != nil && (e.Retest.FinishedAt.Before(start) || evidence.WindowEnd.Before(*e.Retest.FinishedAt)) {
			reliable = false
			add("window_incomplete", "observed", "조회 범위가 재검증 실행 구간을 완전히 포함하지 않습니다", "실행 시작 30초 전부터 종료 후 수집 대기 구간까지 포함해 다시 조회하세요")
		}
	}
	audits, alerts, blocked, allowed, unknown := 0, 0, 0, 0, 0
	seen := map[string]bool{}
	inconsistent := false
	for _, event := range evidence.Events {
		key := event.Kind + ":" + event.ID
		if event.ID == "" || len(event.ID) > 1024 || event.Kind != "audit" && event.Kind != "alert" || event.CorrelationID != e.CorrelationID || event.OccurredAt.Before(evidence.WindowStart) || !event.OccurredAt.Before(evidence.WindowEnd) || seen[key] || event.Action != "blocked" && event.Action != "allowed" && event.Action != "unknown" {
			inconsistent = true
			continue
		}
		seen[key] = true
		if event.Kind == "alert" {
			alerts++
			continue
		}
		audits++
		switch event.Action {
		case "blocked":
			blocked++
		case "allowed":
			allowed++
		default:
			unknown++
		}
	}
	if inconsistent {
		reliable = false
		add("event_inconsistent", "observed", "실행 상관 ID·이벤트 시각·식별자가 일관되지 않습니다", "감사·경보 로그에 같은 ARTEX 실행 UUID가 기록되는지와 시각·중복 수집 설정을 확인하세요")
	}
	if audits == 0 {
		reliable = false
		add("audit_missing", "observed", "이 실행에 연결된 감사 로그가 없습니다", "재검증 요청의 상관 헤더 전달, 감사 로그 내보내기 범위와 상관 필드 매핑을 확인하세요. 로그가 없다는 이유만으로 미탐을 확정할 수 없습니다")
	}
	if !reliable {
		return out, nil
	}
	if alerts > 0 {
		out.Detection = "detected"
	} else {
		settled := e.Retest.FinishedAt.Add(60 * time.Second)
		if evidence.CollectedAt.Before(settled) || evidence.WindowEnd.Before(settled) {
			add("settling", "observed", "경보 수집 대기 시간 60초가 아직 충족되지 않았습니다", "재검증 종료 60초 뒤까지의 로그를 다시 수집한 후 미탐 여부를 확인하세요")
		} else {
			out.Detection = "missed"
			add("alert_absent", "observed", "제공된 조회 범위에 감사 로그는 있지만 동일 실행에 연결된 경보가 없습니다", "같은 실행 UUID로 원본 경보 조회와 내보내기 범위를 다시 확인하세요")
			add("rule_gap", "hypothesis", "규칙 조건·필드 매핑·활성화 또는 경보 UUID 전달 누락이 원인일 수 있지만 이 로그만으로 확정할 수 없습니다", "탐지 규칙 조건과 활성화 상태, 경보의 상관 ID 전달을 각각 점검하고 변경 후 새 실행으로 비교하세요")
		}
	}
	switch {
	case blocked > 0 && allowed == 0 && unknown == 0:
		out.Prevention = "blocked"
	case allowed > 0 && blocked == 0 && unknown == 0:
		out.Prevention = "not_blocked"
		add("audit_allowed", "observed", "감사 로그에 접근 허용 조치가 기록됐습니다", "해당 취약점의 인가·차단 정책을 검토하고 실제 변경 내용을 남겨 후속 실행으로 검증하세요")
	default:
		add("action_ambiguous", "observed", "감사 로그의 조치가 혼합되거나 명시되지 않았습니다", "조치 필드가 실제 blocked 또는 allowed 결과를 기록하도록 매핑하고 혼합 결과의 원인을 확인하세요")
	}
	return out, nil
}

func validateDefenseEvidenceSource(e *DefenseExecution, evidence *securitysource.Evidence) error {
	if e.SourceKind != "file" {
		if evidence.Upload != nil {
			return fmt.Errorf("%w: Splunk 실행에는 파일 증거를 저장할 수 없습니다", ErrDefenseInvalid)
		}
		return nil
	}
	config, err := defenseExecutionFileConfig(e)
	if err != nil {
		return err
	}
	if evidence.Upload == nil || evidence.Upload.Config != config {
		return fmt.Errorf("%w: 실행에 고정된 파일 출처·필드 매핑과 일치하는 업로드 증거가 필요합니다", ErrDefenseInvalid)
	}
	if len(evidence.Upload.Files) > 2 {
		return fmt.Errorf("%w: 감사·경보 파일은 각각 하나만 제공할 수 있습니다", ErrDefenseInvalid)
	}
	total := 0
	seen := map[string]bool{}
	for _, file := range evidence.Upload.Files {
		sum := sha256.Sum256([]byte(file.Content))
		if file.Kind != "audit" && file.Kind != "alert" || seen[file.Kind] || file.Name == "" || file.Bytes != len(file.Content) || file.Rows < 0 || file.SHA256 != fmt.Sprintf("%x", sum) {
			return fmt.Errorf("%w: 업로드 파일의 원본·해시·출처 정보가 일치하지 않습니다", ErrDefenseInvalid)
		}
		seen[file.Kind] = true
		total += len(file.Content)
	}
	if evidence.Upload.NoAlerts && seen["alert"] {
		return fmt.Errorf("%w: 경보 파일과 경보 0건 확인을 동시에 제출할 수 없습니다", ErrDefenseInvalid)
	}
	if evidence.Upload.NoAlerts {
		for _, event := range evidence.Events {
			if event.Kind == "alert" {
				return fmt.Errorf("%w: 경보 0건 확인과 실제 경보 이벤트가 모순됩니다", ErrDefenseInvalid)
			}
		}
	}
	if total > securitysource.MaxUploadBytes {
		return fmt.Errorf("%w: 업로드 원본 크기 한도를 넘었습니다", ErrDefenseInvalid)
	}
	return nil
}

// PostgreSQL JSONB rejects actual NUL characters. A literal backslash-u0000 in
// an uploaded file is ordinary text and must not be confused with decoded NUL.
func defenseJSONContainsNUL(raw []byte) bool {
	if !bytes.Contains(raw, []byte(`\u0000`)) {
		return false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return true
	}
	var contains func(any) bool
	contains = func(v any) bool {
		switch x := v.(type) {
		case string:
			return strings.ContainsRune(x, 0)
		case []any:
			for _, element := range x {
				if contains(element) {
					return true
				}
			}
		case map[string]any:
			for key, element := range x {
				if strings.ContainsRune(key, 0) || contains(element) {
					return true
				}
			}
		}
		return false
	}
	return contains(value)
}

func defenseExecutionFileConfig(e *DefenseExecution) (securitysource.FileConfig, error) {
	var snapshot struct {
		Kind     string                    `json:"kind"`
		Name     string                    `json:"name"`
		Revision int64                     `json:"revision"`
		Config   securitysource.FileConfig `json:"config"`
	}
	if json.Unmarshal(e.SourceSnapshot, &snapshot) != nil || snapshot.Kind != "file" || snapshot.Revision != 1 || e.SourceRevision != 1 || e.SourceID != 0 {
		return snapshot.Config, fmt.Errorf("%w: 파일 출처 스냅샷이 올바르지 않습니다", ErrDefenseInvalid)
	}
	config, err := securitysource.ValidateFileConfig(snapshot.Config)
	if err != nil || config != snapshot.Config || snapshot.Name != config.Label {
		return config, fmt.Errorf("%w: 파일 출처 스냅샷 설정이 올바르지 않습니다", ErrDefenseInvalid)
	}
	return config, nil
}

func (d *DB) SaveDefenseAssessment(ctx context.Context, findingID, executionID int64, evidence *securitysource.Evidence) (*DefenseAssessment, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, err
	}
	e, err := getDefenseExecutionMetadataTx(ctx, tx, findingID, executionID)
	if err != nil {
		return nil, err
	}
	if e.SourceKind == "splunk" {
		var enabled, configMatches bool
		var revision int64
		err = tx.QueryRowContext(ctx, `SELECT s.enabled,s.revision,s.config=e.source_snapshot->'config' FROM security_sources s JOIN finding_defense_executions e ON e.source_id=s.id WHERE s.id=$1 AND e.id=$2 FOR SHARE OF s`, e.SourceID, e.ID).Scan(&enabled, &revision, &configMatches)
		if errors.Is(err, sql.ErrNoRows) || err == nil && (!enabled || revision != e.SourceRevision || !configMatches) {
			return nil, ErrDefenseConflict
		}
		if err != nil {
			return nil, err
		}
	}
	a, err := assessDefenseEvidence(e, evidence)
	if err != nil {
		return nil, err
	}
	reasons, _ := json.Marshal(a.Reasons)
	recommendations, _ := json.Marshal(a.Recommendations)
	diagnostics, _ := json.Marshal(a.Diagnostics)
	raw, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	out, err := scanDefenseAssessment(tx.QueryRowContext(ctx, `INSERT INTO finding_defense_assessments(finding_id,execution_id,detection,prevention,reasons,recommendations,diagnostics,evidence)
	VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,execution_id,detection,prevention,reasons,recommendations,diagnostics,evidence,created_at`, findingID, executionID, a.Detection, a.Prevention, reasons, recommendations, diagnostics, raw))
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func (d *DB) CompareDefenseExecutions(ctx context.Context, findingID, baselineID, currentID int64) (*DefenseComparison, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	baseline, err := getDefenseExecutionMetadataTx(ctx, tx, findingID, baselineID)
	if err != nil {
		return nil, err
	}
	current, err := getDefenseExecutionMetadataTx(ctx, tx, findingID, currentID)
	if err != nil {
		return nil, err
	}
	for _, execution := range []*DefenseExecution{baseline, current} {
		if err := loadDefenseAssessmentsTx(ctx, tx, execution, true); err != nil {
			return nil, err
		}
	}
	out := &DefenseComparison{Baseline: baseline, Current: current, Comparable: true, Reasons: []string{}}
	reject := func(reason string) { out.Comparable = false; out.Reasons = append(out.Reasons, reason) }
	if baselineID == currentID || current.BaselineID == nil || *current.BaselineID != baselineID {
		reject("개선 실행이 선택한 기준 실행과 명시적으로 연결되지 않았습니다")
	}
	if current.RemediationNote == "" {
		reject("개선 조치 설명이 없습니다")
	}
	baselineScope, baselineScopeOK := defenseDiagnosisScope(baseline.DiagnosisSnapshot)
	currentScope, currentScopeOK := defenseDiagnosisScope(current.DiagnosisSnapshot)
	if !baselineScopeOK || !currentScopeOK {
		reject("원본 진단 범위 스냅샷이 없어 동일 대상 여부를 확인할 수 없습니다")
	} else if baselineScope != currentScope {
		reject("두 실행의 원본 대상 자산·취약점 유형·작업 제약이 다릅니다")
	}

	if baseline.SourceKind != current.SourceKind {
		reject("두 실행의 증거 소스 종류가 다릅니다")
	} else if baseline.SourceKind == "file" {
		baselineConfig, baselineErr := defenseExecutionFileConfig(baseline)
		currentConfig, currentErr := defenseExecutionFileConfig(current)
		if baselineErr != nil || currentErr != nil || baselineConfig != currentConfig {
			reject("두 실행의 파일 로그 출처 이름 또는 필드 매핑이 다릅니다")
		}
	} else if baseline.SourceID != current.SourceID || baseline.SourceRevision != current.SourceRevision {
		reject("두 실행의 증거 소스 또는 설정 버전이 다릅니다")
	}
	if current.State != "current" {
		reject("현재 실행 이후 계획·취약점 증거·대상 자산·작업 제약·소스 설정이 변경됐습니다")
	}
	for _, e := range []*DefenseExecution{baseline, current} {
		if e.Retest == nil || e.Retest.Status != "completed" || e.Retest.FinishedAt == nil {
			reject("두 재검증 모두 정상 완료되어야 합니다")
			break
		}
	}
	if len(baseline.Assessments) == 0 || len(current.Assessments) == 0 {
		reject("두 실행 모두 저장된 소스 판정이 필요합니다")
	} else {
		for _, a := range []*DefenseAssessment{baseline.Assessments[0], current.Assessments[0]} {
			if a.Detection == "inconclusive" || a.Prevention == "inconclusive" {
				reject("최신 판정에 불확실한 탐지·차단 결과가 있어 개선 여부를 확정할 수 없습니다")
				break
			}
		}
	}
	if baseline.Retest != nil && baseline.Retest.FinishedAt != nil && current.Retest != nil && baseline.Retest.FinishedAt.After(current.Retest.CreatedAt) {
		reject("기준 실행이 개선 실행보다 먼저 종료되지 않았습니다")
	}
	// Correlation UUIDs are intentionally different per run. Comparability is
	// established by the same source configuration, not equality of raw IDs.
	if _, err := uuid.Parse(baseline.CorrelationID); err != nil {
		reject("기준 실행 상관 ID가 올바르지 않습니다")
	}
	if _, err := uuid.Parse(current.CorrelationID); err != nil {
		reject("개선 실행 상관 ID가 올바르지 않습니다")
	}
	return out, tx.Commit()
}

// Marshal only the diagnostic target/constraints for comparison. Rules, evidence
// content and remediation may evolve, but a different target is not a baseline.
func defenseDiagnosisScope(raw json.RawMessage) (string, bool) {
	type constraint struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	var snapshot struct {
		Finding     json.RawMessage              `json:"finding"`
		Assets      []map[string]json.RawMessage `json:"assets"`
		Constraints []constraint                 `json:"constraints"`
	}
	if json.Unmarshal(raw, &snapshot) != nil || len(snapshot.Finding) == 0 || string(snapshot.Finding) == "null" || snapshot.Assets == nil || snapshot.Constraints == nil {
		return "", false
	}
	var finding struct {
		VulnClass string `json:"vulnclass"`
	}
	if json.Unmarshal(snapshot.Finding, &finding) != nil {
		return "", false
	}
	assetIDs := make(map[string]int64, len(snapshot.Assets))
	for i, asset := range snapshot.Assets {
		var id int64
		if json.Unmarshal(asset["id"], &id) != nil || id <= 0 {
			return "", false
		}
		filtered := make(map[string]json.RawMessage)
		for _, key := range []string{"id", "type", "domain", "ip", "port", "url", "method"} {
			if value := asset[key]; len(value) > 0 && string(value) != "null" {
				filtered[key] = value
			}
		}
		snapshot.Assets[i] = filtered
		assetIDs[string(filtered["id"])] = id
	}
	sort.Slice(snapshot.Assets, func(i, j int) bool {
		return assetIDs[string(snapshot.Assets[i]["id"])] < assetIDs[string(snapshot.Assets[j]["id"])]
	})
	sort.Slice(snapshot.Constraints, func(i, j int) bool {
		if snapshot.Constraints[i].Kind != snapshot.Constraints[j].Kind {
			return snapshot.Constraints[i].Kind < snapshot.Constraints[j].Kind
		}
		return snapshot.Constraints[i].Text < snapshot.Constraints[j].Text
	})
	value := struct {
		VulnClass   string
		Assets      []map[string]json.RawMessage
		Constraints []constraint
	}{finding.VulnClass, snapshot.Assets, snapshot.Constraints}
	b, err := json.Marshal(value)
	return string(b), err == nil
}
