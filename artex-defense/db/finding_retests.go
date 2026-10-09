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

const FindingRetestAgentKey = "retester"

// 재검증(finding_retest) 종결 사유. finding_retests.error 컬럼에 저장돼 재검증 패널
// (finding-retest-panel) 의 item.error 로 노출된다(사용자 노출, server/conversations.go 의
// 형제 사유 convRetest* 와 같은 컬럼·패널이라 함께 한국어로 둔다 — F9). retestNoConclusionReason
// 은 에이전트가 결론 없이 완료했을 때 caller 가 넘긴 사유를 덮어쓰는 폴백이고,
// retestServiceRestartReason 은 재시작 복구(RecoverFindingRetests)가 미완 재검증을 봉인할 때 쓴다.
// 작은따옴표 없는 상수라 SQL 리터럴 자리에 그대로 이어 붙여도 안전하다.
const (
	retestNoConclusionReason   = "에이전트가 재검증 결론을 저장하지 않았습니다. 대화를 확인한 뒤 다시 재검증해 주세요"
	retestServiceRestartReason = "서비스가 재시작되어 재검증이 중단되었습니다. 다시 시작해 주세요"
)

var ErrRetestNotRunning = errors.New("本次复测已结束或尚未开始，请从漏洞详情发起新的复测")

// FindingRetest is an immutable historical test once its conversation turn ends.
// Snapshot is only loaded for the agent, never sent with the history list.
type FindingRetest struct {
	ID                   int64           `json:"id"`
	FindingID            int64           `json:"finding_id"`
	ConversationID       *int64          `json:"conversation_id"`
	Status               string          `json:"status"`
	Verdict              string          `json:"verdict"`
	Notes                string          `json:"notes"`
	Snapshot             json.RawMessage `json:"snapshot,omitempty"`
	Summary              string          `json:"summary"`
	Evidence             string          `json:"evidence"`
	Error                string          `json:"error"`
	CreatedAt            time.Time       `json:"created_at"`
	StartedAt            *time.Time      `json:"started_at"`
	FinishedAt           *time.Time      `json:"finished_at"`
	defenseCorrelationID string
}

const retestCols = `id, finding_id, conversation_id, status, verdict, notes, summary, evidence, error, created_at, started_at, finished_at`

// ActiveFindingRetest is the small status payload polled by the findings list.
// Finding IDs use the same string representation as the findings API.
type ActiveFindingRetest struct {
	ID             int64  `json:"id"`
	FindingID      int64  `json:"finding_id,string"`
	ConversationID int64  `json:"conversation_id"`
	Status         string `json:"status"`
}

func (d *DB) ListActiveFindingRetests(ctx context.Context) ([]ActiveFindingRetest, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, finding_id, conversation_id, status FROM finding_retests
	WHERE status IN ('pending','running') AND conversation_id IS NOT NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ActiveFindingRetest{}
	for rows.Next() {
		var item ActiveFindingRetest
		if err := rows.Scan(&item.ID, &item.FindingID, &item.ConversationID, &item.Status); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanRetest(row interface{ Scan(...any) error }) (*FindingRetest, error) {
	r := &FindingRetest{}
	err := row.Scan(&r.ID, &r.FindingID, &r.ConversationID, &r.Status, &r.Verdict, &r.Notes,
		&r.Summary, &r.Evidence, &r.Error, &r.CreatedAt, &r.StartedAt, &r.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// CreateFindingRetest atomically snapshots the source, creates its conversation
// and persists the first message. A finding row lock deduplicates simultaneous
// clicks across clients; an existing active run is returned without dispatching.
func (d *DB) CreateFindingRetest(ctx context.Context, findingID int64, notes string) (*FindingRetest, *Conversation, bool, error) {
	r, c, _, created, err := d.createFindingRetest(ctx, findingID, notes, nil)
	return r, c, created, err
}

// CreateFindingRetestWithDefense associates the immutable defense execution
// before the first conversation message is persisted or an agent is dispatched.
// An already active retest cannot acquire a new correlation ID retroactively.
func (d *DB) CreateFindingRetestWithDefense(ctx context.Context, findingID int64, notes string, input DefenseExecutionInput) (*FindingRetest, *Conversation, *DefenseExecution, bool, error) {
	return d.createFindingRetest(ctx, findingID, notes, &input)
}

func (d *DB) createFindingRetest(ctx context.Context, findingID int64, notes string, defense *DefenseExecutionInput) (*FindingRetest, *Conversation, *DefenseExecution, bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, false, err
	}
	defer tx.Rollback()
	if defense != nil {
		if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
			return nil, nil, nil, false, err
		}
	}
	var title string
	var snapshot []byte
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(f.name,''), NULLIF(f.vulnclass,''), '未分类'),
	jsonb_build_object('finding', to_jsonb(f),
	 'assets', COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM assets a WHERE f.asset_ids @> to_jsonb(ARRAY[a.id])), '[]'::jsonb),
	 'constraints', COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM task_constraints c JOIN tasks t ON t.exploration_id=c.exploration_id WHERE t.id=f.task_id), '[]'::jsonb))
	FROM findings f WHERE f.id=$1 FOR UPDATE OF f`, findingID).Scan(&title, &snapshot)
	if err != nil {
		return nil, nil, nil, false, err
	}
	r, err := scanRetest(tx.QueryRowContext(ctx, `SELECT `+retestCols+` FROM finding_retests WHERE finding_id=$1 AND status IN ('pending','running')`, findingID))
	if err != nil {
		return nil, nil, nil, false, err
	}
	if r != nil {
		if defense != nil {
			return nil, nil, nil, false, ErrDefenseConflict
		}
		return r, nil, nil, false, nil
	}
	// Keep the title within the same limit as ordinary conversations.
	if runes := []rune(title); len(runes) > 100 {
		title = string(runes[:100])
	}
	c, err := scanConv(tx.QueryRowContext(ctx, `INSERT INTO conversations(agent_key,title) VALUES ($1,$2) RETURNING `+convCols,
		FindingRetestAgentKey, fmt.Sprintf("复测 #%d · %s", findingID, title)))
	if err != nil {
		return nil, nil, nil, false, err
	}
	r, err = scanRetest(tx.QueryRowContext(ctx, `INSERT INTO finding_retests(finding_id,conversation_id,notes,snapshot) VALUES ($1,$2,$3,$4) RETURNING `+retestCols,
		findingID, c.ID, strings.TrimSpace(notes), snapshot))
	if err != nil {
		return nil, nil, nil, false, err
	}
	var execution *DefenseExecution
	if defense != nil {
		execution, err = createDefenseExecutionTx(ctx, tx, findingID, r, *defense)
		if err != nil {
			return nil, nil, nil, false, err
		}
		r.defenseCorrelationID = execution.CorrelationID
	}
	msg := r.InitialMessage()
	_, err = tx.ExecContext(ctx, `INSERT INTO conversation_activities(conversation_id,worker,kind,summary,detail) VALUES ($1,$2,'user',$3,$4)`,
		c.ID, FindingRetestAgentKey, fmt.Sprintf("请复测漏洞 #%d", findingID), msg)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, nil, false, err
	}
	return r, &c, execution, true, nil
}

func (r *FindingRetest) InitialMessage() string {
	msg := fmt.Sprintf("请复测漏洞 #%d。先调用 get_finding_retest_context 读取本会话关联的原始证据与约束，再执行针对性验证，最后调用 record_finding_retest_result 保存结论。", r.FindingID)
	if r.Notes != "" {
		msg += "\n\n本次复测补充说明：\n" + r.Notes
	}
	if r.defenseCorrelationID != "" {
		msg += "\n\n本次复测已关联防御验证执行。先从 get_finding_retest_context 读取服务端提供的 defense_execution。只给已授权原目标上实际复现原漏洞触发条件的 HTTP 请求添加关联头 X-ARTEX-Verification-ID: " + r.defenseCorrelationID + "。登录、会话准备与良性对照请求不得附加这个关联 ID；它们仍应按原复测流程执行并单独记录。保留原身份、认证、请求条件和任务约束；不得为了打标扩大目标范围或改变漏洞关键条件。非 HTTP 或无法可靠附加关联头时如实说明，不伪造日志、请求、告警或阻断证明。关联标记本身不证明安全设备检测成功；检测结论由独立的安全日志采集与证据判定完成。"
	}
	return msg
}

func (d *DB) ListFindingRetests(findingID int64) ([]*FindingRetest, error) {
	rows, err := d.Query(`SELECT `+retestCols+` FROM finding_retests WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FindingRetest{}
	for rows.Next() {
		r, err := scanRetest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) FindingRetestForConversation(ctx context.Context, conversationID int64) (*FindingRetest, error) {
	r, err := scanRetest(d.QueryRowContext(ctx, `SELECT `+retestCols+` FROM finding_retests WHERE conversation_id=$1`, conversationID))
	if err != nil || r == nil {
		return r, err
	}
	err = d.QueryRowContext(ctx, `SELECT snapshot FROM finding_retests WHERE id=$1`, r.ID).Scan(&r.Snapshot)
	return r, err
}

// FailPendingRetestForConversation seals a conversation's unfinished retest when
// the runner could not even load it — the retest ID is unknown on that path, so
// the conversation ID is the only handle. Without it a transient read error
// leaves the row 'pending' forever: the findings list keeps showing 复测中 and
// every later 发起复测 is deduped against a run that is not happening, with only
// a process restart (RecoverFindingRetests) able to clear it.
func (d *DB) FailPendingRetestForConversation(conversationID int64, reason string) error {
	_, err := d.Exec(`UPDATE finding_retests SET status='failed', error=$2, finished_at=now()
		WHERE conversation_id=$1 AND status IN ('pending','running')`, conversationID, reason)
	return err
}

func (d *DB) StartFindingRetest(ctx context.Context, id int64) (bool, error) {
	res, err := d.ExecContext(ctx, `UPDATE finding_retests SET status='running', started_at=now() WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecordFindingRetestResult never accepts a finding ID: ownership comes from the
// runtime conversation. Identical retries are safe; a second verdict is refused.
func (d *DB) RecordFindingRetestResult(ctx context.Context, conversationID int64, verdict, summary, evidence string) error {
	if verdict != "reproduced" && verdict != "fixed" && verdict != "inconclusive" {
		return errors.New("verdict 必须为 reproduced / fixed / inconclusive")
	}
	summary, evidence = strings.TrimSpace(summary), strings.TrimSpace(evidence)
	if summary == "" || evidence == "" {
		return errors.New("summary 与 evidence 不能为空；无法确认时说明实际检查及阻塞原因")
	}
	if len(summary) > 16000 || len(evidence) > 128000 {
		return errors.New("复测结论过长（summary ≤ 16KB，evidence ≤ 128KB）")
	}
	res, err := d.ExecContext(ctx, `UPDATE finding_retests SET verdict=$2,summary=$3,evidence=$4
	WHERE conversation_id=$1 AND status='running' AND (verdict='' OR (verdict=$2 AND summary=$3 AND evidence=$4))`, conversationID, verdict, summary, evidence)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrRetestNotRunning
	}
	return nil
}

// FinishFindingRetest seals the result. Cancellation/failure takes precedence
// over a staged verdict so an interrupted test cannot appear successfully fixed.
// Only a newly completed fixed verdict updates triage, in the same transaction.
func (d *DB) FinishFindingRetest(id int64, status, reason string) error {
	if status != "completed" && status != "failed" && status != "stopped" {
		return errors.New("invalid terminal retest status")
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock the finding before the retest, matching creation and cascading deletion.
	var findingID int64
	err = tx.QueryRow(`SELECT f.id FROM findings f WHERE f.id=(SELECT finding_id FROM finding_retests WHERE id=$1) FOR UPDATE OF f`, id).Scan(&findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // Finding/retest already deleted.
	}
	if err != nil {
		return err
	}
	var finalStatus, verdict string
	err = tx.QueryRow(`UPDATE finding_retests SET
	status=CASE WHEN $2='completed' AND verdict='' THEN 'failed' ELSE $2 END,
	error=CASE WHEN $2='completed' AND verdict='' THEN '`+retestNoConclusionReason+`' ELSE $3 END,
	finished_at=now() WHERE id=$1 AND status IN ('pending','running') RETURNING status,verdict`, id, status, reason).Scan(&finalStatus, &verdict)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // A replay must not overwrite a later manual triage decision.
	}
	if err != nil {
		return err
	}
	if finalStatus == "completed" && verdict == "fixed" {
		// 走带通知的版本，与人工在详情页改状态共用同一套语义。
		//
		// 此前这里是裸的 UPDATE：复测判「已修复」时状态确实变了，但配了
		// on_status_change 的渠道完全收不到推送——状态在界面上悄悄变了，
		// 运维要打开平台才知道。状态更新与推送事件必须一起落库，
		// SetFindingStatusTx 内部处理了「状态没变就不登记」等细节。
		// 用 context.Background()：本函数整条都是无 ctx 的旧风格（d.Begin()/
		// tx.QueryRow/tx.Exec），没有可传递的取消信号，硬加一个 ctx 参数会
		// 牵动 server 侧调用点与多处测试，超出本次改动的范围。
		if _, _, _, _, err := SetFindingStatusTx(context.Background(), tx, findingID, FindingFixed); err != nil {
			return err
		}
	}
	if err := snapshotDefenseRetestTx(context.Background(), tx, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) RecoverFindingRetests() error {
	_, err := d.Exec(`UPDATE finding_retests SET status='stopped', error='` + retestServiceRestartReason + `', finished_at=now() WHERE status IN ('pending','running')`)
	return err
}
