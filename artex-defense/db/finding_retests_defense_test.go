package db

import (
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/securitysource"
)

func defenseRetestInput(t *testing.T, d *DB, findingID int64) DefenseExecutionInput {
	t.Helper()
	state, err := d.SaveDefensePlan(t.Context(), findingID, purplePlan())
	if err != nil {
		t.Fatal(err)
	}
	source, err := d.SaveSecuritySource(t.Context(), 0, 0, "retest association fixture", securitysource.Config{
		BaseURL: "https://siem.invalid", Index: "main", AuditSourcetype: "audit", AlertSourcetype: "alert", CorrelationField: "verification_id", ActionField: "action",
	}, true, []byte("test ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.DeleteFinding(findingID)
		_, _ = d.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID)
	})
	return DefenseExecutionInput{SourceID: source.ID, PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &state.EvidenceVersion, ExpectedSourceFingerprint: state.SourceFingerprint}
}

func TestPurpleRetestAtomicDefenseAssociation(t *testing.T) {
	d, fid := purpleDB(t)
	in := defenseRetestInput(t, d, fid)
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, fid)
	})
	bad := in
	bad.PlanRevision++
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(t.Context(), fid, "rollback", bad); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("stale input: %v", err)
	}
	rows, err := d.ListFindingRetests(fid)
	if err != nil || len(rows) != 0 {
		t.Fatalf("failed execution retained retest: %+v %v", rows, err)
	}
	r, c, execution, created, err := d.CreateFindingRetestWithDefense(t.Context(), fid, "authorized original target", in)
	if err != nil || !created || r == nil || c == nil || execution == nil {
		t.Fatalf("create: %+v %+v %+v %t %v", r, c, execution, created, err)
	}
	if execution.RetestID != r.ID || execution.FindingID != fid {
		t.Fatal("execution association differs")
	}
	var detail string
	if err := d.QueryRow(`SELECT detail FROM conversation_activities WHERE conversation_id=$1 AND kind='user'`, c.ID).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "X-ARTEX-Verification-ID: "+execution.CorrelationID) || !strings.Contains(r.InitialMessage(), execution.CorrelationID) {
		t.Fatal("dispatch/persisted prompt lacks server-owned correlation")
	}
	if !strings.Contains(detail, "实际复现原漏洞触发条件") || !strings.Contains(detail, "登录、会话准备与良性对照请求不得附加这个关联 ID") {
		t.Fatal("correlation scope includes login or benign control requests")
	}
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(t.Context(), fid, "duplicate", in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("active defense accepted: %v", err)
	}
	if ok, err := d.StartFindingRetest(t.Context(), r.ID); err != nil || !ok {
		t.Fatalf("start: %t %v", ok, err)
	}
	if err := d.RecordFindingRetestResult(t.Context(), c.ID, "inconclusive", "No independent alert assertion", "original diagnostic proof"); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishFindingRetest(r.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteConversation(c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDefenseExecution(t.Context(), fid, execution.ID)
	if err != nil || got.Retest == nil || got.Retest.Status != "completed" || got.Retest.FinishedAt == nil || got.Retest.Summary != "No independent alert assertion" {
		t.Fatalf("terminal snapshot lost: %+v %v", got, err)
	}
	if len(got.Assessments) != 0 {
		t.Fatal("retest model verdict fabricated defense assessment")
	}
}

func TestPurpleRetestDoesNotAttachToActiveOrdinaryRun(t *testing.T) {
	d, fid := purpleDB(t)
	in := defenseRetestInput(t, d, fid)
	r, c, _, err := d.CreateFindingRetest(t.Context(), fid, "ordinary")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteConversation(c.ID) })
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(t.Context(), fid, "too late", in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("active ordinary retest linked: %v", err)
	}
	execution, err := d.DefenseExecutionForRetest(t.Context(), r.ID)
	if err != nil || execution != nil {
		t.Fatalf("retroactive execution: %+v %v", execution, err)
	}
	if strings.Contains(r.InitialMessage(), "X-ARTEX-Verification-ID") {
		t.Fatal("ordinary prompt changed")
	}
	rows, err := d.ListDefenseExecutions(t.Context(), fid)
	if err != nil || len(rows) != 0 {
		t.Fatalf("unexpected execution: %+v %v", rows, err)
	}
}
