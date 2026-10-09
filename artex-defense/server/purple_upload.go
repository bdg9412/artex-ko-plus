package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/securitysource"
)

// The wire allowance accounts for JSON escaping. ParseUpload independently
// bounds the actual UTF-8 file bytes and rows; no path or URL is ever opened.
const maxPurpleUploadRequestBytes = 24 << 20

func (s *Server) uploadDefenseExecution(w http.ResponseWriter, r *http.Request) {
	findingID, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	executionID, ok := defenseExecutionID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	execution, err := pg.GetDefenseExecutionForCollection(r.Context(), findingID, executionID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	if execution.SourceKind != "file" {
		writeErr(w, http.StatusConflict, "Splunk 연결 실행에는 파일을 업로드할 수 없습니다. 파일 연결로 새 실행을 시작해 주세요")
		return
	}
	query, windowComplete, err := defenseExecutionWindow(execution, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	var snapshot struct {
		Config securitysource.FileConfig `json:"config"`
	}
	if json.Unmarshal(execution.SourceSnapshot, &snapshot) != nil {
		writeErr(w, http.StatusConflict, "실행 당시 파일 연결 설정을 읽지 못했습니다")
		return
	}
	select {
	case defenseCollectSlots <- struct{}{}:
		defer func() { <-defenseCollectSlots }()
	default:
		writeErr(w, http.StatusTooManyRequests, "다른 증거 수집이 진행 중입니다. 잠시 후 다시 시도해 주세요")
		return
	}
	var input securitysource.FileUpload
	if !decodePurpleRequestLimit(w, r, &input, maxPurpleUploadRequestBytes) {
		return
	}
	evidence, err := securitysource.ParseUpload(snapshot.Config, input, query)
	if err != nil {
		if errors.Is(err, securitysource.ErrInvalid) {
			writeErr(w, http.StatusBadRequest, err.Error())
		} else {
			writeErr(w, http.StatusBadRequest, "로그 파일을 분석하지 못했습니다. 지원 형식과 필드 설정을 확인해 주세요")
		}
		return
	}
	if !windowComplete {
		evidence.Complete = false
		evidence.Warnings = append(evidence.Warnings, "진단 종료 후 60초의 관측 기간이 아직 끝나지 않았습니다. 이후 전체 기간의 로그를 다시 업로드해 주세요")
	}
	assessment, err := pg.SaveDefenseAssessment(r.Context(), findingID, executionID, evidence)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, assessment)
}
