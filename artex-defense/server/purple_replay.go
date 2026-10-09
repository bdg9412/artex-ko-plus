package server

import (
	"fmt"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

// JSON escaping may expand a 1 MiB decoded log payload by six times. The
// evaluator separately limits decoded bytes and event count.
const maxPurpleReplayRequestBytes = 8 << 20

func (s *Server) registerPurpleReplays(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/exploration/findings/{id}/defense/replays", s.runFindingDefenseReplay)
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/replays", s.listFindingDefenseReplays)
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/replays/{runID}/export", s.exportFindingDefenseReplay)
}

func (s *Server) runFindingDefenseReplay(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	var in db.DefenseReplayInput
	if !decodePurpleRequestLimit(w, r, &in, maxPurpleReplayRequestBytes) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.RunDefenseReplay(r.Context(), id, in)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listFindingDefenseReplays(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.ListDefenseReplays(r.Context(), id)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}

func (s *Server) exportFindingDefenseReplay(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	runID, ok := pathInt(r, "runID")
	if !ok || runID <= 0 {
		writeErr(w, http.StatusBadRequest, "올바른 재생 기록 ID를 입력해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.ExportDefenseReplay(r.Context(), id, runID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="defense-replay-%d.json"`, runID))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
