package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

const taskArchivePollInterval = 2 * time.Second

type archiveBatchRequest struct {
	TaskIDs    []string `json:"task_ids"`
	ArchiveIDs []int64  `json:"archive_ids"`
}

type archiveBatchItem struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Queued  bool   `json:"queued"`
	Error   string `json:"error,omitempty"`
	Archive int64  `json:"archive_id,omitempty"`
}

func (s *Server) startTaskArchiveWorker() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	if err := s.m.pg.RecoverTaskArchiveJobs(); err != nil {
		log.Printf("[task-archive] recover jobs: %v", err)
	}
	recoveryFailed := false
	if err := recoverTaskArchiveStages(s.m.dir, s.m.pg); err != nil {
		log.Printf("[task-archive] recover file staging: %v", err)
		recoveryFailed = true
	}
	if err := recoverTaskArchiveRestoreStages(s.m.dir, s.m.pg); err != nil {
		log.Printf("[task-archive] recover restore staging: %v", err)
		recoveryFailed = true
	}
	if err := recoverTaskArchiveDeletePackages(s.m.dir, s.m.pg); err != nil {
		log.Printf("[task-archive] recover delete packages: %v", err)
		recoveryFailed = true
	}
	if recoveryFailed {
		log.Printf("[task-archive] worker disabled because startup recovery is incomplete")
		return
	}
	s.archiveWG.Add(1)
	go func() {
		defer s.archiveWG.Done()
		ticker := time.NewTicker(taskArchivePollInterval)
		defer ticker.Stop()
		for {
			if err := s.runOneTaskArchiveJob(); err != nil {
				log.Printf("[task-archive] worker: %v", err)
			}
			select {
			case <-s.ctx.Done():
				return
			case <-s.archiveWake:
			case <-ticker.C:
			}
		}
	}()
	s.notifyTaskArchiveWorker()
}

func (s *Server) notifyTaskArchiveWorker() {
	if s == nil || s.archiveWake == nil {
		return
	}
	select {
	case s.archiveWake <- struct{}{}:
	default:
	}
}

func (s *Server) runOneTaskArchiveJob() error {
	job, err := s.m.pg.ClaimTaskArchiveJob(s.ctx)
	if err != nil || job == nil {
		return err
	}
	var runErr error
	switch job.State {
	case pgdb.Archiving:
		runErr = s.archiveTask(job)
	case pgdb.Restoring:
		runErr = s.restoreTaskArchive(job)
	case pgdb.Deleting:
		runErr = s.deleteTaskArchive(job)
	default:
		runErr = fmt.Errorf("unknown claimed archive state %q", job.State)
	}
	if runErr != nil {
		if failErr := s.m.pg.FailTaskArchiveJob(job.ID, job.State, runErr); failErr != nil {
			return errors.Join(runErr, failErr)
		}
		return fmt.Errorf("archive job %d (%s): %w", job.ID, job.State, runErr)
	}
	// Drain another queued item without waiting for the periodic poll.
	s.notifyTaskArchiveWorker()
	return nil
}

func (s *Server) archiveTask(job *pgdb.TaskArchive) (runErr error) {
	taskID := strconv.FormatInt(job.TaskID, 10)
	if !s.beginTaskDelete(taskID) {
		return errors.New("이 작업은 다른 보관 또는 삭제 작업을 진행하고 있습니다")
	}
	committed := false
	defer func() {
		if !committed {
			s.abortTaskDelete(taskID)
		}
	}()
	s.cancelTaskChat(taskID, agent.AbortTaskDeleted)
	drainCtx, cancel := context.WithTimeout(s.ctx, taskDeleteDrainTimeout)
	defer cancel()
	if err := s.waitTaskQuiescent(drainCtx, taskID); err != nil {
		return errors.New("작업에 아직 실행 중인 에이전트가 있습니다. 먼저 일시정지한 뒤 보관을 다시 시도하세요")
	}
	if err := s.drainTaskSideQuestions(drainCtx, taskID); err != nil {
		return err
	}
	task, err := s.m.pg.GetTask(job.TaskID)
	if err != nil {
		return err
	}
	if task == nil {
		return pgdb.ErrTaskArchiveNotFound
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "stage_files", 10)
	fileStage, err := stageTaskArchiveFiles(s.m.dir, job.ID, taskID, task.ExplorationID)
	if err != nil {
		return err
	}
	defer func() {
		if !committed {
			runErr = errors.Join(runErr, fileStage.rollback())
		}
	}()
	streamPath := filepath.Join(fileStage.payload, filepath.FromSlash(pgdb.TaskArchiveLLMRecordsPath))
	if err := os.MkdirAll(filepath.Dir(streamPath), archiveDirMode); err != nil {
		return err
	}
	streamFile, err := os.OpenFile(streamPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, archiveFileMode)
	if err != nil {
		return err
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "snapshot_database", 20)
	snapshot, snapshotErr := s.m.pg.SnapshotTaskArchiveWithLLMRecords(job.TaskID, streamFile)
	var syncErr error
	if snapshotErr == nil {
		syncErr = streamFile.Sync()
	}
	closeErr := streamFile.Close()
	if err := errors.Join(snapshotErr, syncErr, closeErr); err != nil {
		return err
	}
	if snapshot.ExplorationID != task.ExplorationID {
		return errors.New("보관 스냅샷을 만드는 동안 작업 탐색 기록이 변경되었습니다")
	}
	if s.m.traffic != nil && len(snapshot.Hosts) > 0 {
		_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "snapshot_traffic", 38)
		trafficCount, err := s.m.traffic.ExportHosts(snapshot.Hosts, filepath.Join(fileStage.payload, "traffic"))
		if err != nil {
			return err
		}
		snapshot.DataCounts["traffic"] = trafficCount
	}
	archivePath := taskArchivePath(s.m.dir, job.ID, taskID)
	evidenceSnapshots, err := pgdb.ArchiveEvidenceSnapshots(snapshot)
	if err != nil {
		return err
	}
	if err = s.evidenceStore().CopySnapshots(s.ctx, evidenceSnapshots, filepath.Join(fileStage.payload, "evidence")); err != nil {
		return err
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "compress", 50)
	originalSize, compressedSize, checksum, err := writeTaskArchivePackage(archivePath, fileStage.payload, snapshot)
	if err != nil {
		return err
	}
	removePackage := true
	defer func() {
		if removePackage {
			_ = os.Remove(archivePath)
		}
	}()
	var trafficStage *traffic.HostDeleteStage
	if s.m.traffic != nil && len(snapshot.ExclusiveHosts) > 0 {
		_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "compact_traffic", 68)
		trafficStage, err = s.m.traffic.StageDeleteHostsExactForArchive(snapshot.ExclusiveHosts, job.ID, job.TaskID)
		if err != nil {
			return err
		}
		defer func() {
			if !committed {
				runErr = errors.Join(runErr, trafficStage.Rollback())
			}
		}()
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "compact_database", 78)
	if err := s.m.pg.CompleteTaskArchive(job.ID, snapshot, archivePath, checksum, originalSize, compressedSize); err != nil {
		return err
	}
	committed = true
	removePackage = false
	if trafficStage != nil {
		if err := trafficStage.Commit(); err != nil {
			warning := "보관을 완료했지만 전용 트래픽 핫 스토리지 정리에 실패했습니다(보관 패키지는 복원할 수 있습니다): " + err.Error()
			log.Printf("[task-archive] task %s: %s", taskID, warning)
			_ = s.m.pg.AppendTaskArchiveWarning(job.ID, warning)
		}
	}
	if err := fileStage.commit(); err != nil {
		warning := "보관을 완료했지만 임시 디렉터리 정리에 실패했습니다: " + err.Error()
		log.Printf("[task-archive] task %s: %s", taskID, warning)
		_ = s.m.pg.AppendTaskArchiveWarning(job.ID, warning)
	}
	s.engine.StopTask(taskID)
	s.taskAgentMu.Lock()
	delete(s.taskAgents, taskID)
	s.taskAgentMu.Unlock()
	s.m.forgetTask(taskID, job.TaskID)
	return nil
}

func (s *Server) restoreTaskArchive(job *pgdb.TaskArchive) (runErr error) {
	if err := validateArchivePath(s.m.dir, job.ArchivePath); err != nil {
		return err
	}
	// A prior attempt may have committed PostgreSQL and files, then failed only
	// while consuming the package. Finish that cleanup without replaying rows.
	if restored, err := s.m.pg.IsTaskArchiveRestored(job.ID); err != nil {
		return err
	} else if restored {
		if err := os.Remove(job.ArchivePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := s.m.pg.CompleteTaskArchiveRestore(job.ID); err != nil {
			return err
		}
		s.loadRestoredTask(job.TaskID)
		return nil
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "verify_package", 10)
	restoreParent := filepath.Join(taskArchiveRoot(s.m.dir), ".restore")
	if err := os.MkdirAll(restoreParent, archiveDirMode); err != nil {
		return err
	}
	extracted, err := os.MkdirTemp(restoreParent, fmt.Sprintf("%d-", job.ID))
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(extracted) }()
	if err := extractTaskArchivePackage(job.ArchivePath, job.SHA256, extracted); err != nil {
		return err
	}
	manifestRaw, err := os.ReadFile(filepath.Join(extracted, "manifest.json"))
	if err != nil {
		return err
	}
	var snapshot pgdb.TaskArchiveSnapshot
	if err := json.Unmarshal(manifestRaw, &snapshot); err != nil {
		return err
	}
	if snapshot.TaskID != job.TaskID || !pgdb.IsTaskArchiveFormatSupported(snapshot.FormatVersion) {
		return pgdb.ErrTaskArchiveFormatMismatch
	}
	evidenceSnapshots, err := pgdb.ArchiveEvidenceSnapshots(&snapshot)
	if err != nil {
		return err
	}
	return s.evidenceStore().WithInstalledSnapshots(s.ctx, evidenceSnapshots, filepath.Join(extracted, "evidence"), func() error {
		return s.restoreTaskArchivePayload(job, &snapshot, extracted)
	})
}

func (s *Server) restoreTaskArchivePayload(job *pgdb.TaskArchive, snapshot *pgdb.TaskArchiveSnapshot, extracted string) (runErr error) {
	var err error
	var llmRecordsFile *os.File
	relative, hasStreamedLLMRecords := snapshot.StreamedTables["llm_records"]
	if len(snapshot.StreamedTables) > 0 &&
		(snapshot.FormatVersion < 2 || !hasStreamedLLMRecords || len(snapshot.StreamedTables) != 1 ||
			relative != pgdb.TaskArchiveLLMRecordsPath) {
		return pgdb.ErrTaskArchiveFormatMismatch
	}
	if hasStreamedLLMRecords {
		llmRecordsFile, err = os.Open(filepath.Join(extracted, filepath.FromSlash(relative)))
		if err != nil {
			return err
		}
		defer func() {
			if llmRecordsFile != nil {
				_ = llmRecordsFile.Close()
			}
		}()
	}
	if s.m.traffic != nil {
		_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "restore_traffic", 35)
		if _, err := s.m.traffic.ImportArchive(filepath.Join(extracted, "traffic")); err != nil {
			return err
		}
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "restore_files", 55)
	files, err := installTaskArchiveFiles(s.m.dir, extracted, strconv.FormatInt(job.TaskID, 10), job.ID)
	if err != nil {
		return err
	}
	databaseRestored := false
	defer func() {
		if !databaseRestored {
			runErr = errors.Join(runErr, files.rollback())
		}
	}()
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "restore_database", 70)
	var warnings []string
	if llmRecordsFile != nil {
		warnings, err = s.m.pg.RestoreTaskArchiveWithLLMRecords(
			job.ID, snapshot, job.RemainingTimeoutSeconds, llmRecordsFile,
		)
		closeErr := llmRecordsFile.Close()
		llmRecordsFile = nil
		err = errors.Join(err, closeErr)
	} else {
		warnings, err = s.m.pg.RestoreTaskArchive(job.ID, snapshot, job.RemainingTimeoutSeconds)
	}
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		log.Printf("[task-archive] restored task %d with warning: %s", job.TaskID, warning)
	}
	if len(warnings) > 0 {
		if _, err := s.m.pg.Exploration(snapshot.ExplorationID).AppendActivity(pgdb.Activity{
			Worker: "system", Kind: "system", Summary: "작업 복원을 완료했지만 일부 연관 항목이 온전히 복원되지 못했습니다", Detail: strings.Join(warnings, "\n"),
		}); err != nil {
			log.Printf("[task-archive] persist restore warnings for task %d: %v", job.TaskID, err)
		}
	}
	databaseRestored = true
	if err := files.commit(); err != nil {
		return err
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "consume_package", 95)
	if err := os.Remove(job.ArchivePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := s.m.pg.CompleteTaskArchiveRestore(job.ID); err != nil {
		return err
	}
	s.loadRestoredTask(job.TaskID)
	return nil
}

func (s *Server) loadRestoredTask(taskID int64) {
	id := strconv.FormatInt(taskID, 10)
	var restored *Task
	for _, task := range s.m.LoadExisting() {
		if task.ID == id {
			restored = task
			break
		}
	}
	if restored == nil {
		if task, ok := s.m.Task(id); ok {
			restored = task
		}
	}
	if restored == nil {
		return
	}
	lifecycle := restored.lifecycleSnapshot()
	if lifecycle.Paused {
		s.engine.Pause(id, agent.AbortPausedOnReload)
	}
	if !isTerminalStatus(lifecycle.Status) {
		s.engine.startDeadlineCoordinator(s.ctx, restored)
	}
}

func (s *Server) deleteTaskArchive(job *pgdb.TaskArchive) error {
	if err := validateArchivePath(s.m.dir, job.ArchivePath); err != nil {
		return err
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "stage_package_delete", 35)
	staged, moved, err := stageTaskArchivePackageDelete(job.ArchivePath, job.ID)
	if err != nil {
		return err
	}
	_ = s.m.pg.UpdateTaskArchiveProgress(job.ID, "delete_metadata", 70)
	if err := s.m.pg.DeleteTaskArchiveStub(job.ID); err != nil {
		if moved {
			_ = os.Rename(staged, job.ArchivePath)
		}
		return err
	}
	if moved {
		if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
			log.Printf("[task-archive] archived task %d metadata deleted; stale package cleanup failed: %v", job.TaskID, err)
		}
	}
	return nil
}

func validateArchivePath(dataDir, candidate string) error {
	if strings.TrimSpace(candidate) == "" {
		return errors.New("보관 패키지 경로가 비어 있습니다")
	}
	root, err := filepath.Abs(taskArchiveRoot(dataDir))
	if err != nil {
		return err
	}
	path, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("보관 패키지 경로가 관리 대상 디렉터리 안에 있지 않습니다")
	}
	return nil
}

func (s *Server) listTaskArchives(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	result, err := s.m.pg.ListTaskArchives(r.URL.Query().Get("q"), r.URL.Query().Get("state"), page, size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) getTaskArchive(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "보관 id 가 유효하지 않습니다")
		return
	}
	item, err := s.m.pg.GetTaskArchive(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if item == nil {
		writeErr(w, 404, "보관을 찾을 수 없습니다")
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) queueTaskArchive(w http.ResponseWriter, r *http.Request) {
	id, ok := canonicalTaskID(r.PathValue("id"))
	if !ok {
		writeErr(w, 400, "작업 id 가 유효하지 않습니다")
		return
	}
	numeric, _ := strconv.ParseInt(id, 10, 64)
	item, err := s.m.pg.QueueTaskArchive(numeric)
	if err != nil {
		writeArchiveError(w, err)
		return
	}
	s.notifyTaskArchiveWorker()
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) queueTaskArchiveRestore(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "보관 id 가 유효하지 않습니다")
		return
	}
	item, err := s.m.pg.QueueTaskArchiveRestore(id)
	if err != nil {
		writeArchiveError(w, err)
		return
	}
	s.notifyTaskArchiveWorker()
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) queueTaskArchiveDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "보관 id 가 유효하지 않습니다")
		return
	}
	item, err := s.m.pg.QueueTaskArchiveDelete(id)
	if err != nil {
		writeArchiveError(w, err)
		return
	}
	s.notifyTaskArchiveWorker()
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) queueTaskArchivesBatch(w http.ResponseWriter, r *http.Request) {
	var request archiveBatchRequest
	if err := decode(r, &request); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	parsed := normalizeBatchTaskIDs(request.TaskIDs)
	if len(parsed) == 0 {
		writeErr(w, 400, "task_ids 값은 비워 둘 수 없습니다")
		return
	}
	if len(parsed) > 100 {
		writeErr(w, 400, "한 번에 최대 100개 작업까지 처리할 수 있습니다")
		return
	}
	ids := make([]string, 0, len(parsed))
	items := make([]archiveBatchItem, 0, len(parsed))
	for _, item := range parsed {
		if !item.valid {
			items = append(items, archiveBatchItem{ID: item.id, Error: "작업 id 가 유효하지 않습니다"})
			continue
		}
		ids = append(ids, item.id)
	}
	ids = s.orderLiveTaskArchiveBatch(ids)
	for _, id := range ids {
		numeric, _ := strconv.ParseInt(id, 10, 64)
		archive, err := s.m.pg.QueueTaskArchive(numeric)
		item := archiveBatchItem{ID: id, OK: err == nil, Queued: err == nil}
		if err != nil {
			item.Error = err.Error()
		} else {
			item.Archive = archive.ID
		}
		items = append(items, item)
	}
	s.notifyTaskArchiveWorker()
	writeJSON(w, http.StatusAccepted, map[string]any{"items": items})
}

func (s *Server) queueTaskArchiveActionBatch(w http.ResponseWriter, r *http.Request, action string) {
	var request archiveBatchRequest
	if err := decode(r, &request); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ids, err := normalizeArchiveIDs(request.ArchiveIDs)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ids = s.orderColdTaskArchiveBatch(ids, action == "restore")
	items := make([]archiveBatchItem, 0, len(ids))
	for _, id := range ids {
		var archive *pgdb.TaskArchive
		if action == "restore" {
			archive, err = s.m.pg.QueueTaskArchiveRestore(id)
		} else {
			archive, err = s.m.pg.QueueTaskArchiveDelete(id)
		}
		item := archiveBatchItem{ID: strconv.FormatInt(id, 10), Archive: id, OK: err == nil, Queued: err == nil}
		if err != nil {
			item.Error = err.Error()
		} else if archive != nil {
			item.Archive = archive.ID
		}
		items = append(items, item)
	}
	s.notifyTaskArchiveWorker()
	writeJSON(w, http.StatusAccepted, map[string]any{"items": items})
}

func (s *Server) restoreTaskArchivesBatch(w http.ResponseWriter, r *http.Request) {
	s.queueTaskArchiveActionBatch(w, r, "restore")
}

func (s *Server) deleteTaskArchivesBatch(w http.ResponseWriter, r *http.Request) {
	s.queueTaskArchiveActionBatch(w, r, "delete")
}

func normalizeArchiveIDs(ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return nil, errors.New("archive_ids 값은 비워 둘 수 없습니다")
	}
	if len(ids) > 100 {
		return nil, errors.New("한 번에 최대 100개 보관까지 처리할 수 있습니다")
	}
	seen := map[int64]bool{}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return nil, fmt.Errorf("보관 id %d 가 유효하지 않습니다", id)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *Server) orderLiveTaskArchiveBatch(ids []string) []string {
	sources := map[string][]string{}
	for _, id := range ids {
		if task, ok := s.m.Task(id); ok {
			for _, sourceID := range task.lifecycleSnapshot().SourceTaskIDs {
				sources[id] = append(sources[id], strconv.FormatInt(sourceID, 10))
			}
		}
	}
	return topoTaskIDs(ids, sources, false)
}

func (s *Server) orderColdTaskArchiveBatch(ids []int64, restore bool) []int64 {
	taskToArchive := map[string]int64{}
	sources := map[string][]string{}
	var taskIDs []string
	for _, id := range ids {
		archive, err := s.m.pg.GetTaskArchive(id)
		if err != nil || archive == nil {
			continue
		}
		taskID := strconv.FormatInt(archive.TaskID, 10)
		taskToArchive[taskID] = id
		taskIDs = append(taskIDs, taskID)
		for _, sourceID := range archive.SourceTaskIDs {
			sources[taskID] = append(sources[taskID], strconv.FormatInt(sourceID, 10))
		}
	}
	orderedTasks := topoTaskIDs(taskIDs, sources, restore)
	ordered := make([]int64, 0, len(ids))
	seen := map[int64]bool{}
	for _, taskID := range orderedTasks {
		id := taskToArchive[taskID]
		ordered = append(ordered, id)
		seen[id] = true
	}
	for _, id := range ids {
		if !seen[id] {
			ordered = append(ordered, id)
		}
	}
	return ordered
}

// topoTaskIDs orders source->dependent for restore and dependent->source for
// archive/delete. Cycles are impossible at creation, but stable fallback keeps a
// damaged database operable.
func topoTaskIDs(ids []string, sources map[string][]string, restore bool) []string {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	adjacency := map[string][]string{}
	indegree := map[string]int{}
	for id := range set {
		indegree[id] = 0
	}
	for dependent, sourceIDs := range sources {
		for _, source := range sourceIDs {
			if !set[dependent] || !set[source] {
				continue
			}
			from, to := dependent, source
			if restore {
				from, to = source, dependent
			}
			adjacency[from] = append(adjacency[from], to)
			indegree[to]++
		}
	}
	queue := []string{}
	for _, id := range ids {
		if indegree[id] == 0 {
			queue = append(queue, id)
		}
	}
	ordered := make([]string, 0, len(ids))
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		ordered = append(ordered, id)
		for _, next := range adjacency[id] {
			indegree[next]--
			if indegree[next] == 0 {
				queue = append(queue, next)
			}
		}
	}
	if len(ordered) != len(ids) {
		seen := map[string]bool{}
		for _, id := range ordered {
			seen[id] = true
		}
		for _, id := range ids {
			if !seen[id] {
				ordered = append(ordered, id)
			}
		}
	}
	return ordered
}

func writeArchiveError(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	if errors.Is(err, pgdb.ErrTaskArchiveNotFound) {
		status = http.StatusNotFound
	} else if !errors.Is(err, pgdb.ErrTaskArchiveIneligible) &&
		!errors.Is(err, pgdb.ErrTaskArchiveQueued) &&
		!errors.Is(err, pgdb.ErrTaskArchiveDependent) &&
		!errors.Is(err, pgdb.ErrTaskArchiveState) &&
		!errors.Is(err, pgdb.ErrTaskArchiveDeleteBlocked) {
		status = http.StatusInternalServerError
	}
	writeErr(w, status, err.Error())
}
