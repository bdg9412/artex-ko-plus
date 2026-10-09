package server

import (
	"os"
	"path/filepath"
	"testing"
)

// task_archive_package.go 의 보관 패키지 삭제 준비 오류 문구를 한국어로 유지하는 회귀 방어
// 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를 재사용한다.
// 누군가 이 리터럴을 중국어로 되돌리면 이 테스트가 실패한다.
//
// 호출 그래프 판정(errArchiveStagedAndOriginalCoexist 상수 주석 참조): 이 오류는 백그라운드
// 아카이브 워커 runOneTaskArchiveJob(task_archives.go:102)이 FailTaskArchiveJob 으로
// task_archives.error 컬럼에 저장하고, tasks/page.tsx 의 TaskArchivesPanel 이 {archive.error}
// 로 화면에 직접 표시하는 사용자 노출 전용이다(actool·planner 되먹임 0). 같은 전파 경로의
// 형제 오류(archiveTask·validateArchivePath)도 이미 한국어라 이 번역은 그와 정합한다.
//
// stageTaskArchivePackageDelete 는 DB 에 닿지 않는 순수 파일 함수라, DB 없는 이 호스트에서
// 원본 파일과 삭제 임시 파일(.deleting-N)을 동시에 만들어 실제 모순 분기를 구동할 수 있다.
func TestTaskArchiveStagedAndOriginalCoexistErrorLocalized(t *testing.T) {
	dataDir := t.TempDir()
	archivePath := taskArchivePath(dataDir, 21, "42")
	if err := os.MkdirAll(filepath.Dir(archivePath), archiveDirMode); err != nil {
		t.Fatal(err)
	}
	// 원본 보관 패키지와 삭제 임시 파일이 모두 존재하는 모순 상태를 만든다.
	if err := os.WriteFile(archivePath, []byte("original"), archiveFileMode); err != nil {
		t.Fatal(err)
	}
	staged := archivePath + ".deleting-21"
	if err := os.WriteFile(staged, []byte("archive"), archiveFileMode); err != nil {
		t.Fatal(err)
	}
	_, moved, err := stageTaskArchivePackageDelete(archivePath, 21)
	if err == nil {
		t.Fatalf("원본과 삭제 임시 파일이 공존하면 오류가 반환되어야 합니다 (moved=%v)", moved)
	}
	if moved {
		t.Fatal("공존 모순 상태에서는 moved 가 true 가 되어서는 안 됩니다")
	}
	assertKoreanError(t, "staged_and_original_coexist", err.Error())
}
