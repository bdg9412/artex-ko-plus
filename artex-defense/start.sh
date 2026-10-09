#!/bin/sh
# ARTEX 데몬 시작 스크립트(Linux / macOS / Docker ENTRYPOINT)
#
# 사용법:
#   ./start.sh                       포그라운드 실행(Ctrl-C 로 중지)
#   nohup ./start.sh >artex.log 2>&1 &   백그라운드 상주
#   ./start.sh -addr :9000           추가 인자는 artex 로 그대로 전달
#
# 이 스크립트는 한 가지만 합니다. artex 를 실행하고, 프로세스가 종료되면 종료 코드를 보고 다시 띄울지 결정합니다.
#
#   0      사용자가 정상 중지     → 루프 종료
#   75     프로그램이 재시작 요청  → 즉시 다시 실행(화면에서 "원클릭 업데이트" 또는 "롤백"을 누름)
#   그 외  비정상 종료          → 백오프 후 다시 실행(1→2→4…최대 60초)
#
# 다운로드·SHA256 체크섬 검증·버전 교체는 일부러 여기서 하지 않습니다. 그 로직은 sh 와 bat 에 두 벌을 써야 하고,
# 하필 가장 틀리면 안 되는 부분입니다. 실행되지 않는 바이너리로 한번 교체되면 이 스크립트는 그것을 충실히
# 반복해서 띄우고, 사용자는 기계에 직접 들어가 수동으로 복구하는 수밖에 없습니다. 그래서 검증·교체는 전부 Go(selfupdate 패키지)에 두어
# artex 가 기동할 때 스스로 처리하게 하고, 스크립트는 단순하게 유지합니다.
set -u

cd "$(dirname "$0")" || exit 1

BIN=./artex
[ -x "$BIN" ] || { echo "[artex] 실행 파일을 찾을 수 없습니다: $BIN" >&2; exit 1; }

RESTART_CODE=75
MAX_DELAY=60

child=0
stopping=0

# artex 본체로 중지 신호를 전달합니다.
#
# Docker 에서는 이것이 필수입니다. docker stop 은 SIGTERM 을 PID 1(즉 이 스크립트)에만 보내고
# 자식 프로세스에는 보내지 않습니다. 전달하지 않으면 artex 가 신호를 받지 못해 우아한 종료를 못 하고,
# 10초 뒤 SIGKILL 로 강제 종료되어 실행 중이던 작업이 도중에 끊깁니다.
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# 신호는 wait 를 중단시켜 128 보다 큰 값을 반환하게 합니다. 이때 자식 프로세스는 아직 우아한 종료를 진행 중이므로,
	# 한 번 더 wait 해야 진짜 종료 코드를 얻을 수 있습니다.
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[artex] 중지되었습니다"
		exit 0
	fi

	case "$code" in
		0)
			echo "[artex] 정상 종료"
			exit 0
			;;
		"$RESTART_CODE")
			# 업데이트/롤백이 준비되었습니다. 다시 실행하면 artex 가 기동 시 버전 교체를 완료합니다(selfupdate.Bootstrap 참조).
			echo "[artex] 재시작 요청(새 버전 적용)…"
			delay=1
			;;
		*)
			echo "[artex] 비정상 종료 (code=$code), ${delay}s 후 재시작" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done
