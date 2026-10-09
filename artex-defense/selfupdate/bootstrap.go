package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// smokeEnv 让被冒烟测试拉起的子进程直接跳过 Bootstrap。
//
// 严格来说不加也不会出事：子进程的 os.Executable() 是 artex.new，推导出来的
// 全部路径都带 .new 前缀，碰不到真正的升级文件。但依赖这种巧合太脆弱，
// 显式短路一目了然，也省掉子进程一次无谓的磁盘探测。
const smokeEnv = "ARTEX_SELFUPDATE_SMOKE"

// Action 是 Bootstrap 给 main 的指令。
type Action int

const (
	// Continue：照常启动 server。
	Continue Action = iota
	// Restart：立刻以 ExitRestart 退出，让守护脚本重新拉起。
	Restart
)

// State 描述本次启动时的升级状态，供 /api/update/check 如实告诉前端
// "上一次升级是成功了还是被回滚了"。
type State struct {
	Pending     bool   // 换装后尚未确认稳定
	RolledBack  bool   // 本次启动刚刚执行过自动回滚
	FailedStage bool   // 暂存件校验/冒烟未通过，已丢弃
	Detail      string // 面向用户的一句话说明
}

// Bootstrap 在 main 的最开头运行，必须在任何监听端口、打开数据库之前调用。
//
// 三种局面：
//
//	① 存在暂存件 artex.new  → 校验 + 冒烟，通过则换装并要求重启；不通过则丢弃继续跑旧版
//	② 只剩标记文件          → 说明刚换装完，累计一次尝试；连续失败够多次则回滚
//	③ 什么都没有            → 正常启动
func Bootstrap() (Action, State) {
	if os.Getenv(smokeEnv) != "" {
		return Continue, State{}
	}
	p, err := ResolvePaths()
	if err != nil {
		log.Printf("[update] 跳过自举：%v", err)
		return Continue, State{}
	}

	if _, err := os.Stat(p.New); err == nil {
		return applyStaged(p)
	}

	m, ok := readMarker(p.Marker)
	if !ok {
		return Continue, State{}
	}
	return confirmOrRollback(p, m)
}

// applyStaged 处理"存在暂存件"的局面：校验通过就换装，失败就丢弃。
//
// 这里是整个升级链路唯一会覆盖可执行文件的地方，也是最后一道闸门——冒烟测试挡掉
// 下载损坏、架构选错、动态链接缺失这类问题。一旦放行一个跑不起来的二进制，
// 守护脚本会不知疲倦地反复拉起它，而 Go 代码根本没机会运行，自动回滚也就无从谈起。
func applyStaged(p Paths) (Action, State) {
	m, _ := readMarker(p.Marker)

	if err := verifyStaged(p); err != nil {
		log.Printf("[update] 暂存的新版本未通过校验，已丢弃，继续运行当前版本：%v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "새 버전 검증에 실패해 폐기했습니다: " + err.Error()}
	}

	if err := swap(p); err != nil {
		log.Printf("[update] 换装失败，继续运行当前版本：%v", err)
		cleanStaged(p)
		_ = os.Remove(p.Marker)
		return Continue, State{FailedStage: true, Detail: "버전 교체에 실패했습니다: " + err.Error()}
	}

	// 换装成功。保留标记，交给下一次启动（跑的就是新版）确认是否稳定。
	m.Attempts = 0
	if m.StagedAt == 0 {
		m.StagedAt = time.Now().Unix()
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] 写升级标记失败（失去自动回滚能力）：%v", err)
	}
	log.Printf("[update] 已换装到 %s，退出以重启（exit %d）", orUnknown(m.To), ExitRestart)
	return Restart, State{Pending: true}
}

// confirmOrRollback 处理"换装后的启动"：累计尝试次数，超限则把旧版换回来。
//
// 计数只在 Go 代码跑起来后才递增，所以它覆盖的是"能执行但初始化时崩溃"
// （配置不兼容、端口被占、DB 迁移炸了）这类故障；"根本无法 exec" 由换装前的
// 冒烟测试挡住，两者合起来才是完整的。
func confirmOrRollback(p Paths, m marker) (Action, State) {
	m.Attempts++
	if m.Attempts > maxAttempts {
		if err := rollback(p); err != nil {
			// 回滚都失败了就别再重启了，否则会陷入无限重启。清掉标记，
			// 让进程按当前状态起——起不来的话用户至少能在日志里看到原因。
			log.Printf("[update] 新版本连续 %d 次启动失败，且回滚失败：%v", maxAttempts, err)
			_ = os.Remove(p.Marker)
			return Continue, State{Detail: "새 버전 시작에 실패하고 롤백도 실패했습니다: " + err.Error()}
		}
		log.Printf("[update] 新版本连续 %d 次启动失败，已回滚到 %s，退出以重启（exit %d）",
			maxAttempts, orUnknown(m.From), ExitRestart)
		_ = os.Remove(p.Marker)
		return Restart, State{RolledBack: true, Detail: fmt.Sprintf("새 버전 시작에 실패해 이전 버전으로 롤백했습니다(%s)", orUnknown(m.From))}
	}
	if err := writeMarker(p.Marker, m); err != nil {
		log.Printf("[update] 更新升级标记失败：%v", err)
	}
	log.Printf("[update] 新版本启动中（第 %d/%d 次尝试），稳定运行后将确认升级",
		m.Attempts, maxAttempts)
	return Continue, State{Pending: true}
}

// Settle 确认新版本已稳定运行，清除升级标记。
//
// 由 main 在 HTTP 监听起来之后延迟调用：活过这段时间才算数，否则标记留在原地，
// 下次启动继续累计尝试次数，直到触发回滚。
func Settle() {
	p, err := ResolvePaths()
	if err != nil {
		return
	}
	settle(p)
}

func settle(p Paths) {
	if _, ok := readMarker(p.Marker); !ok {
		return // 不是升级后的启动，无事可做
	}
	if err := os.Remove(p.Marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("[update] 清除升级标记失败：%v", err)
		return
	}
	log.Printf("[update] 新版本运行稳定，升级完成（上一版本保留为 %s）", p.Old)
}

// SettleDelay 是判定"新版本活下来了"所需的运行时长。
const SettleDelay = 30 * time.Second

// verifyStaged 校验暂存件：先比对 SHA256，再真正把它拉起来跑一次。
func verifyStaged(p Paths) error {
	want, err := os.ReadFile(p.Sum)
	if err != nil {
		return fmt.Errorf("체크섬 읽기 실패: %w", err)
	}
	got, err := fileSHA256(p.New)
	if err != nil {
		return fmt.Errorf("체크섬 계산 실패: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(want)), got) {
		return errors.New("SHA256 이 일치하지 않습니다(다운로드가 손상됐거나 변조됨)")
	}
	return smokeTest(p.New)
}

// smokeTest 用 -h 拉起新二进制，确认它在当前系统上真的能执行。
// 这能挡掉下载截断、架构选错（exec format error）、缺依赖等一大类问题。
func smokeTest(bin string) error {
	if err := os.Chmod(bin, 0o755); err != nil {
		return fmt.Errorf("실행 권한 부여 실패: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-h")
	cmd.Env = append(os.Environ(), smokeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return errors.New("스모크 테스트 시간 초과(새 바이너리가 응답하지 않음)")
	}
	if err != nil {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "…"
		}
		return fmt.Errorf("스모크 테스트 실패: %v: %s", err, snippet)
	}
	return nil
}

// swap 把当前二进制换成暂存的新版本。
//
// Unix 和 Windows 都允许 rename 一个正在运行的可执行文件（Windows 禁止的是删除和
// 覆盖，rename 不在其列），所以这里不需要分平台，也不需要先停掉自己。
func swap(p Paths) error {
	// Windows 的 rename 不会覆盖已存在的目标，上一轮升级留下的 .old 必须先清掉。
	if err := os.Remove(p.Old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("이전 백업 %s 정리 실패: %w", p.Old, err)
	}
	if err := os.Rename(p.Current, p.Old); err != nil {
		return fmt.Errorf("현재 버전 백업 실패: %w", err)
	}
	if err := os.Rename(p.New, p.Current); err != nil {
		// 换装失败但当前版本已经被挪走了，必须原样放回去，否则下次启动没有可执行文件。
		if rerr := os.Rename(p.Old, p.Current); rerr != nil {
			return fmt.Errorf("새 버전 설치 실패(%v), 현재 버전 복구도 실패: %w", err, rerr)
		}
		return fmt.Errorf("새 버전 설치 실패: %w", err)
	}
	_ = os.Remove(p.Sum)
	return nil
}

// rollback 把 swap 备份的旧版本换回来。
func rollback(p Paths) error {
	if _, err := os.Stat(p.Old); err != nil {
		return fmt.Errorf("롤백할 백업이 없습니다(%s): %w", p.Old, err)
	}
	// 把起不来的新版挪到 .failed 留作排查，而不是直接删掉。
	failed := p.Current + ".failed"
	_ = os.Remove(failed)
	if err := os.Rename(p.Current, failed); err != nil {
		return fmt.Errorf("실패한 버전 이동 실패: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		return fmt.Errorf("이전 버전 복구 실패: %w", err)
	}
	return nil
}

// Rollback 是 /api/update/rollback 的实现：主动退回上一版本。
// 只做换装，重启同样交给守护脚本（调用方随后以 ExitRestart 退出）。
func Rollback() error {
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p.Old); err != nil {
		return errors.New("롤백할 이전 버전이 없습니다(" + p.Old + " 없음)")
	}
	cleanStaged(p)
	if err := smokeTest(p.Old); err != nil {
		return fmt.Errorf("이전 버전을 실행할 수 없어 롤백을 거부합니다: %w", err)
	}
	// 交换当前与备份：回滚之后还能再滚回来。
	tmp := p.Current + ".swap"
	_ = os.Remove(tmp)
	if err := os.Rename(p.Current, tmp); err != nil {
		return fmt.Errorf("현재 버전 이동 실패: %w", err)
	}
	if err := os.Rename(p.Old, p.Current); err != nil {
		_ = os.Rename(tmp, p.Current)
		return fmt.Errorf("이전 버전 설치 실패: %w", err)
	}
	if err := os.Rename(tmp, p.Old); err != nil {
		log.Printf("[update] 回滚后整理备份失败（不影响运行）：%v", err)
	}
	_ = os.Remove(p.Marker)
	return nil
}

// HasBackup 报告是否存在可回滚的上一版本，供前端决定要不要显示回滚按钮。
func HasBackup() bool {
	p, err := ResolvePaths()
	if err != nil {
		return false
	}
	_, err = os.Stat(p.Old)
	return err == nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "알 수 없는 버전"
	}
	return s
}
