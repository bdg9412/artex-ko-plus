package selfupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

// sumsAsset 是 release.yml 生成的校验和清单，覆盖 Release 里全部 zip。
const sumsAsset = "SHA256SUMS"

// maxBinarySize 限制解压出来的二进制体积，防止畸形 zip 把磁盘写满。
const maxBinarySize = 512 << 20 // 512 MiB

// Phase 是升级过程中的阶段，直接用作 SSE 事件里的 phase 字段。
type Phase string

const (
	PhaseIdle     Phase = "idle"
	PhaseDownload Phase = "downloading"
	PhaseVerify   Phase = "verifying"
	PhaseExtract  Phase = "extracting"
	PhaseStaged   Phase = "staged"
	PhaseFailed   Phase = "failed"
)

// Progress 由调用方提供，用来把进度推给前端。pct 仅在下载阶段有意义（0-100），
// 其余阶段传 -1。
type Progress func(ph Phase, pct int, msg string)

// Stage 下载指定 Release 的当前平台发布包，校验后把新二进制暂存为 artex.new。
//
// 走的是完整 zip 而不是裸二进制，理由有两个：现有 Release 的 SHA256SUMS 本来就
// 只覆盖 zip，走 zip 不需要改 CI，也能兼容已经发布出去的历史版本；zip 里还带着
// skills/，为将来同步内置 skill 留了口子。代价只是多下载 skills 那几百 KB。
//
// 函数返回即代表暂存完成，调用方随后优雅关闭并以 ExitRestart 退出。
func Stage(ctx context.Context, c *http.Client, rel *Release, currentVersion string, prog Progress) error {
	if prog == nil {
		prog = func(Phase, int, string) {}
	}
	p, err := ResolvePaths()
	if err != nil {
		return err
	}
	if err := checkWritable(p.Dir); err != nil {
		return err
	}

	name := AssetName(rel.TagName, runtime.GOOS, runtime.GOARCH)
	asset, ok := rel.FindAsset(name)
	if !ok {
		return fmt.Errorf("이 버전은 %s/%s 용 릴리스 패키지를 제공하지 않습니다(%s 누락)", runtime.GOOS, runtime.GOARCH, name)
	}

	prog(PhaseDownload, 0, "체크섬 목록을 가져오는 중…")
	sums, err := fetchSums(ctx, c, rel)
	if err != nil {
		return err
	}
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("%s 에 %s 항목이 없어 검증되지 않은 바이너리 설치를 거부합니다", sumsAsset, name)
	}

	// 临时文件全部落在目标目录里，保证最后的 rename 是同一文件系统内的原子操作
	// （跨设备 rename 会失败，而 /tmp 常常是独立挂载点）。
	zipPath := p.New + ".zip.part"
	binPath := p.New + ".part"
	defer func() {
		_ = os.Remove(zipPath)
		_ = os.Remove(binPath)
	}()

	prog(PhaseDownload, 0, fmt.Sprintf("%s 내려받는 중(%s)…", name, humanSize(asset.Size)))
	got, err := download(ctx, c, asset, zipPath, prog)
	if err != nil {
		return err
	}

	prog(PhaseVerify, -1, "SHA256 검증 중…")
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("SHA256 이 일치하지 않습니다: 기대값 %s, 실제값 %s(다운로드가 손상됐거나 변조됨)", short(want), short(got))
	}

	prog(PhaseExtract, -1, "압축을 풀고 스모크 테스트 중…")
	if err := extractBinary(zipPath, binPath); err != nil {
		return err
	}
	if err := smokeTest(binPath); err != nil {
		return fmt.Errorf("새 버전이 현재 시스템에서 실행되지 않습니다: %w", err)
	}

	// 暂存件自己的 sha256 单独存一份：下次启动换装前还要再校验一次，
	// 防止暂存后到重启前这段时间里文件被改动或写坏。
	binSum, err := fileSHA256(binPath)
	if err != nil {
		return fmt.Errorf("새 바이너리 체크섬 계산 실패: %w", err)
	}
	if err := os.WriteFile(p.Sum, []byte(binSum), 0o644); err != nil {
		return fmt.Errorf("체크섬 기록 실패: %w", err)
	}
	if err := os.Rename(binPath, p.New); err != nil {
		_ = os.Remove(p.Sum)
		return fmt.Errorf("새 버전 준비 실패: %w", err)
	}

	if err := writeMarker(p.Marker, marker{
		From:     currentVersion,
		To:       strings.TrimPrefix(rel.TagName, "v"),
		StagedAt: time.Now().Unix(),
	}); err != nil {
		// 标记只影响自动回滚能力，暂存件本身已就位，不因此中断升级。
		prog(PhaseStaged, -1, "경고: 업데이트 표시 파일 기록에 실패해 이번 업데이트는 자동 롤백 보호를 받지 못합니다")
	}

	prog(PhaseStaged, 100, "새 버전이 준비되었습니다. 재시작 중…")
	return nil
}

// fetchSums 下载并解析 SHA256SUMS，返回 文件名 → 十六进制摘要。
func fetchSums(ctx context.Context, c *http.Client, rel *Release) (map[string]string, error) {
	asset, ok := rel.FindAsset(sumsAsset)
	if !ok {
		return nil, fmt.Errorf("이 릴리스에 %s 항목이 없어 무결성을 검증할 수 없으므로 업데이트를 거부합니다", sumsAsset)
	}
	body, err := get(ctx, c, asset.URL)
	if err != nil {
		return nil, fmt.Errorf("%s 내려받기 실패: %w", sumsAsset, err)
	}
	defer body.Close()

	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%s 읽기 실패: %w", sumsAsset, err)
	}
	out := parseSums(string(raw))
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 내용이 비어 있거나 형식을 인식할 수 없습니다", sumsAsset)
	}
	return out, nil
}

// parseSums 解析 sha256sum 风格的清单，返回 文件名 → 十六进制摘要。
//
// 第一个字段必须是 64 位十六进制才收录。只按"恰好两个字段"判断是不够的——
// 任意一行两个单词的说明文字都会被当成合法条目，把垃圾值塞进摘要表，
// 真正的资产反而可能匹配到错误的摘要。
func parseSums(raw string) map[string]string {
	out := map[string]string{}
	for line := range strings.Lines(raw) {
		// 格式为 "<sha256>  <filename>"（sha256sum 用双空格；shasum 的二进制
		// 模式会给文件名加 * 前缀）。
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || !isHexSHA256(fields[0]) {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == "" {
			continue
		}
		out[name] = strings.ToLower(fields[0])
	}
	return out
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// download 把资产写入 dst，同时计算 SHA256 并按 Content-Length 汇报进度。
func download(ctx context.Context, c *http.Client, a Asset, dst string, prog Progress) (string, error) {
	body, err := get(ctx, c, a.URL)
	if err != nil {
		return "", fmt.Errorf("%s 내려받기 실패: %w", a.Name, err)
	}
	defer body.Close()

	f, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("임시 파일 생성 실패: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	pw := &progressWriter{total: a.Size, prog: prog, name: a.Name, last: time.Now()}
	if _, err := io.Copy(io.MultiWriter(f, h, pw), body); err != nil {
		return "", fmt.Errorf("다운로드가 중단되었습니다: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("디스크 기록 실패: %w", err)
	}
	if a.Size > 0 && pw.written != a.Size {
		return "", fmt.Errorf("다운로드가 완전하지 않습니다: 기대 %d바이트, 실제 %d바이트", a.Size, pw.written)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// get 发起一个受白名单约束的 GET，返回响应体。
func get(ctx context.Context, c *http.Client, rawURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "artex-selfupdate")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// extractBinary 从发布包里取出 artex 可执行文件。
//
// 包内结构是 artex-<版本>-<os>-<arch>/artex，但这里按**基名**匹配而不是拼完整
// 路径：版本号在包名里出现过一次，拼错一个字符就整个升级失败，按基名找更耐改。
func extractBinary(zipPath, dst string) error {
	want := "artex"
	if runtime.GOOS == "windows" {
		want = "artex.exe"
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("릴리스 패키지 열기 실패: %w", err)
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || !strings.EqualFold(path.Base(entry.Name), want) {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return fmt.Errorf("%s 읽기 실패: %w", entry.Name, err)
		}
		defer rc.Close()

		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return fmt.Errorf("새 바이너리 쓰기 실패: %w", err)
		}
		defer f.Close()

		n, err := io.Copy(f, io.LimitReader(rc, maxBinarySize+1))
		if err != nil {
			return fmt.Errorf("%s 압축 해제 실패: %w", entry.Name, err)
		}
		if n > maxBinarySize {
			return fmt.Errorf("릴리스 패키지 안의 실행 파일이 %s 보다 커서 압축 해제를 거부합니다", humanSize(maxBinarySize))
		}
		if n == 0 {
			return fmt.Errorf("릴리스 패키지 안의 %s 파일이 비어 있습니다", want)
		}
		return f.Sync()
	}
	return fmt.Errorf("릴리스 패키지에서 %s 파일을 찾지 못했습니다", want)
}

// checkWritable 提前确认目录可写。没有这一步，非 root 运行、或二进制被放在系统
// 目录时，会在下载完几十 MB 之后才在换装那一刻失败。
func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".artex-update-probe-*")
	if err != nil {
		return fmt.Errorf("프로그램 디렉터리 %s 에 쓸 수 없어 자동 업데이트를 할 수 없습니다(권한을 확인하거나 수동 업데이트를 사용하세요): %w", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// progressWriter 统计已写字节并限频汇报，避免每个 32KiB 分块都推一条 SSE。
type progressWriter struct {
	total   int64
	written int64
	name    string
	prog    Progress
	last    time.Time
}

func (w *progressWriter) Write(b []byte) (int, error) {
	w.written += int64(len(b))
	if time.Since(w.last) < 300*time.Millisecond {
		return len(b), nil
	}
	w.last = time.Now()
	pct := -1
	if w.total > 0 {
		pct = int(w.written * 100 / w.total)
	}
	w.prog(PhaseDownload, pct, fmt.Sprintf("내려받는 중 %s / %s", humanSize(w.written), humanSize(w.total)))
	return len(b), nil
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12] + "…"
	}
	return sum
}
