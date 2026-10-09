package server

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// Go 의 archive/zip 은 Store(0) 와 Deflate(8) 두 가지 해제기만 내장하고 있어서, 다른
// 방식을 만나면 "zip: unsupported compression algorithm" 을 반환한다. 압축 프로그램은
// 기본이 아닌 설정에서 다른 방식을 자주 쓰므로(7-Zip 의 bzip2, WinZip 의 zstd), 여기서
// 순수 Go 로 풀 수 있는 두 가지를 보충한다. 정말로 풀 수 없는 경우(Deflate64 / LZMA /
// XZ / PPMd / 암호화 파일)는 압축을 풀기 전에 한국어 안내를 내보내고, 하부 오류를 그대로
// 사용자에게 넘기지 않는다.
const (
	zipMethodStore     = 0
	zipMethodDeflate   = 8
	zipMethodDeflate64 = 9
	zipMethodBzip2     = 12
	zipMethodLZMA      = 14
	zipMethodZstdPKW   = 20 // PKWARE 가 초기에 zstd 에 할당한 번호
	zipMethodZstd      = 93
	zipMethodXZ        = 95
	zipMethodJPEG      = 96
	zipMethodWavPack   = 97
	zipMethodPPMd      = 98
	zipMethodAES       = 99
)

var zipMethodNames = map[uint16]string{
	zipMethodStore:     "Store",
	zipMethodDeflate:   "Deflate",
	zipMethodDeflate64: "Deflate64",
	zipMethodBzip2:     "bzip2",
	zipMethodLZMA:      "LZMA",
	zipMethodZstdPKW:   "Zstandard",
	zipMethodZstd:      "Zstandard",
	zipMethodXZ:        "XZ",
	zipMethodJPEG:      "JPEG",
	zipMethodWavPack:   "WavPack",
	zipMethodPPMd:      "PPMd",
	zipMethodAES:       "AES 암호화",
}

// 사용자에게 노출되는 스킬 업로드 오류 응답 문구. fsUploadSkill 이
// writeErr(400, err.Error()) 로 그대로 내보낸다(server_mgmt.go).
const (
	errSkillZipParse       = "압축 파일을 해석하지 못했습니다(zip 형식이어야 합니다): %w"
	errSkillZipEncrypted   = "압축 파일이 암호화되어 있습니다(%s). 암호화하지 않은 zip 파일을 업로드하세요."
	errSkillZipUnsupported = "지원하지 않는 압축 방식입니다: %s(method %d), 파일 %s. " +
		"「저장(Store)」 또는 「Deflate」 방식으로 다시 압축해 주세요" +
		"(7-Zip·WinRAR 에서는 압축 방식을 Deflate 로 선택하거나, 운영 체제 기본 압축 기능 또는 명령행 zip -r 를 사용하세요)."
)

func zipMethodName(m uint16) string {
	if n, ok := zipMethodNames[m]; ok {
		return n
	}
	return "알 수 없음"
}

// newSkillZipReader parses an uploaded archive and registers the extra decompressors
// we can support beyond the stdlib's Store/Deflate.
func newSkillZipReader(buf []byte) (*zip.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, fmt.Errorf(errSkillZipParse, err)
	}
	zr.RegisterDecompressor(zipMethodBzip2, func(r io.Reader) io.ReadCloser {
		return io.NopCloser(bzip2.NewReader(r))
	})
	zdec := zstd.ZipDecompressor(zstd.WithDecoderConcurrency(1))
	zr.RegisterDecompressor(zipMethodZstd, zdec)
	zr.RegisterDecompressor(zipMethodZstdPKW, zdec)
	return zr, nil
}

// skillZipEntry pairs a zip entry with its decoded (UTF-8) name — f.Name may hold
// raw GBK bytes, see zipEntryName.
type skillZipEntry struct {
	f    *zip.File
	name string
}

// skillZipEntries lists the archive's real files (no directory entries, no archiver
// junk) with their names decoded to UTF-8.
func skillZipEntries(zr *zip.Reader) []skillZipEntry {
	out := make([]skillZipEntry, 0, len(zr.File))
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := zipEntryName(f)
		if strings.HasPrefix(name, "__MACOSX/") || strings.Contains(name, "/__MACOSX/") ||
			path.Base(name) == ".DS_Store" {
			continue // macOS 가 압축할 때 남긴 잔여 항목
		}
		out = append(out, skillZipEntry{f: f, name: name})
	}
	return out
}

// zipEntryName returns the entry path as UTF-8. Windows 의 7-Zip / WinRAR / 파일 탐색기는
// UTF-8 플래그 비트를 세우지 않으면 한글·중국어 파일명을 GBK 로 zip 에 기록하고, Go 는 그
// 바이트를 그대로 보존한다. 그러면 이름이 올바른 UTF-8 도 아니고 경로 검증도 통과하지
// 못하므로, 여기서 GBK 로 대체 디코딩한다.
func zipEntryName(f *zip.File) string {
	if utf8.ValidString(f.Name) {
		return f.Name
	}
	if dec, err := simplifiedchinese.GBK.NewDecoder().String(f.Name); err == nil && utf8.ValidString(dec) {
		return dec
	}
	return f.Name
}

// checkSkillZipMethods rejects archives we cannot extract, naming the offending
// entry and method instead of letting f.Open() fail with an opaque English error.
func checkSkillZipMethods(entries []skillZipEntry) error {
	for _, e := range entries {
		if e.f.Flags&0x1 != 0 || e.f.Method == zipMethodAES {
			return fmt.Errorf(errSkillZipEncrypted, e.name)
		}
		switch e.f.Method {
		case zipMethodStore, zipMethodDeflate, zipMethodBzip2, zipMethodZstd, zipMethodZstdPKW:
		default:
			return fmt.Errorf(errSkillZipUnsupported,
				zipMethodName(e.f.Method), e.f.Method, e.name)
		}
	}
	return nil
}
