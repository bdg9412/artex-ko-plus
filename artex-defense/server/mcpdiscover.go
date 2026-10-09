package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcphttp"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

// mcpClient is the shared surface of a connected MCP server (stdio, Streamable HTTP,
// or legacy SSE),
// so tools/list and cleanup are handled uniformly regardless of transport.
type mcpClient interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// connectMCP 이 돌려주는 전송 설정 검증 오류 네 가지는 사용자 노출이다 —
// pgRefreshMCP(server_mgmt.go) 가 discoverAndCacheMCP 실패를
// writeErr(502, errMgmtToolDiscoverFail+err.Error()) 로 응답 본문에 그대로 싣는다.
// 다른 호출처(assembly.go 의 에이전트 조립·discoverEmptyMCPsOnStartup 시작 자동 발견·
// sync_scopesentry.go 동기화·pgSaveMCP 추가 직후 발견)는 전부 log.Printf 로만 남기거나
// 버려서 에이전트 두뇌 입력이 아니다. 그래서 한국어화한다. 전송 방식 enum
// (stdio/http/sse)과 URL 은 와이어 식별자라 원문을 유지하고, UI mcpPage(전송 방식·명령·
// 원격 URL)와 표기를 맞춘다.
const (
	errMCPStdioNoCommand      = "stdio 전송 방식에 명령이 없습니다"
	errMCPHTTPNoURL           = "http 전송 방식에 URL 이 없습니다"
	errMCPSSENoURL            = "sse 전송 방식에 URL 이 없습니다"
	errMCPUnknownTransportFmt = "알 수 없는 전송 방식입니다: %q"
)

// connectMCP dials one MCP server per its transport. Callers must Close the client.
func connectMCP(ctx context.Context, m *db.MCPServer) (mcpClient, error) {
	switch m.Transport {
	case "stdio":
		if m.Command == "" {
			return nil, errors.New(errMCPStdioNoCommand)
		}
		return mcp.NewStdioClient(ctx, m.Name, m.Command, jsonStrMap(m.Env), jsonStrSlice(m.Args)...)
	case "http":
		if m.URL == "" {
			return nil, errors.New(errMCPHTTPNoURL)
		}
		// env map doubles as HTTP headers (e.g. Authorization).
		return mcphttp.New(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	case "sse":
		if m.URL == "" {
			return nil, errors.New(errMCPSSENoURL)
		}
		return mcphttp.NewSSE(ctx, m.Name, m.URL, jsonStrMap(m.Env), m.Insecure)
	default:
		return nil, fmt.Errorf(errMCPUnknownTransportFmt, m.Transport)
	}
}

// discoverAndCacheMCP connects to one MCP, lists its tools, and persists the tool
// names to mcp_tools_cache so the UI shows them without a live connection.
func (s *Server) discoverAndCacheMCP(ctx context.Context, m *db.MCPServer) error {
	cl, err := connectMCP(ctx, m)
	if err != nil {
		return err
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		return err
	}
	tools := make([]db.MCPTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, db.MCPTool{Name: t.Name(), Description: t.Description()})
	}
	if err := s.m.pg.SaveMCPTools(m.ID, tools); err != nil {
		return err
	}
	log.Printf("[mcp] %s 에서 도구 %d개를 발견해 캐시했습니다", m.Name, len(tools))
	return nil
}

// discoverEmptyMCPsOnStartup fills the tool cache for any enabled MCP that has none
// yet (notably the seeded browser MCP on first run). Runs sequentially in one
// goroutine so we never spawn many stdio servers (npx) at once, and never blocks
// startup. Best-effort: a failure leaves the cache empty to retry next start.
func (s *Server) discoverEmptyMCPsOnStartup() {
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		log.Printf("[mcp] 시작 시 자동 발견: 목록을 읽지 못했습니다: %v", err)
		return
	}
	for _, m := range servers {
		if !m.Enabled || len(m.Tools) > 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
		if err := s.discoverAndCacheMCP(ctx, m); err != nil {
			log.Printf("[mcp] 시작 시 %s 자동 발견에 실패했습니다: %v", m.Name, err)
		}
		cancel()
	}
}
