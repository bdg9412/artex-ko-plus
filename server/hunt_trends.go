package server

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/hunting"
)

const huntTrendInterval = 15 * time.Minute

func (s *Server) listHuntTrends(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	reports, state, err := pg.ListHuntTrends(r.Context())
	if err != nil {
		writeErr(w, 500, "위협 동향 리포트를 읽지 못했습니다")
		return
	}
	assets, truncated, matchErr := pg.HuntTrendAssets(r.Context())
	inventory := map[string]any{"scanned_assets": len(assets), "truncated": truncated, "available": matchErr == nil}
	if matchErr == nil {
		reports = hunting.MatchTrendAssets(reports, assets)
	} else {
		log.Printf("[hunting] trend inventory matching: %v", matchErr)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"reports": reports, "collection": state, "inventory": inventory})
}

func (s *Server) collectHuntTrends(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	acquired, err := pg.AcquireHuntTrendCollection(r.Context())
	if err != nil {
		writeErr(w, 500, "위협 동향 수집을 시작하지 못했습니다")
		return
	}
	if !acquired {
		writeErr(w, 409, "위협 동향 수집 중이거나 최근 5분 안에 수집했습니다")
		return
	}
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	go s.runHuntTrendCollection(parent)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 202, map[string]any{"started": true})
}

func (s *Server) runHuntTrendCollection(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 65*time.Second)
	defer cancel()
	collector := hunting.TrendCollector{}
	if s.huntTrendCollector != nil {
		collector = *s.huntTrendCollector
	}
	reports, warnings := collector.Collect(ctx)
	message := strings.Join(warnings, "; ")
	if ctx.Err() != nil && len(reports) == 0 {
		message = "동향 수집 시간 한도 도달 또는 서비스 종료"
	}
	persistCtx, persistCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer persistCancel()
	if err := s.m.pg.FinishHuntTrendCollection(persistCtx, reports, message); err != nil {
		log.Printf("[hunting] trend report persistence: %v", err)
	} else {
		log.Printf("[hunting] trend reports collected: %d, source warnings: %d", len(reports), len(warnings))
	}
}

func (s *Server) scheduleHuntTrends(ctx context.Context) {
	// Startup delay prevents external feed traffic from holding up startup and
	// keeps short-lived server tests free of background network work.
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(huntTrendInterval)
	defer ticker.Stop()
	for {
		if acquired, err := s.m.pg.AcquireHuntTrendCollection(ctx); err != nil {
			log.Printf("[hunting] trend collection lease: %v", err)
		} else if acquired {
			s.runHuntTrendCollection(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
