package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/hunting"
)

type HuntTrendCollection struct {
	LastAttempt *time.Time `json:"last_attempt"`
	LastSuccess *time.Time `json:"last_success"`
	LastError   string     `json:"last_error"`
	Busy        bool       `json:"busy"`
}

func (d *DB) ListHuntTrends(ctx context.Context) ([]hunting.TrendReport, HuntTrendCollection, error) {
	rows, err := d.QueryContext(ctx, `SELECT report FROM defensive_hunt_trends WHERE published_at >= clock_timestamp()-interval '14 days' ORDER BY CASE report->>'priority' WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,published_at DESC LIMIT 100`)
	if err != nil {
		return nil, HuntTrendCollection{}, err
	}
	defer rows.Close()
	reports := []hunting.TrendReport{}
	for rows.Next() {
		var raw []byte
		var report hunting.TrendReport
		if err := rows.Scan(&raw); err != nil {
			return nil, HuntTrendCollection{}, err
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			return nil, HuntTrendCollection{}, err
		}
		reports = append(reports, report)
	}
	if err := rows.Err(); err != nil {
		return nil, HuntTrendCollection{}, err
	}
	var state HuntTrendCollection
	var attempt, success sql.NullTime
	var busy bool
	err = d.QueryRowContext(ctx, `SELECT last_attempt,last_success,last_error,lease_until>clock_timestamp() FROM defensive_hunt_trend_collection WHERE singleton=true`).Scan(&attempt, &success, &state.LastError, &busy)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, HuntTrendCollection{}, err
	}
	if attempt.Valid {
		state.LastAttempt = &attempt.Time
	}
	if success.Valid {
		state.LastSuccess = &success.Time
	}
	state.Busy = busy
	return reports, state, nil
}

// The database lease serializes the scheduled and manual collectors across
// processes. A crashed collector releases itself after the bounded run timeout.
func (d *DB) AcquireHuntTrendCollection(ctx context.Context) (bool, error) {
	_, err := d.ExecContext(ctx, `INSERT INTO defensive_hunt_trend_collection(singleton) VALUES(true) ON CONFLICT DO NOTHING`)
	if err != nil {
		return false, err
	}
	r, err := d.ExecContext(ctx, `UPDATE defensive_hunt_trend_collection SET lease_until=clock_timestamp()+interval '90 seconds',last_attempt=clock_timestamp(),last_error='' WHERE singleton=true AND lease_until<clock_timestamp() AND (last_attempt IS NULL OR last_attempt<clock_timestamp()-interval '5 minutes')`)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (d *DB) FinishHuntTrendCollection(ctx context.Context, reports []hunting.TrendReport, collectionError string) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, report := range reports {
		if report.TopicKey == "" || report.Term == "" || report.PublishedAt.IsZero() || len(report.References) == 0 {
			return ErrDefenseInvalid
		}
		raw, err := json.Marshal(report)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO defensive_hunt_trends(topic_key,report,published_at) VALUES($1,$2,$3) ON CONFLICT(topic_key) DO UPDATE SET report=EXCLUDED.report,published_at=GREATEST(defensive_hunt_trends.published_at,EXCLUDED.published_at),updated_at=clock_timestamp()`, report.TopicKey, raw, report.PublishedAt)
		if err != nil {
			return err
		}
	}
	if len(collectionError) > 1000 {
		collectionError = collectionError[:1000]
	}
	_, err = tx.ExecContext(ctx, `UPDATE defensive_hunt_trend_collection SET lease_until='-infinity',last_success=CASE WHEN $1 THEN clock_timestamp() ELSE last_success END,last_error=$2 WHERE singleton=true`, len(reports) > 0 || collectionError == "", collectionError)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM defensive_hunt_trends WHERE published_at<clock_timestamp()-interval '30 days'`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
