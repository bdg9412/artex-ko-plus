package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/hunting"
)

const huntTrendAssetLimit = 5000

// HuntTrendAssets reads only product fingerprints and target labels. This is a
// bounded inventory hint, not a scan or authorization of a hunting scope.
func (d *DB) HuntTrendAssets(ctx context.Context) ([]hunting.TrendAsset, bool, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,COALESCE(domain,''),COALESCE(ip,''),port,COALESCE(app_name,''),array_to_json(technologies)::text,last_seen FROM assets WHERE type IN ('service','app') AND (cardinality(technologies)>0 OR COALESCE(app_name,'')<>'') ORDER BY last_seen DESC,id DESC LIMIT $1`, huntTrendAssetLimit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	assets := make([]hunting.TrendAsset, 0)
	for rows.Next() {
		var id int64
		var domain, ip, appName, techJSON string
		var port sql.NullInt64
		var lastSeen time.Time
		if err := rows.Scan(&id, &domain, &ip, &port, &appName, &techJSON, &lastSeen); err != nil {
			return nil, false, err
		}
		var technologies []string
		if err := json.Unmarshal([]byte(techJSON), &technologies); err != nil {
			return nil, false, err
		}
		target := domain
		if target == "" {
			target = ip
		}
		if target != "" && port.Valid {
			target = net.JoinHostPort(target, strconv.FormatInt(port.Int64, 10))
		}
		label := target
		if label == "" {
			label = appName
		}
		if label == "" {
			label = "자산 #" + strconv.FormatInt(id, 10)
		}
		assets = append(assets, hunting.TrendAsset{ID: strconv.FormatInt(id, 10), Label: label, Target: target, AppName: appName, Technologies: technologies, LastSeen: lastSeen})
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(assets) > huntTrendAssetLimit
	if truncated {
		assets = assets[:huntTrendAssetLimit]
	}
	return assets, truncated, nil
}
