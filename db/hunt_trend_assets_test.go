package db

import (
	"testing"

	"github.com/Autumn-27/artex/hunting"
)

func TestHuntTrendAssetsReadsOnlyProductFingerprints(t *testing.T) {
	d := defensiveDB(t)
	var id int64
	err := d.QueryRowContext(t.Context(), `INSERT INTO assets(type,domain,port,url,service_type,technologies,auth,extra) VALUES('service','trend-fixture.lab',443,'https://trend-fixture.lab','http',ARRAY['Ivanti Connect Secure 22.7'],ARRAY['{"token":"must-not-leak"}'::jsonb],'{"secret":"must-not-leak"}'::jsonb) RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	assets, _, err := d.HuntTrendAssets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, asset := range assets {
		if asset.Label != "trend-fixture.lab:443" {
			continue
		}
		found = asset.Target == asset.Label && len(asset.Technologies) == 1 && asset.Technologies[0] == "Ivanti Connect Secure 22.7"
		matched := hunting.MatchTrendAssets([]hunting.TrendReport{{TopicKey: "CVE-2026-12345", Kind: "kev", Product: "Connect Secure"}}, []hunting.TrendAsset{asset})
		found = found && matched[0].AssetMatchCount == 1
	}
	if !found {
		t.Fatal("service product fingerprint was not available for report matching")
	}
}
