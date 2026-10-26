package agent

import "github.com/Autumn-27/artex/db"

// diagnosticWorkerAssets keeps the worker's permanent system prompt small.
// The intent still carries every asset ID, and list_assets(ids) can fetch full
// records when details are needed. Raw Extra/Auth/Params may be large and are
// not needed in every model turn of a read-only diagnostic follow-up.
func diagnosticWorkerAssets(assets []*db.Asset) map[string]any {
	const previewCount = 12
	const maxURLBytes = 512
	ids := make([]int64, 0, len(assets))
	preview := make([]map[string]any, 0, min(len(assets), previewCount))
	for _, asset := range assets {
		if asset == nil {
			continue
		}
		ids = append(ids, asset.ID)
		if len(preview) >= previewCount {
			continue
		}
		item := map[string]any{"id": asset.ID, "type": asset.Type}
		if asset.Domain != "" {
			item["domain"] = asset.Domain
		}
		if asset.IP != "" {
			item["ip"] = asset.IP
		}
		if asset.Port != nil {
			item["port"] = *asset.Port
		}
		if asset.Method != "" {
			item["method"] = asset.Method
		}
		if asset.URL != "" {
			if len(asset.URL) <= maxURLBytes {
				item["url"] = asset.URL
			} else {
				item["url_omitted"] = true
			}
		}
		preview = append(preview, item)
	}
	return map[string]any{
		"asset_ids": ids,
		"assets":    preview,
		"count":     len(ids),
		"detail":    "필요한 자산의 정확한 URL·파라미터·기타 필드는 list_assets(ids)로 조회하세요. 이 개요에 없는 자산도 asset_ids에 포함됩니다.",
	}
}
