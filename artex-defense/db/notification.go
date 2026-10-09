package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Autumn-27/artex/notify"
)

// 本文件是 IM 推送的渠道配置与事件层。投递任务的领取与状态流转见
// db/notification_delivery.go。
//
// 两条不变量，改这个文件时务必保持：
//
//  1. 写漏洞的事务(RecordFindingTx)只调用 InsertNotificationEventTx 做一次盲插，
//     不读任何通知相关的表、不做过滤匹配。任何在这里引入的读操作都可能因为
//     用户配错的过滤条件而污染甚至中止漏洞写入事务。
//  2. 过滤匹配永不报错：配置畸形一律按「命中」处理(见 notify.Match)。宁可多推，
//     不可漏推。

// ErrNotificationChannelNotFound 渠道不存在。
var ErrNotificationChannelNotFound = errors.New("通知渠道不存在")

// 投递状态。
const (
	NotifyStatePending = "pending" // 待发
	NotifyStateSending = "sending" // 已被某个 dispatcher 领取，租约未到期
	NotifyStateSent    = "sent"    // 已送达
	NotifyStateFailed  = "failed"  // 重试耗尽或永久失败，可手动重发
	NotifyStateSkipped = "skipped" // 渠道已停用，不再发送
)

// 推送模式。
const (
	NotifyModeRealtime = "realtime"
	NotifyModeDigest   = "digest"
)

// ValidNotifyMode 白名单校验推送模式（与 findings.status 同理：不用 DB CHECK，
// 便于后续扩展）。
func ValidNotifyMode(m string) bool {
	return m == NotifyModeRealtime || m == NotifyModeDigest
}

// NotificationChannel 是一个渠道实例配置。Config 与 Filter 保持原始 JSON，
// 解析交给 notify 包——db 层不理解它们的字段含义。
type NotificationChannel struct {
	ID     int64           `json:"id"`
	Name   string          `json:"name"`
	Kind   string          `json:"kind"`
	Mode   string          `json:"mode"`
	Config json.RawMessage `json:"config"`
	Filter json.RawMessage `json:"filter"`
	// Enabled 用指针是为了区分「没传这个字段」与「显式传 false」——
	// 前端开关控件只提交被改动的字段。
	Enabled    *bool     `json:"enabled,omitempty"`
	RatePerMin int       `json:"rate_per_min"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// IsEnabled 返回渠道是否启用；Enabled 为 nil（未加载）时按启用处理。
func (c *NotificationChannel) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// NotificationEvent 是一条事件事实。
type NotificationEvent struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	FindingID int64           `json:"finding_id"`
	Snapshot  json.RawMessage `json:"snapshot"`
	CreatedAt time.Time       `json:"created_at"`
}

const notificationChannelCols = `id, name, kind, enabled, config, mode, filter, rate_per_min, created_at, updated_at`

func scanNotificationChannel(sc interface{ Scan(...any) error }) (*NotificationChannel, error) {
	var c NotificationChannel
	var enabled bool
	if err := sc.Scan(&c.ID, &c.Name, &c.Kind, &enabled, &c.Config, &c.Mode, &c.Filter, &c.RatePerMin, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	c.Enabled = &enabled
	return &c, nil
}

// ListNotificationChannels 返回全部渠道实例，启用的排在前面、同级按 id。
// 排序放在 SQL 里是为了让 UI 与 dispatcher 看到同一个稳定顺序。
func (d *DB) ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+notificationChannelCols+` FROM notification_channels
ORDER BY enabled DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationChannel{}
	for rows.Next() {
		c, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NotificationChannelByID 取单个渠道。
func (d *DB) NotificationChannelByID(ctx context.Context, id int64) (*NotificationChannel, error) {
	row := d.QueryRowContext(ctx, `SELECT `+notificationChannelCols+` FROM notification_channels WHERE id=$1`, id)
	c, err := scanNotificationChannel(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotificationChannelNotFound
	}
	return c, err
}

// SaveNotificationChannel 新建或更新一个渠道。
//
// 更新时只覆盖调用方显式给出的字段（非 nil / 非空），这样前端可以提交局部
// 修改的抽屉表单，而不必回传 config 里那些它没展示的字段——回传反而会造成
// 「掩码值把真实密钥覆盖掉」的事故。
func (d *DB) SaveNotificationChannel(ctx context.Context, c *NotificationChannel) (int64, error) {
	if c.Mode == "" {
		c.Mode = NotifyModeRealtime
	}
	// 这里刻意**不**对 0 做任何加工：0 是合法配置，含义是「不限流」。
	//
	// 曾经写成 `if c.RatePerMin <= 0 { c.RatePerMin = 默认值 }`，本意是「未指定时
	// 给个安全默认」，但那把「显式设成 0」也一起吞掉了——文档、UI 提示与
	// takeTokens 都把 0 解释为不限流，唯独这里悄悄改成 20（钉钉/企微/Telegram）
	// 或 100（飞书），操作者以为放开了限流、实际被 20/分钟卡着且没有任何提示。
	//
	// 「未指定」与「显式 0」的区别只有调用方知道（请求体里字段缺省 vs 明确传 0），
	// 所以默认值由 server 层在字段缺省时填，见 notifyCreateChannel。
	if c.RatePerMin < 0 {
		return 0, errors.New("限流值不能为负")
	}
	if c.Config == nil {
		c.Config = json.RawMessage(`{}`)
	}
	if c.Filter == nil {
		c.Filter = json.RawMessage(`{}`)
	}
	enabled := c.IsEnabled()

	if c.ID == 0 {
		var id int64
		err := d.QueryRowContext(ctx, `INSERT INTO notification_channels(name,kind,enabled,config,mode,filter,rate_per_min)
VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			c.Name, c.Kind, enabled, string(c.Config), c.Mode, string(c.Filter), c.RatePerMin).Scan(&id)
		return id, err
	}
	res, err := d.ExecContext(ctx, `UPDATE notification_channels
SET name=$2, kind=$3, enabled=$4, config=$5, mode=$6, filter=$7, rate_per_min=$8
WHERE id=$1`,
		c.ID, c.Name, c.Kind, enabled, string(c.Config), c.Mode, string(c.Filter), c.RatePerMin)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotificationChannelNotFound
	}
	return c.ID, nil
}

// SetNotificationChannelEnabled 切换启停。
//
// 停用一个渠道时，把它尚未发出的投递一并标记为 skipped：否则重新启用后
// 会突然收到一批「停用期间积压」的旧漏洞，时效已失且容易误判为新增。
func (d *DB) SetNotificationChannelEnabled(ctx context.Context, id int64, enabled bool) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE notification_channels SET enabled=$2 WHERE id=$1`, id, enabled)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotificationChannelNotFound
		}
		if !enabled {
			if _, err := tx.ExecContext(ctx, `UPDATE notification_deliveries SET state=$2, last_error=$3
WHERE channel_id=$1 AND state IN ($4,$5)`,
				id, NotifyStateSkipped, "渠道已停用", NotifyStatePending, NotifyStateSending); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteNotificationChannel 删除渠道。其投递历史随外键级联删除
// （渠道配置都没了，历史无从解读）。
func (d *DB) DeleteNotificationChannel(ctx context.Context, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotificationChannelNotFound
	}
	return nil
}

// RecordNotificationEventTx 在调用方的事务里**尽力**写入一条推送事件。
//
// 这是漏洞写入路径上唯一的通知相关改动：一次 INSERT，不读任何表、不认识渠道、
// 不跑过滤。事务提交即保证「漏洞落库」与「推送任务存在」原子一致，
// 不存在提交成功却没入队、消息永久丢失的窗口。
//
// 两个关键设计，都不是随手写的：
//
//  1. **为什么用 SAVEPOINT**：PostgreSQL 里事务内任一语句报错会让整个事务进入
//     aborted 状态，此后所有语句（含 COMMIT）一律失败。所以「忽略这条 INSERT
//     的错误、让调用方继续提交」在 PG 里是做不到的——除非用保存点把错误隔离在
//     这一条语句上。没有保存点，就只剩「整笔回滚」这一个选项。
//
//  2. **为什么整笔回滚是错的**：推送是便利功能，漏洞记录才是产品本身。一个通知
//     表的问题（旧库未迁移、磁盘瞬时故障）不该让高危漏洞存不进库。所以这里隔离
//     错误、记日志、返回 false，让漏洞写入照常提交——代价是丢掉这一条推送。
//     返回 bool 而非 error 是刻意的：调用方不该把它当作会影响写入成败的错误。
func RecordNotificationEventTx(ctx context.Context, tx *sql.Tx, kind string, findingID int64, snap notify.Snapshot) bool {
	raw, err := json.Marshal(snap)
	if err != nil {
		log.Printf("[notify] 序列化推送事件失败 finding=%d: %v", findingID, err)
		return false
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT notify_event`); err != nil {
		log.Printf("[notify] 建立保存点失败 finding=%d: %v", findingID, err)
		return false
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot) VALUES($1,$2,$3)`,
		kind, findingID, string(raw)); err != nil {
		log.Printf("[notify] 写入推送事件失败 finding=%d（漏洞记录不受影响）: %v", findingID, err)
		// 回滚到保存点，把事务从 aborted 状态里救回来。
		if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT notify_event`); rbErr != nil {
			log.Printf("[notify] 回滚到保存点失败 finding=%d: %v", findingID, rbErr)
		}
		return false
	}
	// 释放保存点，避免长事务里积攒无用的保存点。
	_, _ = tx.ExecContext(ctx, `RELEASE SAVEPOINT notify_event`)
	return true
}

// AddNotificationEvent 是 InsertNotificationEventTx 的独立事务版本，供不在
// 既有事务里的调用点使用（如渠道的「发送测试消息」，它没有真实 finding）。
func (d *DB) AddNotificationEvent(ctx context.Context, kind string, findingID int64, snap notify.Snapshot) (int64, error) {
	raw, err := json.Marshal(snap)
	if err != nil {
		return 0, fmt.Errorf("序列化通知事件快照失败: %w", err)
	}
	var id int64
	err = d.QueryRowContext(ctx, `INSERT INTO notification_events(kind,finding_id,snapshot) VALUES($1,$2,$3) RETURNING id`,
		kind, findingID, string(raw)).Scan(&id)
	return id, err
}

// FanOutPendingEvents 把尚未分派的漏洞事件按当前启用的渠道展开成投递任务，
// 返回本轮处理的事件数与新建的投递数。
//
// 整轮操作在一个事务里：事件用 FOR UPDATE SKIP LOCKED 领取，多个进程同时跑
// 也各自领到不同的行（项目里归档队列的领取用的是同一套手法，见
// db/task_archives.go 的 completeNextArchiveJob）。
//
// 过滤匹配刻意放在 Go 侧而非 SQL：渠道的过滤条件是一组可选字段的 JSONB，
// 用 SQL 表达六种组合的匹配会让查询难以维护，而渠道数量是「人手配的几条」，
// 全量加载后在内存里逐条比对更快也更好测。
//
// 未命中任何渠道的事件同样会被标记 fanned_out ——否则它会永远留在待分派集合里，
// 每个 tick 被重扫一遍。
func (d *DB) FanOutPendingEvents(ctx context.Context, limit int) (eventCount, deliveryCount int, err error) {
	if limit <= 0 {
		limit = 200
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // 提交成功后是 no-op

	channels, err := listEnabledNotificationChannelsTx(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, kind, finding_id, snapshot FROM notification_events
WHERE NOT fanned_out ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return 0, 0, err
	}
	var (
		events      []NotificationEvent
		parsedSnaps []notify.Snapshot
	)
	for rows.Next() {
		var ev NotificationEvent
		if err := rows.Scan(&ev.ID, &ev.Kind, &ev.FindingID, &ev.Snapshot); err != nil {
			rows.Close()
			return 0, 0, err
		}
		var snap notify.Snapshot
		// 快照是我们自己写的，理论上必定可解析；解析失败不阻断投递流程，
		// 但这条事件会因字段全空而被所有带过滤条件的渠道跳过——宁可少推一条
		// 也不让一个坏行卡死整个队列。
		_ = json.Unmarshal(ev.Snapshot, &snap)
		// kind 以行内值为准：快照里那份是渲染用的副本，可能被旧版本写过。
		snap.Kind = ev.Kind
		events = append(events, ev)
		parsedSnaps = append(parsedSnaps, snap)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if len(events) == 0 {
		return 0, 0, tx.Commit()
	}

	type pending struct {
		eventID   int64
		channelID int64
	}
	var toInsert []pending
	for i, snap := range parsedSnaps {
		for _, ch := range channels {
			if !notify.Match(notify.ParseFilter(ch.Filter), snap) {
				continue
			}
			toInsert = append(toInsert, pending{eventID: events[i].ID, channelID: ch.ID})
		}
	}
	if len(toInsert) > 0 {
		var (
			vals []string
			args []any
		)
		for _, p := range toInsert {
			vals = append(vals, fmt.Sprintf("($%d,$%d)", len(args)+1, len(args)+2))
			args = append(args, p.eventID, p.channelID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries(event_id,channel_id) VALUES `+strings.Join(vals, ","), args...); err != nil {
			return 0, 0, err
		}
	}

	// 标记本轮事件已分派。未命中任何渠道的事件也一起标记（见函数注释）。
	ids := make([]string, 0, len(events))
	markArgs := make([]any, 0, len(events))
	for _, ev := range events {
		markArgs = append(markArgs, ev.ID)
		ids = append(ids, fmt.Sprintf("$%d", len(markArgs)))
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notification_events SET fanned_out=true WHERE id IN (`+strings.Join(ids, ",")+`)`, markArgs...); err != nil {
		return 0, 0, err
	}
	return len(events), len(toInsert), tx.Commit()
}

// listEnabledNotificationChannelsTx 在事务里取启用中的渠道。数量很少，
// 不做分页也不加缓存——缓存会引入「改了配置何时生效」这个额外的时序问题。
func listEnabledNotificationChannelsTx(ctx context.Context, tx *sql.Tx) ([]*NotificationChannel, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name, kind, config, mode, filter, rate_per_min
FROM notification_channels WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotificationChannel{}
	for rows.Next() {
		var c NotificationChannel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &c.Mode, &c.Filter, &c.RatePerMin); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// NotificationAssetNames 把资产 id 解析成简短展示名，供推送消息使用。
//
// 返回顺序与入参一致、长度可能小于入参（不存在的 id 被跳过）。保持入参顺序是
// 为了让同一条漏洞的消息在多次投递里资产顺序稳定——否则重试后收到的消息里
// 资产次序变了，会被误读成「资产变了」。
func (d *DB) NotificationAssetNames(ctx context.Context, ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	ph, args := placeholders(1, ids)
	rows, err := d.QueryContext(ctx, `SELECT id, type, domain, ip, url, app_name, bundle_id FROM assets WHERE id IN (`+ph+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	labels := map[int64]string{}
	for rows.Next() {
		var (
			id                int64
			typ               string
			domain, ip, url   sql.NullString
			appName, bundleID sql.NullString
		)
		if err := rows.Scan(&id, &typ, &domain, &ip, &url, &appName, &bundleID); err != nil {
			return nil, err
		}
		labels[id] = assetDisplayName(typ, domain.String, ip.String, url.String, appName.String, bundleID.String)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if label, ok := labels[id]; ok && label != "" {
			out = append(out, label)
		}
	}
	return out, nil
}

// assetDisplayName 按资产类型挑选最具辨识度的标识。
// 兜底返回空串，由调用方决定怎么呈现「名字取不到的资产」——本函数不臆造占位符，
// 否则「资产#42」这种噪音会混进推送消息里，读者还以为是真实域名。
func assetDisplayName(typ, domain, ip, url, appName, bundleID string) string {
	pick := func(vals ...string) string {
		for _, v := range vals {
			if strings.TrimSpace(v) != "" {
				return v
			}
		}
		return ""
	}
	switch typ {
	case "root_domain", "subdomain":
		return domain
	case "ip":
		return ip
	case "app":
		return pick(appName, bundleID)
	case "service", "endpoint":
		return pick(url, domain, ip)
	default:
		return pick(domain, ip, url, appName)
	}
}

// SetFindingStatusWithNotify 更新漏洞处置状态，并在同一事务里登记一条状态变更
// 推送事件。
//
// 返回 from=变更前的状态；found=漏洞是否存在；notified=事件是否登记成功。
//
// 三条刻意的行为：
//   - 状态未实际变化时不登记事件。前端抽屉重复提交同一个值、或自动化脚本
//     幂等重放，都不该产出推送噪音。
//   - 漏洞不存在时返回 found=false 且不做任何写入，由调用方翻译成 404。
//   - 事件登记失败不影响状态更新（见 RecordNotificationEventTx 的保存点说明），
//     所以 notified=false 时状态已经改成功了，调用方不应因此报错。
func (d *DB) SetFindingStatusWithNotify(ctx context.Context, id int64, status string) (from string, found bool, notified bool, err error) {
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var txErr error
		from, found, _, notified, txErr = SetFindingStatusTx(ctx, tx, id, status)
		return txErr
	})
	return from, found, notified, err
}

// SetFindingStatusTx 在**调用方的事务**内更新漏洞状态并登记状态变更推送事件。
//
// 抽成事务级函数是为了让所有改状态的路径共用同一套语义——此前只有
// patchFinding 走带通知的版本，而**复测结论为「已修复」时**（finding_retests
// 里那条 `UPDATE findings SET status=...`）是直接写库的，于是配了
// `on_status_change` 的渠道对这类状态流转完全收不到推送：界面上状态悄悄变了，
// 运维要到打开平台才发现。
//
// 返回 from=变更前状态、found=漏洞是否存在、changed=状态是否真的变了、
// notified=事件是否登记成功（登记失败不影响状态更新，见 RecordNotificationEventTx）。
func SetFindingStatusTx(ctx context.Context, tx *sql.Tx, id int64, status string) (from string, found bool, changed bool, notified bool, err error) {
	var (
		vulnclass, name, severity, summary string
		taskID                             sql.NullInt64
		assetIDs                           []byte
	)
	scanErr := tx.QueryRowContext(ctx, `SELECT vulnclass, name, severity, summary, task_id, asset_ids, status
FROM findings WHERE id=$1 FOR UPDATE`, id).
		Scan(&vulnclass, &name, &severity, &summary, &taskID, &assetIDs, &from)
	if scanErr == sql.ErrNoRows {
		return "", false, false, false, nil
	}
	if scanErr != nil {
		return "", false, false, false, scanErr
	}
	found = true
	if from == status {
		// 状态没有真的变化就不登记事件：重复提交同一个值、幂等重放都不该
		// 产生推送噪音。
		return from, true, false, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status=$2 WHERE id=$1`, id, status); err != nil {
		return from, true, false, false, err
	}
	var assets []int64
	_ = json.Unmarshal(assetIDs, &assets)
	notified = RecordNotificationEventTx(ctx, tx, notify.EventFindingStatusChanged, id, notify.Snapshot{
		Kind:       notify.EventFindingStatusChanged,
		FindingID:  id,
		TaskID:     taskID.Int64,
		VulnClass:  vulnclass,
		Name:       name,
		Severity:   severity,
		Summary:    summary,
		AssetIDs:   assets,
		FromStatus: from,
		ToStatus:   status,
	})
	return from, true, true, notified, nil
}

// NotificationStats 是通知页顶部的概览计数。
type NotificationStats struct {
	Channels     int   `json:"channels"`
	ChannelsOn   int   `json:"channels_on"`
	Pending      int   `json:"pending"`
	Failed       int   `json:"failed"`
	SentToday    int   `json:"sent_today"`
	BacklogAgeMS int64 `json:"backlog_age_ms"` // 最老的待发投递距今毫秒数
}

// NotificationStatsSnapshot 汇总通知系统的健康度。
// BacklogAgeMS 是「推送是不是卡住了」最直接的指标——比 pending 计数有用得多，
// 因为积压 3 条和积压 3 条的差别可以是从 3 秒到 3 小时。
func (d *DB) NotificationStatsSnapshot(ctx context.Context) (*NotificationStats, error) {
	var s NotificationStats
	if err := d.QueryRowContext(ctx, `SELECT
    (SELECT count(*) FROM notification_channels),
    (SELECT count(*) FROM notification_channels WHERE enabled),
    (SELECT count(*) FROM notification_deliveries WHERE state IN ($1,$2)),
    (SELECT count(*) FROM notification_deliveries WHERE state=$3),
    (SELECT count(*) FROM notification_deliveries WHERE state=$4 AND sent_at >= date_trunc('day', now())),
    COALESCE((SELECT EXTRACT(EPOCH FROM (now() - min(created_at))) * 1000 FROM notification_deliveries WHERE state=$1), 0)::bigint`,
		NotifyStatePending, NotifyStateSending, NotifyStateFailed, NotifyStateSent).
		Scan(&s.Channels, &s.ChannelsOn, &s.Pending, &s.Failed, &s.SentToday, &s.BacklogAgeMS); err != nil {
		return nil, err
	}
	return &s, nil
}
