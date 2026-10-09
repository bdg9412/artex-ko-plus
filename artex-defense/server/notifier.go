package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// 全局设置键（存在 settings 键值表里，无需建表）。
const (
	// settingNotifyEnabled 是推送总开关。默认开：它用于维护期一键止血，
	// 而不是功能的启用条件——真正的启用条件是「有没有配渠道」。
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL 是生成漏洞详情回链的外部访问地址
	// （如 https://artex.example.com）。留空则消息里不带回链按钮。
	// 项目里没有可复用的外部地址配置，所以这里新增一项。
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes 是汇总模式的周期（分钟）。
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick 是投递引擎的轮询间隔。3 秒是该引擎实时性的上限，
	// 也是「漏洞落库」到「消息到达 IM」之间的主要延迟来源。
	notifyTick = 3 * time.Second
	// notifyBackgroundDisabledEnv 가 설정되면 서버가 백그라운드 투递 루프
	// (newNotifier(s).Run)를 띄우지 않는다. 통합 테스트는 stepRealtime·stepDigest 를
	// 직접 호출해 분배 결과를 결정론적으로 검증하는데, 3 초 주기의 백그라운드 루프가
	// 같은 채널을 동시에 처리하면 집계가 타이밍에 따라 흔들린다. 이를 막기 위한
	// 테스트 전용 스위치이며, 변수가 없으면 평소대로 기동한다(프로덕션 동작 불변).
	notifyBackgroundDisabledEnv = "ARTEX_NOTIFY_BACKGROUND_DISABLED"
	// notifyLease 是领取投递时的租约时长。必须显著大于单次投递的最坏耗时
	// （notify 包的 HTTP 客户端超时 15 秒），否则会出现同一行被两个
	// dispatcher 同时投递。
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick 限制每轮分派的事件数，避免首次启用渠道时
	// 一次性把历史积压全部展开成投递任务。
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes 是汇总周期的默认值。
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick 是渠道未设限流时的每轮投递上限。
	// 存在的意义是防止「一个渠道配成不限流 + 一次扫出上千条漏洞」把
	// 单轮循环拖成长时间阻塞。
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick 是单渠道每轮最多投递几条。
	//
	// 这个上限由**租约时长**倒推：领取时给行打的是租约（notifyLease = 3 分钟），
	// 若一轮里串行投递的条数多到最坏耗时超过租约，后几条还没发完租约就过期了。
	// 单进程内无所谓（Run 是单个 goroutine 串行跑，tick 不会重入），但**两个
	// 进程连同一个库**时，对端会把租约过期的行重新领走并重复发送，还会把
	// attempts 双份递增、在原进程仍在投递时就判成失败。
	//
	// 取值：3 分钟租约 / 30 秒单次超时 = 6 是**刚好用满租约**、零余量，
	// 不能取；取 5 让最坏耗时 150 秒留出 30 秒余量。这个关系由
	// TestNotifyTickBudgetFitsWithinLease 钉死——改 notifyLease、
	// notifySendTimeout 或本值中的任意一个都会让那条断言失败。
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout 是单次投递的超时。它同时决定上一条常量的取值，
	// 两者相乘不能超过 notifyLease，见 TestNotifyTickBudgetFitsWithinLease。
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff 是失败重试的退避序列，下标为已尝试次数。
// 3 次机会（含首次）与 db.MaxNotifyAttempts 对应，两者必须一起改。
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// 전달 실패·지연 사유. notification_deliveries.last_error 에 저장되어
// notify_api.go 의 전달 이력 응답을 거쳐 알림 페이지 「전달 기록」 표(delivery-list.tsx)에
// 그대로 표시된다. 따라서 사용자 노출 문구라 한국어로 둔다(진단 로그 log.Printf 는 원문 보존, Z2).
const (
	errDeliveryChannelKindUnregistered = "등록되지 않은 채널 유형입니다: %q"
	errDeliverySnapshotUnrenderable    = "이벤트 스냅샷을 해석하지 못해 이 취약점을 메시지로 만들지 못했습니다"
	errDeliveryChannelLengthCapped     = "이 메시지가 채널 길이 상한에 도달해 앞의 %d건만 전송했고, 나머지는 다음 배치로 미룹니다"
	errDeliveryNoDeliveredCount        = "채널이 전송 건수를 보고하지 않았습니다(delivered=%d)"
	errDeliveryRetryExhausted          = "%d회 재시도 후에도 실패했습니다: %s"
	errDeliverySnapshotEmpty           = "전달 항목 #%d 의 이벤트 스냅샷이 비어 있습니다"
	errDeliverySnapshotParse           = "전달 항목 #%d 의 이벤트 스냅샷을 해석하지 못했습니다: %w"
	errDeliveryBatchAllUnparseable     = "요약 배치의 전달 %d건을 모두 해석하지 못했습니다"
)

// Notifier 是漏洞推送的投递引擎。
//
// 与 Scheduler 并列，作为独立 goroutine 运行（见 server.New）。刻意不复用
// Scheduler 的 tick：推送的实时性要求（3 秒）与触发器的业务节奏不同，
// 且两者的失败互不牵连——推送卡住不该影响 agent 触发。
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu 保护 buckets。渠道数量少、竞争低，一把互斥锁足够，
	// 不值得为它引入更细粒度的结构。
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket 是单渠道的令牌桶。
//
// 用令牌桶而不是「每分钟计数后清零」的滑动窗口，是因为后者的边界效应很糟：
// 在窗口末尾发满 20 条、下一瞬间再发 20 条，对平台来说是一秒内 40 条，
// 会被限流；令牌桶以恒定速率补充，天然避免这种突发。
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run 循环直到 ctx 结束。由 server.New 启动一次。
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step 跑一轮：先分派新事件，再投递到期的任务。
//
// 任何一步失败都只记日志、不中断循环——通知系统的故障绝不能升级成进程级问题。
// 每个 tick 都是独立的，下一轮会自然重试。
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] 分派事件失败: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] 读取渠道失败: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// 令牌桶的计量单位是**消息条数**（等价于 HTTP 请求数），不是漏洞条数。
		// 实时模式下两者相同（一条漏洞一条消息）；汇总模式下一整批漏洞合成
		// 一条消息，所以只消耗一个令牌。
		//
		// 两种模式都先问令牌桶、再按额度去领——顺序不能反，否则被限流挡下的
		// 投递已经消耗过重试次数。
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan 返回汇总渠道本轮的令牌消耗与批次大小上界。
//
// 两个返回值是**两个不同的量纲**，这正是独立成函数的理由：
//
//   - tokens 是消息条数。一批漏洞合成一条消息、发一次 HTTP 请求，所以恒为 1。
//     rate_per_min 因此仍然对 digest 生效（每分钟最多这么多条汇总消息）。
//   - claimLimit 是这一批最多装几条漏洞。它只受内存上界约束，与请求预算无关。
//
// 曾经为了让 rate_per_min 对 digest 生效，把每轮请求预算
// （notifyMaxSendsPerChannelPerTick，由租约倒推而来）直接当批次大小传下去。
// 后果是 rate_per_min=20 的渠道在 3 秒的 tick 里只补到 1 个令牌，于是每条汇总
// 消息只装 1 个漏洞——digest 退化成「带汇总文案的实时推送」，读者收到的是一串
// 「近 30 分钟新增 1 个漏洞」，而 db.MaxDigestBatchSize 永不可达。
//
// 这个症状在端到端测试里不容易发现（现有用例都手动传一个够大的 limit 给
// stepDigest，绕过了 step 里的额度计算），所以把决策收在这里由
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget 直接钉住。
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime 领取并投递某渠道的实时任务，一条漏洞一条消息。
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] 领取实时投递失败 channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(errDeliveryChannelKindUnregistered, ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// 渲染失败是本地数据问题，重试不会变好。
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest 在批次到期时把某渠道的待发投递聚合成一条消息发出。
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] 判断汇总批次失败 channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] 领取汇总批次失败 channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf(errDeliveryChannelKindUnregistered, ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// 快照坏掉、没能进消息的那些投递要显式判失败。不这么做的话它们会留在
	// included 之外、既不进消息也不进失败列表——发送成功时它们的状态会被
	// 之后的批量标记漏掉，永远停在 sending 直到租约过期被反复领取。
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := errDeliverySnapshotUnrenderable
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] 标记坏快照投递失败 channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] 跳过 %d 条快照无法解析的投递 channel=%d", len(skipped), ch.ID)
	}
	// 只把进了消息的那些交给 send：included[i] 与 msg.Items[i] 严格对应，
	// send 依赖这个对应关系把「渠道回报装下了前 K 条」落到正确的投递行上。
	n.send(ctx, channel, cfg, msg, included)
}

// send 投递并按结果流转状态。
//
// 同一批投递（汇总模式下可能几十条）共享一个发送结果：要么送达、要么整批重试。
// 不做逐条重试——汇总消息是一条，重发其中一部分会让批次语义错乱。
//
// 唯一的例外是**渠道长度上限导致的分段**：渠道回报实际只装下了前 K 条，
// 那么第 K+1 条起必须留到下一批，而不是跟着一起被标记成功。否则被截掉的
// 那些漏洞既不在消息里、也不在失败列表里，彻底消失。
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// 单次投递设上限，避免某个渠道卡住把这一轮剩余渠道全部拖住。
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// 渠道回报的条数不可能超过投递数；真发生了说明渲染层算错了，
			// 按全部送达处理并把问题记下来，总好过把记录写乱。
			log.Printf("[notify] 渠道回报送达条数 %d 超过投递数 %d channel=%s，按全部送达处理",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] 标记已送达失败 channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// 本条消息已达渠道长度上限：剩下的立刻回队，由下一个 tick 续发。
			// 用 DeferDeliveries 而非 RescheduleDeliveries —— 这不是失败，
			// 不该消耗重试预算（领取时已经乐观 +1 了，那里会减回去）。
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf(errDeliveryChannelLengthCapped, delivered)); err != nil {
				log.Printf("[notify] 分段续发排队失败 channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// 渠道既没报错也没说送达了多少条。按失败处理（走退避），
		// 免得这条投递被反复领取却永远标记不掉。
		err = fmt.Errorf(errDeliveryNoDeliveredCount, delivered)
	}

	// 失败处置**逐条**决定，而不是拿整批的最大尝试次数做判断。
	//
	// 曾经是 `if maxAttempts(deliveries) >= MaxNotifyAttempts` 整批判死，但批次里
	// 各条的尝试次数并不相同：一个已经重试两次的老投递（attempts=2）会把同一批里
	// 全新的投递（attempts=1）一起拖进 failed——新漏洞一条重试都没用上就永久丢了，
	// 与「不让老行拖新行下水」的初衷正好相反。
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] 标记失败状态出错 channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf(errDeliveryRetryExhausted, db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] 标记失败状态出错 channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// 按延迟分组重排：只有 3 档退避，分组数天然很小，不必为每条单独发一次
	// UPDATE（那会让一个 500 条的批次产生 500 次往返）。
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] 重排投递失败 channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] 投递失败 channel=%d kind=%s 永久失败=%d 重试耗尽=%d 待重试=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries 返回 all 中不在 keep 里的那些（按指针身份比较）。
// 用于找出「没能进消息」的投递——它们必须被显式处置，不能留在灰色地带。
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt 取渠道实现并解析其配置。
// 返回 ok=false 表示类型未注册，投递应直接判失败而不是无限重试。
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// 配置解析失败时给一个空 map：渠道自身的 Validate 会报出「缺哪个字段」，
		// 那个错误比 JSON 解析错误更能指导用户修复。
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle 渲染单条漏洞消息。
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch 渲染汇总消息。逐条解析快照——单条坏了只跳过那一条，
// 不让它把整批汇总拖没。
//
// 返回值 included 与 msg.Items **严格一一对应**（第 i 个投递 ↔ 第 i 个条目）。
// 这个对应关系是硬要求：调用方按「渠道回报装下了前 K 条」来决定前 K 个投递
// 标记已送达。若这里跳过了坏快照却不把跳过的投递从 included 里剔除，
// 下标就会错位——本该失败的坏条目会被标成已送达，而好条目被误判为未送达。
// 坏掉的那些由调用方显式标记失败，见 stepDigest。
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// 坏快照不进消息，也不进 included——它的处置由调用方负责
			// （显式标记失败，而不是混在「已送达」里蒙混过关）。
			log.Printf("[notify] 汇总批次中跳过无法解析的快照 delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf(errDeliveryBatchAllUnparseable, len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor 把事件快照渲染成待推送条目，顺带解析资产名与详情回链。
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// 资产名解析失败不该阻止推送：读不到名字比收不到通知轻得多，
		// 消息里少一行资产而已。
		log.Printf("[notify] 解析资产名失败 finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// 详情页路由见 web/src/app/(main)/function/findings/detail/page.tsx，
		// 它从 query 参数 id 读取漏洞 id。
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens 从渠道令牌桶里取走**最多 want 个**令牌，返回实际取到的数量。
//
// 一个令牌 = 一条消息（一次 HTTP 请求）。实时模式下调用方要几条就传几条；
// 汇总模式下一整批漏洞只发一条消息，传 1。
//
// 桶容量为该渠道每分钟上限，按恒定速率补充。ratePerMin<=0 表示不限流，
// 返回一个有限但足够大的值，防止单轮循环被无限积压拖住。
//
// want 这个上限是必需的：没有它就只能把桶整个抽空，而调用方自己还有每轮上限，
// 多取的令牌既用不上、又在下次补充前凭空消失——攒下来的突发容量永远不可达，
// 连「这一轮没有任何待发投递」都会照扣一笔。
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// 按经过的真实时间补充，速率是 ratePerMin/60 每秒。
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// 加一个极小 epsilon 再取整：令牌数是浮点累加出来的，分两次补满时
	// 0.5 + 0.5 可能得到 0.9999999999，直接 int() 会被截成 0——
	// 数学上已满的桶却取不出令牌。1e-9 远小于一个令牌，不会放过真正的欠额。
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled 读取总开关。
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL 返回回链用的外部地址，去掉尾部斜杠。
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval 返回汇总周期，非法或未配置时回落到默认值。
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot 解析投递对应事件的快照。
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf(errDeliverySnapshotEmpty, dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf(errDeliverySnapshotParse, dl.ID, err)
	}
	if snap.Kind == "" {
		// 事件类型以事件行为准，快照里那份可能由旧版本写过。
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
