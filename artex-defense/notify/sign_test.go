package notify

import (
	"net/url"
	"testing"
	"time"
)

// 签名基准值由 OpenSSL 独立算出，不是用本包自己的实现生成的——
// 否则只能证明「代码没变」，证明不了「算法对」。
//
//	TS=1700000000000, SECRET=SECtest123
//	钉钉: printf '%s\n%s' "$TS" "$SECRET" | openssl dgst -sha256 -hmac "$SECRET" -binary | openssl base64 -A
//	      -> w3RMHXzixTMdzr8OHJUmVLS4IoPJVdu+Ut1LE48MePE=
//	飞书: printf '' | openssl dgst -sha256 -hmac "$(printf '%s\n%s' "$TS" "$SECRET")" -binary | openssl base64 -A
//	      -> Hd4xFWQU6R6ad4nzy4ETIznzlqebqH7xcTFVmONTudo=
const (
	signTestTSMillis = int64(1700000000000)
	signTestSecret   = "SECtest123"
	dingTalkExpected = "w3RMHXzixTMdzr8OHJUmVLS4IoPJVdu+Ut1LE48MePE="
	feishuExpected   = "Hd4xFWQU6R6ad4nzy4ETIznzlqebqH7xcTFVmONTudo="
)

func TestDingTalkSignMatchesReference(t *testing.T) {
	got, err := dingTalkSignedURL("https://oapi.dingtalk.com/robot/send?access_token=tok", signTestSecret, time.UnixMilli(signTestTSMillis))
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("产出地址不可解析: %v", err)
	}
	q := u.Query()
	if q.Get("sign") != dingTalkExpected {
		t.Errorf("签名不符\n期望 %s\n得到 %s", dingTalkExpected, q.Get("sign"))
	}
	if q.Get("timestamp") != "1700000000000" {
		t.Errorf("时间戳应为毫秒且原样带上，得到 %q", q.Get("timestamp"))
	}
	// 原有 query 参数（access_token）不能被签名覆盖掉。
	if q.Get("access_token") != "tok" {
		t.Errorf("原有 query 参数丢失，得到 %q", q.Get("access_token"))
	}
}

func TestFeishuSignMatchesReference(t *testing.T) {
	got := feishuSign("1700000000000", signTestSecret)
	if got != feishuExpected {
		t.Errorf("签名不符\n期望 %s\n得到 %s", feishuExpected, got)
	}
}

// TestSignAlgorithmsDiffer 锁住两家的算法差异。它们刚好互为对方的参数顺序
// （钉钉 key=secret，飞书 key=待签串），照另一家抄必然校验失败，
// 这条用例确保将来重构不会把两者合并成同一个函数。
func TestSignAlgorithmsDiffer(t *testing.T) {
	ts := "1700000000000"
	dingURL, err := dingTalkSignedURL("https://example.com/hook", signTestSecret, time.UnixMilli(signTestTSMillis))
	if err != nil {
		t.Fatal(err)
	}
	dq, _ := url.Parse(dingURL)
	if dq.Query().Get("sign") == feishuSign(ts, signTestSecret) {
		t.Fatal("钉钉与飞书签名相同，说明其中一家的算法实现错了")
	}
}

func TestDingTalkNoSecretLeavesURLUntouched(t *testing.T) {
	// 未开启加签的机器人：不得凭空添加 timestamp/sign 参数。
	const hook = "https://oapi.dingtalk.com/robot/send?access_token=tok"
	got, err := dingTalkSignedURL(hook, "", time.UnixMilli(signTestTSMillis))
	if err != nil {
		t.Fatal(err)
	}
	if got != hook {
		t.Fatalf("未配置 secret 时地址不应改动，得到 %q", got)
	}
}

func TestValidateHTTPURL(t *testing.T) {
	ok := []string{"https://example.com/hook", "http://10.0.0.1:8080/x?y=1"}
	for _, s := range ok {
		if err := validateHTTPURL(s); err != nil {
			t.Errorf("%q 应被接受: %v", s, err)
		}
	}
	// file:// 之类不应放行——http.Client 对它们的处理超出预期范围。
	bad := []string{"", "file:///etc/passwd", "ftp://example.com", "https://", "gopher://x"}
	for _, s := range bad {
		if err := validateHTTPURL(s); err == nil {
			t.Errorf("%q 应被拒绝", s)
		}
	}
}
