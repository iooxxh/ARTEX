package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent/chainskel"
)

// 四层架构接线测试(反问思维链):
// L1 代码判据命中 → chainskel.Match(纯函数,见 agent/chainskel 包内测试)
// L2 铁律常驻 → plannerSystem/workerSystem 固定尾
// L3 骨架路由 → add_intent chain_tags 校验 + ForIntent 注入
// L4 原文兜底 → RefsGuideForIntent 指引行

// L2:meta 铁律必须常驻 planner/worker system prompt(静态文本,不含每轮变量)。
func TestSystemPromptMetaRules(t *testing.T) {
	p := plannerSystem("拿下X", "/data", "/data")
	if !strings.Contains(p, "meta 铁律(反问纪律,全程在场)") {
		t.Fatal("plannerSystem 缺 planner 版 meta 铁律")
	}
	w := workerSystem("", "", "/data", "/data")
	if !strings.Contains(w, "meta 铁律(观测真伪与卡住自检)") {
		t.Fatal("workerSystem 缺 worker 版 meta 铁律")
	}
	// 常量与包内定义一致(防止接线时误改文本)。
	if !strings.Contains(p, chainskel.PlannerMetaRules) {
		t.Fatal("plannerSystem 未原样追加 chainskel.PlannerMetaRules")
	}
	if !strings.Contains(w, chainskel.WorkerMetaRules) {
		t.Fatal("workerSystem 未原样追加 chainskel.WorkerMetaRules")
	}
}

// L3:chain_tags 校验 + 规整后写入意图 payload(需要 PG,无库时跳过)。
func TestAddOneIntentChainTags(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("chain tags", "test chain_tags", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	tools := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)

	// 非法 tag 应报错。
	if _, err := tools.addOneIntent(intentItem{Summary: "对 example.com 登录口做 sql 注入测试", ChainTags: []string{" Web ", "sqli?"}}); err == nil || !strings.Contains(err.Error(), "chain_tags") {
		t.Fatalf("非法 tag 应报 chain_tags 错, got err=%v", err)
	}
	// 超 2 个 tag 应报错。
	if _, err := tools.addOneIntent(intentItem{Summary: "x", ChainTags: []string{"web", "ad", "priv"}}); err == nil {
		t.Fatal("超过 2 个 tag 应报错")
	}
	// 合法 tags:规整(小写去重)后写入 payload。
	id, err := tools.addOneIntent(intentItem{Summary: "对 example.com 登录口做 sql 注入测试", ChainTags: []string{"web", "RECON"}})
	if err != nil {
		t.Fatalf("合法 tags 不应报错: %v", err)
	}
	n, err := tools.ts.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("取意图节点: %v", err)
	}
	payload := string(n.Payload)
	if !strings.Contains(payload, `"chain_tags":["web","recon"]`) {
		t.Fatalf("payload 应含规整后的 chain_tags, got: %s", payload)
	}
	if !strings.Contains(payload, `"summary"`) {
		t.Fatalf("payload 缺 summary: %s", payload)
	}
}

// L3+L4:worker 按意图 payload 注入骨架 + 原文指引(纯函数,无需 DB)。
func TestWorkerIntentChainsInjection(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"summary":    "对 example.com 登录口做 sql 注入测试",
		"chain_tags": []string{"web"},
	})
	sk := chainskel.ForIntent(payload)
	if !strings.Contains(sk, "<chains-skeleton") || !strings.Contains(sk, `category="web"`) {
		t.Fatalf("web 意图应注入 web 骨架, got:\n%s", sk)
	}
	rg := chainskel.RefsGuideForIntent(payload)
	if !strings.Contains(rg, "skills/chains-web/refs/") {
		t.Fatalf("web 意图应给出 L4 原文指引, got:\n%s", rg)
	}
	// 无 tag 时关键词回退:recon 关键词应命中 recon 骨架。
	payload2, _ := json.Marshal(map[string]any{"summary": "对目标做子域信息收集"})
	if sk2 := chainskel.ForIntent(payload2); !strings.Contains(sk2, `category="recon"`) {
		t.Fatalf("recon 关键词应回退命中 recon 骨架, got:\n%s", sk2)
	}
	// 完全无关的意图静默不注入。
	payload3, _ := json.Marshal(map[string]any{"summary": "随便看看"})
	if out := chainskel.ForIntent(payload3); out != "" {
		t.Fatalf("匹配不中应静默不注入, got:\n%s", out)
	}
	if out := chainskel.RefsGuideForIntent(payload3); out != "" {
		t.Fatalf("匹配不中指引行也应静默, got:\n%s", out)
	}
}
