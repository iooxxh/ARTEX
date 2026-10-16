package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

func truncateReply(s string) string {
	const max = 200
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

type createTaskReq struct {
	Name                 string   `json:"name,omitempty"` // 可选任务名称;省略/空=未命名
	CategoryID           *int64   `json:"category_id,omitempty"`
	Description          string   `json:"description"`
	Goal                 string   `json:"goal"`
	LLMProfileID         *int64   `json:"llm_profile_id,omitempty"`    // 指定运行本任务的 LLM 配置;省略/null=用激活配置
	LLMProfileIDs        []int64  `json:"llm_profile_ids,omitempty"`   // 有序任务级配置链;第一项初始生效
	SourceTaskIDs        []string `json:"source_task_ids,omitempty"`   // 仅直接、只读继承的来源任务
	CompanyIDs           []int64  `json:"company_ids,omitempty"`       // 关联企业范围并快照关联当前企业资产;不复制资产或强制生成意图
	TimeoutSeconds       int      `json:"timeout_seconds"`             // 任务级超时(秒);0/省略=不限时
	PlanHeartbeatSeconds int      `json:"plan_heartbeat_seconds"`      // planner 心跳触发间隔(秒);0/省略=默认600(10min);下限=默认=600,低于自动抬到600
	SeedFirstIntent      *bool    `json:"seed_first_intent,omitempty"` // 创建时直接下发一条种子意图(内容=描述+目标),让 worker 免等首轮 planner 直接开跑;省略/null=默认关闭,走标准先规划再执行。显式传 true 才开(CTF 常一 work 解决时可省掉开跑前的 planner 轮)。
	CoverageEnabled      *bool    `json:"coverage_enabled,omitempty"`  // 资产覆盖度功能;省略/null=默认开(true)。false=关闭覆盖度计算/展示/自动累积范围+隐藏 add_task_scope/list_untested_assets。company 关联不受影响。
	// InterceptRules 任务级资产拦截/允许规则(创建时录入,存 task_intercept_rules,不进全局表)。
	InterceptRules []taskInterceptRuleReq `json:"intercept_rules,omitempty"`
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	if s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "任务正在删除，无法发送新消息")
		return
	}
	// 注意:任务暂停(paused)不拦截主 Agent 对话。主 Agent 编排会话独立于 planner/
	// worker 的暂停,暂停中仍可继续对话(暂停只终止其正在进行的那一轮,见 control())。
	var req struct {
		Message     string           `json:"message"`
		Attachments []chatAttachment `json:"attachments,omitempty"` // 方式1 上传的文件(路径相对任务工作目录)
		Seg         *int             `json:"seg,omitempty"`         // 目标主会话分段;缺省=最新段
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	agentMessage, ok := s.prepareChatMentionMessage(w, req.Message)
	if !ok {
		return
	}
	// Admission is serialized with deletion's chat cancellation. Mark every chat
	// turn busy before its first activity/file write, including rule-mode turns.
	// If deletion wins the race, the second barrier check rejects this request.
	s.chatMu.Lock()
	if s.engine.IsDeleting(t.ID) {
		s.chatMu.Unlock()
		writeErr(w, 409, "任务正在删除，无法发送新消息")
		return
	}
	if s.chatBusy[t.ID] {
		s.chatMu.Unlock()
		writeErr(w, 409, "主 Agent 正在处理上一条消息，请稍候")
		return
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	ctx = intercept.WithReviewContext(ctx, "", intercept.ReviewBackground{Source: intercept.BackgroundUserMessage, Text: req.Message})
	s.chatBusy[t.ID] = true
	s.chatCancel[t.ID] = cancel
	s.chatMu.Unlock()

	// The turn belongs to whichever main-agent segment the user is chatting in (any
	// segment is interactive, like the top-level chat conversations). Stamp every
	// mainagent row with it so this turn's transcript + activity land in that segment.
	// Missing seg (older clients) falls back to the newest segment.
	mainSeg := 0
	if req.Seg != nil && *req.Seg >= 0 {
		mainSeg = *req.Seg
	} else {
		mainSeg, _ = t.Store.CurrentMainSeg()
	}
	segPtr := &mainSeg

	// Persist + broadcast the human turn so the 主 Agent 编排会话 survives page
	// reloads and updates live: the conversation lives in the activity stream as
	// worker="mainagent" (the per-task activity table, replayed via SSE). With
	// attachments, the activity's Detail carries {text, attachments} so the transcript
	// renders attachment cards.
	humanTurn := userActivityWithAttachments("mainagent", req.Message, req.Attachments)
	humanTurn.MainSeg = segPtr
	s.engine.emitActivity(t, humanTurn)
	var ma *agent.MainAgent
	if s.taskRuntimeAvailable(t, "mainagent") {
		ma = s.agentsForTask(t).main
	}
	if ma != nil {
		// Run the agent on a per-turn cancellable ctx (NOT r.Context()): the turn can
		// take minutes (multi-tool loop), and binding it to the request lifecycle meant
		// a page reload / proxy timeout cancelled it mid-run ("context canceled"). The
		// steps + final answer stream back live via SSE (worker="mainagent"), so the
		// handler returns immediately and the browser never needs to hold the request.
		go func() {
			defer func() {
				s.finishTaskChat(t.ID, cancel)
			}()
			// emit every step (thinking/tool_use/tool_result/text/result) so the main
			// agent session shows its work live, like worker/planner. The final answer
			// is the captured "result" step — no separate reply emit (would duplicate).
			emit := func(rec db.Activity) {
				rec.MainSeg = segPtr
				s.engine.emitActivity(t, rec)
			}
			maTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
			resume := func() { s.reviveTask(t) } // set_goals 新增目标 → 把任务拉回 running
			// 把上传附件的【绝对路径】清单拼进发给 agent 的消息,它据此用 Read/Bash 打开文件。
			// taskDir = agent 的工作目录(CWD),与 chatUpload 落盘、ensureRunDir 一致。
			taskDir := filepath.Join(s.m.dir, "tasks", t.ID)
			agentMsg := composeAgentMessage(agentMessage, req.Attachments, taskDir)
			s.engine.BeginLLMCall(t.ID)
			_, err := ma.Chat(ctx, maTaskID, mainSeg, s.m.Assets(), t.Store, t.Goal, agentMsg, emit, t.Notify, resume, t.NotifyGoal, t.NotifyHint)
			s.engine.EndLLMCall(t.ID)
			if err != nil && ctx.Err() == nil {
				s.engine.emitActivity(t, db.Activity{Worker: "mainagent", Kind: "text", IsError: true, Summary: "（主 Agent 出错：" + err.Error() + "）", MainSeg: segPtr})
			}
		}()
		writeJSON(w, 202, map[string]any{"status": "accepted", "mode": "llm"})
		return
	}
	reply := s.fallbackChat(t, req.Message)
	s.engine.emitActivity(t, db.Activity{Worker: "mainagent", Kind: "text", Summary: reply, MainSeg: segPtr})
	s.finishTaskChat(t.ID, cancel)
	writeJSON(w, 200, map[string]any{"reply": reply, "mode": "rule"})
}
