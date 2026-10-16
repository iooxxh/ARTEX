package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) settingsPayload() map[string]any {
	on, backend, braveKey, tavilyKey, proxy := s.m.WebSearch()
	pyStored, _, _ := s.m.pg.GetSetting(settingPythonInterp)
	concOn, concLimit := s.m.ConcurrencyLimit()
	if concLimit == 0 {
		concLimit = defaultConcurrencyLimit // 关闭时也回显一个合理默认值给 UI
	}
	return map[string]any{
		"traffic_capture":          s.m.TrafficEnabled(),
		"agent_traffic_binding":    s.m.pg.GetBool(settingAgentTrafficBinding, false),
		"llm_record":               s.m.LLMRecordEnabled(),
		"web_search_enabled":       on,
		"web_search_backend":       backend,
		"brave_key_set":            strings.TrimSpace(braveKey) != "",
		"tavily_key_set":           strings.TrimSpace(tavilyKey) != "",
		"web_search_proxy":         proxy,                       // 独立出口代理(http/https/socks5)，空=直连
		"global_proxy":             s.m.GlobalProxy(),           // 全局出口代理(http/https/socks5)，所有目标流量走它，空=直连
		"python_interpreter":       strings.TrimSpace(pyStored), // 用户/自动设的值(空=用运行时检测)
		"workers":                  s.m.Workers(),               // 并发工作 agent 数(默认3)；对之后启动的任务生效
		"task_concurrency_enabled": concOn,                      // 任务并发上限开关(默认关)
		"task_concurrency_limit":   concLimit,                   // 同时运行任务上限(开启后默认5)
		// LLM 轮询(故障转移)。默认关；开启后走全局激活配置的 agent 在当前配置不可用时
		// 自动切到下一个配置。bind_fallback 仅在轮询开启时有意义(默认关)。
		"llm_pool_enabled":       s.m.LLMPoolEnabled(),
		"llm_pool_bind_fallback": s.m.LLMPoolBindFallback(),
		// 操作约束注入范围(默认都开):把本任务的 allow/deny 约束拼进对应 agent 的系统提示。
		"constraints_inject_planner": s.constraintInjectPlanner(),
		"constraints_inject_worker":  s.constraintInjectWorker(),
		// 实验功能:noa 模型驱动上下文压缩(默认关)。开启后平台接入的四类 agent 由 noa
		// 接管上下文压缩,取代内置 compaction;每 run 读一次,对之后启动的 run 生效。
		"noa_compaction": s.m.NoaCompactionEnabled(),
		// 漏洞 IM 推送的全局项。渠道本身是独立资源，走 /api/notify/* 管理；
		// 这里只放「作用于全部渠道」的三项。
		"notify_enabled":             s.m.pg.GetBool(settingNotifyEnabled, true),
		"notify_public_base_url":     notifyPublicBaseURL(s.m.pg),
		"notify_digest_interval_min": notifyDigestIntervalMin(s.m.pg),
	}
}

// notifyPublicBaseURL 读推送回链用的外部地址。
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TrafficCapture      *bool `json:"traffic_capture"`
		AgentTrafficBinding *bool `json:"agent_traffic_binding"`
		LLMRecord           *bool `json:"llm_record"` // LLM 录制开关（默认关）；即时生效，无需重建 agent
		// Web search. WebSearchEnabled/Backend toggle the tool + backend; BraveKey/TavilyKey
		// are optional — omit (null) to leave a stored key untouched, send "" to clear.
		WebSearchEnabled *bool   `json:"web_search_enabled"`
		WebSearchBackend *string `json:"web_search_backend"`
		BraveKey         *string `json:"brave_search_api_key"`
		TavilyKey        *string `json:"tavily_search_api_key"`
		WebSearchProxy   *string `json:"web_search_proxy"`   // 独立出口代理(http/https/socks5)；null=不改，""=清空
		GlobalProxy      *string `json:"global_proxy"`       // 全局出口代理(http/https/socks5)；null=不改，""=清空(直连)
		PythonInterp     *string `json:"python_interpreter"` // 自定义脚本工具的 python 解释器路径
		Workers          *int    `json:"workers"`            // 并发工作 agent 数(>0)；对之后启动的任务生效
		// 任务并发上限:同时「运行中」的任务数上限。关闭=不限;开启后新建任务超限则排队,有空位自动启动。
		ConcurrencyEnabled *bool `json:"task_concurrency_enabled"`
		ConcurrencyLimit   *int  `json:"task_concurrency_limit"`
		// LLM 轮询(故障转移)开关 + 「绑定配置失败也兜底回轮询链」开关。两者都需要
		// 重建 provider 链才生效，走下面的 changed → applyLLM 路径。
		LLMPoolEnabled      *bool `json:"llm_pool_enabled"`
		LLMPoolBindFallback *bool `json:"llm_pool_bind_fallback"`
		// 操作约束注入范围开关(默认都开);即时生效(planner/worker 每轮读),无需重建 agent。
		ConstraintsInjectPlanner *bool `json:"constraints_inject_planner"`
		ConstraintsInjectWorker  *bool `json:"constraints_inject_worker"`
		// 实验功能:noa 上下文压缩开关(默认关);每 run 读,对之后启动的 run 生效,无需重建 agent。
		NoaCompaction *bool `json:"noa_compaction"`
		// 漏洞 IM 推送的全局项。三者都由投递引擎每轮读一次，改完即时生效，
		// 不需要重建 agent 或重启。
		NotifyEnabled    *bool   `json:"notify_enabled"`
		NotifyBaseURL    *string `json:"notify_public_base_url"`
		NotifyDigestMins *int    `json:"notify_digest_interval_min"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.ConstraintsInjectPlanner != nil {
		if err := s.m.pg.SetBool(settingConstraintsInjectPlanner, *req.ConstraintsInjectPlanner); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.ConstraintsInjectWorker != nil {
		if err := s.m.pg.SetBool(settingConstraintsInjectWorker, *req.ConstraintsInjectWorker); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.NoaCompaction != nil {
		// 每 run 读的解析器,切换即时对之后启动的 run 生效,无需 applyLLM 重建。
		if err := s.m.SetNoaCompaction(*req.NoaCompaction); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	// 推送全局项:投递引擎每轮重新读取,所以即时生效、无需重启。
	if req.NotifyEnabled != nil {
		if err := s.m.pg.SetBool(settingNotifyEnabled, *req.NotifyEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.NotifyBaseURL != nil {
		// 统一裁掉尾部斜杠:回链拼接用的是 fmt.Sprintf("%s/function/..."),
		// 留着尾部斜杠会产出 "//function/..." 这种双斜杠路径。
		base := trimTrailingSlash(strings.TrimSpace(*req.NotifyBaseURL))
		if base != "" && !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			writeErr(w, 400, "回链地址需以 http:// 或 https:// 开头")
			return
		}
		if err := s.m.pg.SetSetting(settingNotifyPublicBaseURL, base); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.NotifyDigestMins != nil {
		// 下限 1 分钟:更短的周期等于实时推送,那样应该直接把渠道改成 realtime 模式。
		if *req.NotifyDigestMins < 1 || *req.NotifyDigestMins > 24*60 {
			writeErr(w, 400, "汇总周期需在 1 到 1440 分钟之间")
			return
		}
		if err := s.m.pg.SetSetting(settingNotifyDigestMinutes, strconv.Itoa(*req.NotifyDigestMins)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.Workers != nil {
		if err := s.m.SetWorkers(*req.Workers); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if req.ConcurrencyEnabled != nil || req.ConcurrencyLimit != nil {
		// 部分 PUT:未给的字段用当前值兜底,避免只改一个把另一个重置。
		curOn, curLimit := s.m.ConcurrencyLimit()
		if curLimit == 0 {
			curLimit = defaultConcurrencyLimit
		}
		on, limit := curOn, curLimit
		if req.ConcurrencyEnabled != nil {
			on = *req.ConcurrencyEnabled
		}
		if req.ConcurrencyLimit != nil {
			limit = *req.ConcurrencyLimit
		}
		if err := s.m.SetConcurrency(on, limit); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		// 立即协调一次:关闭时放行全部排队,调高上限时补位启动,不必等下一个 tick。
		go s.reconcileConcurrency()
	}
	if req.PythonInterp != nil {
		if err := s.m.pg.SetSetting(settingPythonInterp, strings.TrimSpace(*req.PythonInterp)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.LLMRecord != nil {
		// 录制器每次调用读取该标志，切换即时生效，无需 applyLLM 重建。
		if err := s.m.SetLLMRecordEnabled(*req.LLMRecord); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	changed := false
	if req.LLMPoolEnabled != nil {
		if err := s.m.SetLLMPoolEnabled(*req.LLMPoolEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true // the provider chain itself changes shape → rebuild
	}
	if req.LLMPoolBindFallback != nil {
		if err := s.m.SetLLMPoolBindFallback(*req.LLMPoolBindFallback); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true
	}
	if req.LLMPoolEnabled != nil || req.LLMPoolBindFallback != nil {
		// Pinned tasks' planner/worker and per-profile chat agents hold providers
		// built under the OLD switch state — drop them so they pick up the new one.
		s.invalidateProfileAgents()
	}
	if req.AgentTrafficBinding != nil {
		if err := s.m.pg.SetBool(settingAgentTrafficBinding, *req.AgentTrafficBinding); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if req.TrafficCapture != nil {
		if err := s.m.SetTrafficEnabled(*req.TrafficCapture); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true
	}
	if req.GlobalProxy != nil {
		// Validation failure (bad scheme/host) is a client error, not a 500.
		if err := s.m.SetGlobalProxy(*req.GlobalProxy); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		changed = true // capture-off egress is baked into agents at build time → rebuild
	}
	if req.WebSearchEnabled != nil || req.WebSearchBackend != nil || req.BraveKey != nil || req.TavilyKey != nil || req.WebSearchProxy != nil {
		// Fill unspecified fields from current state so a partial PUT doesn't reset them.
		on, backend, _, _, _ := s.m.WebSearch()
		if req.WebSearchEnabled != nil {
			on = *req.WebSearchEnabled
		}
		if req.WebSearchBackend != nil {
			backend = *req.WebSearchBackend
		}
		if err := s.m.SetWebSearch(on, backend, req.BraveKey, req.TavilyKey, req.WebSearchProxy); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = true
	}
	if changed {
		// rebuild agents so the new proxy/tools/prompt/web-search take hold (only if LLM configured).
		s.cfgMu.Lock()
		cfg, on := s.llmCfg, s.llmOn
		s.cfgMu.Unlock()
		if on {
			if err := s.applyLLM(cfg); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
		}
	}
	writeJSON(w, 200, s.settingsPayload())
}

// testWebSearch runs a real "test" search with the given (or currently saved)
// backend/proxy/key to verify the config can actually reach a search backend —
// mirroring testLLM. Backend/proxy come from the request (so the form's unsaved
// edits are tested); empty API keys fall back to stored values so the user need
// not retype them. Always 200 with {ok, error?, count?, backend?}.
