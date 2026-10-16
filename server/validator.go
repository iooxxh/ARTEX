// validator.go 是确定性验证层（Phase 3）在 server 侧的支撑逻辑：
//
//   - validatorOnline()：验证服务健康检查（GET /health），结果缓存 60 秒；
//   - 人工复核队列（GET /api/exploration/findings 分页分支）默认只展示
//     verify_status 为 verified/inconclusive 的 finding；验证服务离线时降级为
//     展示全部，并在响应里打标 validator_online=false 供前端展示。
package server

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// validatorBaseURL 返回验证服务地址：环境变量 VALIDATOR_URL，缺省 http://localhost:8080。
func validatorBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("VALIDATOR_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

var (
	validatorHealthMu     sync.Mutex
	validatorHealthCached bool
	validatorHealthAt     time.Time
)

const validatorHealthTTL = 60 * time.Second

// validatorOnline 检查验证服务是否在线（GET /health，2s 超时），结果缓存 60 秒。
func validatorOnline() bool {
	validatorHealthMu.Lock()
	if time.Since(validatorHealthAt) < validatorHealthTTL {
		ok := validatorHealthCached
		validatorHealthMu.Unlock()
		return ok
	}
	validatorHealthMu.Unlock()

	ok := checkValidatorHealth()

	validatorHealthMu.Lock()
	validatorHealthCached, validatorHealthAt = ok, time.Now()
	validatorHealthMu.Unlock()
	return ok
}

func checkValidatorHealth() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validatorBaseURL()+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
