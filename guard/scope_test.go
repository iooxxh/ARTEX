package guard

import "testing"

func scopeRules(kv ...string) []ScopeRule {
	var out []ScopeRule
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, ScopeRule{Kind: kv[i], Value: kv[i+1]})
	}
	return out
}

func TestScopeMatcherDomain(t *testing.T) {
	m := NewScopeMatcher(scopeRules("domain", "Example.COM"))
	cases := []struct {
		host string
		want ScopeVerdict
	}{
		{"example.com", ScopeIn},
		{"EXAMPLE.COM", ScopeIn},
		{"www.example.com", ScopeIn},
		{"a.b.example.com", ScopeIn},
		{"example.com.", ScopeIn},
		{"notexample.com", ScopeOut},       // 后缀不等于子域
		{"example.com.evil.com", ScopeOut}, // 域名做前缀不算
		{"other.org", ScopeOut},
		{"example.com:8443", ScopeIn}, // host:port 去端口
	}
	for _, c := range cases {
		if got := m.Check(c.host); got != c.want {
			t.Errorf("Check(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestScopeMatcherIP(t *testing.T) {
	m := NewScopeMatcher(scopeRules("ip", "10.0.0.5", "ip", "2001:db8::1"))
	for _, c := range []struct {
		host string
		want ScopeVerdict
	}{
		{"10.0.0.5", ScopeIn},
		{"10.0.0.5:8080", ScopeIn},
		{"10.0.0.6", ScopeOut},
		{"2001:db8::1", ScopeIn},
		{"[2001:db8::1]:443", ScopeIn},
		{"2001:db8::2", ScopeOut},
	} {
		if got := m.Check(c.host); got != c.want {
			t.Errorf("Check(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestScopeMatcherCIDR(t *testing.T) {
	m := NewScopeMatcher(scopeRules("cidr", "192.168.1.0/24", "cidr", "2001:db8::/32"))
	for _, c := range []struct {
		host string
		want ScopeVerdict
	}{
		{"192.168.1.1", ScopeIn},
		{"192.168.1.254", ScopeIn},
		{"192.168.2.1", ScopeOut},
		{"2001:db8::abcd", ScopeIn},
		{"2001:db9::1", ScopeOut},
	} {
		if got := m.Check(c.host); got != c.want {
			t.Errorf("Check(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestScopeMatcherKeywordDead(t *testing.T) {
	// keyword 是死规则:不参与匹配,有 keyword 也算无规则 → Unknown。
	m := NewScopeMatcher(scopeRules("keyword", "anything"))
	if got := m.Check("anything.example.com"); got != ScopeUnknown {
		t.Errorf("keyword 规则应死, got %v", got)
	}
}

func TestScopeMatcherBadRules(t *testing.T) {
	m := NewScopeMatcher(scopeRules("cidr", "not-a-cidr", "domain", "", "ip", "999.1.1.1"))
	if got := m.Check("10.0.0.1"); got != ScopeUnknown {
		t.Errorf("全非法规则应得 Unknown, got %v", got)
	}
}

func TestScopeMatcherEmptyRulesUnknown(t *testing.T) {
	m := NewScopeMatcher(nil)
	for _, h := range []string{"example.com", "10.0.0.1"} {
		if got := m.Check(h); got != ScopeUnknown {
			t.Errorf("空规则 Check(%q) = %v, want Unknown", h, got)
		}
	}
}

func TestScopeMatcherLocalAllow(t *testing.T) {
	m := NewScopeMatcher(scopeRules("domain", "example.com"))
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if got := m.Check(h); got != ScopeIn {
			t.Errorf("本机 %q 应放行, got %v", h, got)
		}
	}
	// RFC1918 内网地址不在放行之列。
	if got := m.Check("192.168.0.1"); got != ScopeOut {
		t.Errorf("内网 192.168.0.1 应 Out, got %v", got)
	}
	m.AllowLocal = false
	if got := m.Check("127.0.0.1"); got != ScopeOut {
		t.Errorf("关掉 AllowLocal 后 127.0.0.1 应 Out, got %v", got)
	}
}
