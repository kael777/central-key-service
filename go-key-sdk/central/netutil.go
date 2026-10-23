package central

import (
	"fmt"
	"net"
	"strings"
)

// ValidHostSpec 驗證白名單項目：單一 IP 或 CIDR。
func ValidHostSpec(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("空白")
	}
	if s == "0.0.0.0/0" || s == "::/0" {
		return fmt.Errorf("不允許 0.0.0.0/0 或 ::/0")
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("非法 IP：%s", s)
	}
	return nil
}

// HostAllowed 判斷來源是否在白名單內；空清單代表不限制。
// remote 可帶埠號（如 10.0.0.1:52314）。
func HostAllowed(allow []string, remote string) bool {
	if len(allow) == 0 {
		return true
	}
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, spec := range allow {
		spec = strings.TrimSpace(spec)
		if strings.Contains(spec, "/") {
			_, n, err := net.ParseCIDR(spec)
			if err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if net.ParseIP(spec) != nil && net.ParseIP(spec).Equal(ip) {
			return true
		}
	}
	return false
}
