// loadtest：對中央服務的 /api/v1/sync 做簡單壓測（mTLS）。
// 用法：go run ./cmd/loadtest -base https://127.0.0.1:8443 -certs ./certs -system SYS-A -rps 10 -duration 20s
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	base := flag.String("base", "https://127.0.0.1:8443", "中央服務位址（可用逗號分隔多個）")
	certs := flag.String("certs", "certs", "憑證目錄（內含 clients/<code>.crt/.key 與 ca.crt）")
	system := flag.String("system", "SYS-A", "系統代碼")
	rps := flag.Int("rps", 10, "每秒請求數")
	duration := flag.Duration("duration", 20*time.Second, "持續時間")
	workers := flag.Int("workers", 4, "併發 worker 數")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(fmt.Sprintf("%s/clients/%s.crt", *certs, *system), fmt.Sprintf("%s/clients/%s.key", *certs, *system))
	if err != nil {
		fmt.Fprintf(os.Stderr, "載入憑證失敗：%v\n", err)
		os.Exit(1)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if pem, err := os.ReadFile(*certs + "/ca.crt"); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(pem) {
			tlsCfg.RootCAs = pool
		}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, MaxIdleConnsPerHost: *workers},
	}

	bases := strings.Split(*base, ",")
	var rr atomic.Uint64
	jobs := make(chan struct{}, 1024)
	var ok, failed atomic.Int64
	var muErr sync.Mutex
	var firstErr error
	var mu sync.Mutex
	lat := make([]time.Duration, 0, *rps*int(duration.Seconds())+16)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				start := time.Now()
				target := strings.TrimSpace(bases[int(rr.Add(1))%len(bases)])
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target+"/api/v1/sync", nil)
				resp, err := client.Do(req)
				d := time.Since(start)
				if err != nil || resp.StatusCode != http.StatusOK {
					failed.Add(1)
					muErr.Lock()
					if firstErr == nil {
						if err != nil {
							firstErr = err
						} else {
							firstErr = fmt.Errorf("HTTP %d", resp.StatusCode)
						}
					}
					muErr.Unlock()
					if resp != nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				ok.Add(1)
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}()
	}

	interval := time.Second / time.Duration(*rps)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.After(*duration)
loop:
	for {
		select {
		case <-deadline:
			break loop
		case <-ticker.C:
			select {
			case jobs <- struct{}{}:
			default:
			}
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		idx := int(float64(len(lat)-1) * q)
		return lat[idx]
	}
	fmt.Printf("請求 %d，成功 %d，失敗 %d\n", ok.Load()+failed.Load(), ok.Load(), failed.Load())
	fmt.Printf("延遲 p50=%s p95=%s p99=%s max=%s\n",
		p(0.50).Round(time.Microsecond), p(0.95).Round(time.Microsecond),
		p(0.99).Round(time.Microsecond), p(1.0).Round(time.Microsecond))
	fmt.Printf("實際 RPS=%.1f\n", float64(ok.Load())/duration.Seconds())
	if firstErr != nil {
		fmt.Printf("首個錯誤：%v\n", firstErr)
	}
}
