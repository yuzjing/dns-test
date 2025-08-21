package main

import (
        "bytes"
        "crypto/tls"
        "flag"
        "fmt"
        "io"
        "net"
        "net/http"
        "sort"
        "strings"
        "sync"
        "time"

        "github.com/miekg/dns"
)

type DNSServer struct {
        Name string
        DoT  []string
        DoH  []string
        IPv4 []string
        IPv6 []string
}
type Result struct {
        ServerName string
        TestType   string
        Address    string
        Duration   time.Duration
        Error      error
}

var (
        dnsServers = []DNSServer{
                {Name: "Google", DoT: []string{"dns.google:853"}, DoH: []string{"https://dns.google/dns-query"}, IPv4: []string{"8.8.8.8", "8.8.4.4"}, IPv6: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"}},
                {Name: "Cloudflare", DoT: []string{"one.one.one.one:853"}, DoH: []string{"https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query"}, IPv4: []string{"1.1.1.1", "1.0.0.1"}, IPv6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}},
                {Name: "Quad9", DoT: []string{"dns.quad9.net:853"}, DoH: []string{"https://dns.quad9.net/dns-query"}, IPv4: []string{"9.9.9.9", "149.112.112.112"}, IPv6: []string{"2620:fe::fe", "2620:fe::9"}},
                {Name: "OpenDNS", DoT: []string{"dns.opendns.com:853"}, DoH: []string{"https://doh.opendns.com/dns-query"}, IPv4: []string{"208.67.222.222", "208.67.220.220"}, IPv6: []string{"2620:119:35::35", "2620:119:53::53"}},
                {Name: "AdGuard", DoT: []string{"dns.adguard.com:853"}, DoH: []string{"https://dns.adguard.com/dns-query"}, IPv4: []string{"94.140.14.14", "94.140.15.15"}, IPv6: []string{"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}},
                {Name: "NextDNS", DoT: []string{"dns.nextdns.io:853"}, DoH: []string{"https://dns.nextdns.io"}, IPv4: []string{"45.90.28.232", "45.90.30.232"}, IPv6: []string{"2a07:a8c0::b1:c4a3", "2a07:a8c1::b1:c4a3"}},
                {Name: "CleanBrowsing", DoT: []string{"security-filter-dns.cleanbrowsing.org:853"}, DoH: []string{"https://doh.cleanbrowsing.org/doh/security-filter"}, IPv4: []string{"185.228.168.9", "185.228.169.9"}, IPv6: []string{"2a0d:2a00:1::2", "2a0d:2a00:2::2"}},
                {Name: "AliDNS (阿里DNS)", DoT: []string{"dns.alidns.com:853"}, DoH: []string{"https://dns.alidns.com/dns-query"}, IPv4: []string{"223.5.5.5", "223.6.6.6"}, IPv6: []string{"2400:3200::1", "2400:3200:baba::1"}},
                {Name: "DNSPod", DoT: []string{"dot.pub:853"}, DoH: []string{"https://doh.pub/dns-query"}, IPv4: []string{"119.29.29.29", "182.254.116.116"}, IPv6: []string{"2402:4e00::", "2402:4e00:1::"}},
        }
        domesticDomains      = []string{"baidu.com", "qq.com", "taobao.com", "jd.com", "weibo.com", "163.com", "bilibili.com", "douban.com", "zhihu.com"}
        internationalDomains = []string{"google.com", "github.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com", "www.microsoft.com"}
        timeout              = 5 * time.Second

        dotConnections = make(map[string]*dns.Conn)
        dotConnMutex   = &sync.Mutex{}
)

func main() {
        count := flag.Int("count", 10, "每个网站的测试次数")
        delay := flag.Int("delay", 50, "每次查询之间的延迟时间(毫秒)")
        flag.Parse()
        fmt.Printf("DNS 速度测试开始 (每个域名测试 %d 次, 查询间隔 %dms, 超时 %v)\n", *count, *delay, timeout)
        fmt.Printf("\n==================== 国内网站测试 ====================\n")
        testDomains(domesticDomains, *count, time.Duration(*delay)*time.Millisecond)
        fmt.Printf("\n==================== 国外网站测试 ====================\n")
        testDomains(internationalDomains, *count, time.Duration(*delay)*time.Millisecond)
        fmt.Printf("\n======================= 测试完成 =======================\n")
}

func testDomains(domains []string, count int, delay time.Duration) {
        results := make(chan Result)
        var wg sync.WaitGroup
        for _, server := range dnsServers {
                for _, domain := range domains {
                        for i := 0; i < count; i++ {
                                for _, ip := range server.IPv4 {
                                        wg.Add(1)
                                        go testUDP(server.Name, ip, domain, dns.TypeA, results, &wg)
                                        time.Sleep(delay)
                                }
                                for _, ip := range server.IPv6 {
                                        wg.Add(1)
                                        go testUDP(server.Name, ip, domain, dns.TypeAAAA, results, &wg)
                                        time.Sleep(delay)
                                }
                                for _, dotAddr := range server.DoT {
                                        wg.Add(1)
                                        go testDoT(server.Name, dotAddr, domain, results, &wg)
                                        time.Sleep(delay)
                                }
                                for _, dohURL := range server.DoH {
                                        wg.Add(1)
                                        go testDoH(server.Name, dohURL, domain, results, &wg)
                                        time.Sleep(delay)
                                }
                        }
                }
        }
        go func() {
                wg.Wait()
                close(results)
        }()
        processResults(results)
}

func testUDP(serverName, serverIP, domain string, recordType uint16, results chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        testType := "UDP_IPv4"
        if recordType == dns.TypeAAAA {
                testType = "UDP_IPv6"
        }
        m := new(dns.Msg)
        m.SetQuestion(dns.Fqdn(domain), recordType)
        m.RecursionDesired = true
        c := new(dns.Client)
        c.Timeout = timeout
        start := time.Now()
        _, _, err := c.Exchange(m, net.JoinHostPort(serverIP, "53"))
        duration := time.Since(start)
        results <- Result{serverName, testType, serverIP, duration, err}
}

func testDoT(serverName, serverAddr, domain string, results chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        dotConnMutex.Lock()
        conn, ok := dotConnections[serverAddr]
        if ok && conn.Conn == nil {
                delete(dotConnections, serverAddr)
                ok = false
        }
        dotConnMutex.Unlock()
        if !ok {
                host := strings.Split(serverAddr, ":")[0]
                dialer := &tls.Dialer{
                        Config: &tls.Config{InsecureSkipVerify: false, ServerName: host},
                }
                newConn, err := dialer.Dial("tcp", serverAddr)
                if err != nil {
                        results <- Result{serverName, "DoT", serverAddr, 0, err}
                        return
                }
                conn = &dns.Conn{Conn: newConn}
                dotConnMutex.Lock()
                dotConnections[serverAddr] = conn
                dotConnMutex.Unlock()
        }
        m := new(dns.Msg)
        m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
        m.RecursionDesired = true
        c := new(dns.Client)
        c.Timeout = timeout
        start := time.Now()
        _, _, err := c.ExchangeWithConn(m, conn)
        duration := time.Since(start)
        if err != nil {
                conn.Close()
                dotConnMutex.Lock()
                delete(dotConnections, serverAddr)
                dotConnMutex.Unlock()
        }
        results <- Result{serverName, "DoT", serverAddr, duration, err}
}

func testDoH(serverName, serverURL, domain string, results chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        m := new(dns.Msg)
        m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
        m.RecursionDesired = true
        packedMsg, err := m.Pack()
        if err != nil {
                results <- Result{serverName, "DoH", serverURL, 0, err}
                return
        }
        req, err := http.NewRequest("POST", serverURL, bytes.NewReader(packedMsg))
        if err != nil {
                results <- Result{serverName, "DoH", serverURL, 0, err}
                return
        }
        req.Header.Set("Content-Type", "application/dns-message")
        client := &http.Client{Timeout: timeout}
        start := time.Now()
        resp, err := client.Do(req)
        duration := time.Since(start)
        if err != nil {
                results <- Result{serverName, "DoH", serverURL, duration, err}
                return
        }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK {
                err = fmt.Errorf("HTTP status %d", resp.StatusCode)
                results <- Result{serverName, "DoH", serverURL, duration, err}
                return
        }
        _, err = io.ReadAll(resp.Body)
        if err != nil {
                results <- Result{serverName, "DoH", serverURL, duration, err}
                return
        }
        results <- Result{serverName, "DoH", serverURL, duration, nil}
}

// processResults - Final version with unconditional success ratio display.
func processResults(results <-chan Result) {
        type resultSummary struct {
                ServerName   string
                TestType     string
                SuccessCount int
                FailureCount int
                Durations    []time.Duration
                Errors       []error
        }
        summary := make(map[string]*resultSummary)
        for res := range results {
                if _, ok := summary[res.Address]; !ok {
                        summary[res.Address] = &resultSummary{ServerName: res.ServerName, TestType: res.TestType}
                }
                if res.Error != nil {
                        summary[res.Address].FailureCount++
                        summary[res.Address].Errors = append(summary[res.Address].Errors, res.Error)
                } else {
                        summary[res.Address].SuccessCount++
                        summary[res.Address].Durations = append(summary[res.Address].Durations, res.Duration)
                }
        }

        type finalResult struct {
                DisplayName string
                AvgTime     time.Duration
                IsFailure   bool
                ErrorMsg    string
        }
        finalResults := make(map[string][]finalResult)

        for key, data := range summary {
                rankingKey := data.TestType
                if rankingKey == "UDP_IPv4" || rankingKey == "UDP_IPv6" {
                        rankingKey = "UDP"
                }

                baseDisplayName := ""
                switch data.TestType {
                case "UDP_IPv4", "UDP_IPv6":
                        baseDisplayName = fmt.Sprintf("%s (%s)", data.ServerName, key)
                case "DoT":
                        baseDisplayName = fmt.Sprintf("%s (DoT: %s)", data.ServerName, key)
                case "DoH":
                        host := strings.Split(strings.TrimPrefix(key, "https://"), "/")[0]
                        baseDisplayName = fmt.Sprintf("%s (DoH: %s)", data.ServerName, host)
                }

                // THE FINAL FIX: Unconditionally create the display name with the ratio.
                totalRequests := data.SuccessCount + data.FailureCount
                finalDisplayName := baseDisplayName
                if totalRequests > 0 {
                        finalDisplayName = fmt.Sprintf("%s (%d/%d succ)", baseDisplayName, data.SuccessCount, totalRequests)
                }

                fr := finalResult{DisplayName: finalDisplayName}

                if data.SuccessCount > 0 {
                        var total time.Duration
                        for _, d := range data.Durations {
                                total += d
                        }
                        fr.AvgTime = total / time.Duration(data.SuccessCount)
                } else if data.FailureCount > 0 {
                        fr.IsFailure = true
                        firstError := data.Errors[0]
                        if netErr, ok := firstError.(net.Error); ok && netErr.Timeout() {
                                fr.ErrorMsg = "[Error: i/o timeout]"
                        } else {
                                fr.ErrorMsg = fmt.Sprintf("[Error: %s]", firstError.Error())
                        }
                }

                finalResults[rankingKey] = append(finalResults[rankingKey], fr)
        }

        testOrder := []string{"UDP", "DoT", "DoH"}
        titleMap := map[string]string{"UDP": "Standard DNS (UDP) IPv4 & IPv6", "DoT": "DNS over TLS (DoT)", "DoH": "DNS over HTTPS (DoH)"}

        for _, testType := range testOrder {
                res, ok := finalResults[testType]
                if !ok || len(res) == 0 {
                        continue
                }
                fmt.Printf("\n--- %s 平均响应时间排名 ---\n", titleMap[testType])
                sort.Slice(res, func(i, j int) bool {
                        if res[i].IsFailure != res[j].IsFailure {
                                return res[j].IsFailure
                        }
                        if res[i].IsFailure {
                                return false
                        }
                        return res[i].AvgTime < res[j].AvgTime
                })
                for i, r := range res {
                        // Adjust padding for the longer display name
                        if r.IsFailure {
                                fmt.Printf("%2d. %-58s: %s\n", i+1, r.DisplayName, r.ErrorMsg)
                        } else {
                                fmt.Printf("%2d. %-58s: %.2f ms\n", i+1, r.DisplayName, float64(r.AvgTime.Nanoseconds())/1e6)
                        }
                }
        }
}
