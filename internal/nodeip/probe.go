// Package nodeip discovers the node's direct public addresses without using a
// panel egress proxy (which would identify that proxy rather than the node).
package nodeip

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	Interval   = time.Minute
	ReportPath = "/cluster/v1/node-ips"
)

type Report struct {
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	ObservedAt int64  `json:"observedAt"`
}

func PublicIP(value string, v4 bool) (string, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		return "", errors.New("invalid_public_ip")
	}
	ip = ip.Unmap()
	if ip.Is4() != v4 || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "", errors.New("invalid_public_ip")
	}
	return ip.String(), nil
}

func Probe(ctx context.Context) Report {
	var result Report
	var wg sync.WaitGroup
	for _, family := range []bool{true, false} {
		wg.Add(1)
		go func(v4 bool) {
			defer wg.Done()
			host, network := "api6.ipify.org", "tcp6"
			if v4 {
				host, network = "api.ipify.org", "tcp4"
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, 129))
			if err != nil || len(data) > 128 {
				return
			}
			ip, err := PublicIP(strings.TrimSpace(string(data)), v4)
			if err != nil {
				return
			}
			if v4 {
				result.IPv4 = ip
			} else {
				result.IPv6 = ip
			}
		}(family)
	}
	wg.Wait()
	result.ObservedAt = time.Now().UnixMilli()
	return result
}
