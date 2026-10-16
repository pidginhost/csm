package hostfacts

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	canaryTimeout = 5 * time.Second
	maxCanaryBody = 64 << 10
	// canaryMessage is the smallest message rspamd scans.
	canaryMessage = "From: <canary@csm.invalid>\r\nSubject: csm canary\r\n\r\ncanary\r\n"
)

// Canary scans one message from the canary address with only the CSM_IP
// rule enabled and returns the generation its CSM_IP_CANARY option names
// ("" when the symbol is absent). no_log and no_stat keep the scan out of
// rspamd's history and statistics (spec 8.4). Errors never repeat the reply.
func Canary(ctx context.Context, socket string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, canaryTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	req := "POST /checkv2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" +
		"IP: 192.0.2.255\r\nSettings: {symbols_enabled = [\"CSM_IP\"]}\r\nFlags: no_log,no_stat\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(canaryMessage)) + canaryMessage
	if _, err = io.WriteString(conn, req); err != nil {
		return "", err
	}
	reply := &io.LimitedReader{R: conn, N: 2*maxCanaryBody + 1}
	resp, err := http.ReadResponse(bufio.NewReader(reply), nil)
	if err != nil {
		return "", errors.New("rspamd /checkv2 returned an invalid HTTP response")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rspamd /checkv2 returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCanaryBody+1))
	if err != nil || len(body) > maxCanaryBody {
		return "", errors.New("rspamd /checkv2 reply could not be read")
	}
	var result struct {
		Symbols map[string]struct {
			Options []string `json:"options"`
		} `json:"symbols"`
	}
	if json.Unmarshal(body, &result) != nil {
		return "", errors.New("rspamd /checkv2 reply is not JSON")
	}
	for _, o := range result.Symbols["CSM_IP_CANARY"].Options {
		if gen, ok := strings.CutPrefix(o, "g"); ok {
			return gen, nil
		}
	}
	return "", nil
}
