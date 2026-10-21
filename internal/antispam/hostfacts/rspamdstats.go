package hostfacts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/pidginhost/csm/internal/antispam"
)

// Reply bounds for the stats card, and how many rules it lists.
const (
	maxStatReply     = 1 << 20
	maxCountersReply = 4 << 20
	statsTopRules    = 8
)

// loopbackClient talks only to the address it is given: no proxy from the
// environment, no redirects, no connection reuse.
var loopbackClient = &http.Client{
	Timeout: controllerTimeout,
	Transport: &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// ReadRspamdStats reads /stat and /counters from the endpoint
// antispam.StatsEndpointFor chose. It never sends a password. Errors are
// fixed text; they never repeat a reply or the endpoint.
func ReadRspamdStats(ctx context.Context, ep antispam.StatsEndpoint) (antispam.RspamdStats, error) {
	if ep.Address == "" {
		return antispam.RspamdStats{}, errors.New("no rspamd controller endpoint to read")
	}
	get := func(path string, limit int64) ([]byte, error) {
		if ep.Unix {
			return ControllerGet(ctx, ep.Address, path, limit, ep.RspamdUID)
		}
		return loopbackGet(ctx, ep.Address, path, limit)
	}
	body, err := get("/stat", maxStatReply)
	if err != nil {
		return antispam.RspamdStats{}, err
	}
	stats, err := antispam.ParseRspamdStat(body)
	if err != nil {
		return antispam.RspamdStats{}, err
	}
	if body, err = get("/counters", maxCountersReply); err != nil {
		return antispam.RspamdStats{}, err
	}
	if stats.TopRules, err = antispam.ParseRspamdCounters(body, statsTopRules); err != nil {
		return antispam.RspamdStats{}, err
	}
	if stats.Version == "" {
		stats.Version = ep.Version
	}
	return stats, nil
}

// loopbackGet sends a plain GET to a loopback controller listener that
// trusts its peer address, with the same Host header ControllerDo sends.
func loopbackGet(ctx context.Context, addr, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		return nil, errors.New("invalid rspamd controller address")
	}
	req.Host = "localhost"
	resp, err := loopbackClient.Do(req)
	if err != nil {
		return nil, errors.New("cannot reach rspamd's controller")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rspamd's controller returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil:
		return nil, errors.New("rspamd's controller reply could not be read")
	case int64(len(data)) > limit:
		return nil, errors.New("rspamd's controller reply is too large")
	}
	return data, nil
}
