package checks

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Cloaking infrastructure kept in the options table.
//
// Two shapes, both from doorway kits found on one host:
//
//   - Configuration stored under a digest of the site's own hostname, so the
//     row is unfindable without knowing which site you are looking at, with a
//     base64 layer over the serialized array so its contents do not appear in
//     any search of the table.
//   - One rewrite rule per doorway cluster, routing a numbered sitemap
//     straight into a matching numbered feed, to hand crawlers the generated
//     pages without them appearing in the site's real sitemap.
//
// Neither is code execution. Both are the scaffolding a doorway network needs,
// and both survive the deletion of every spam post.

const (
	// maxCloakOptionBytes bounds one option value. Configuration blobs are
	// normally small, but rewrite_rules can exceed this on a large site. The
	// query also returns the original byte length so a bounded read can never
	// be mistaken for a complete value.
	maxCloakOptionBytes = 256 * 1024
	// maxCloakOptionRows bounds the digest-named candidates read.
	maxCloakOptionRows = 50
	// maxCloakSamplesShown bounds what the finding names.
	maxCloakSamplesShown = 10
)

// digestOptionName matches an option named by a 32-character hex digest and
// nothing else. WordPress core and plugins name options after what they hold.
var digestOptionName = regexp.MustCompile(`^[0-9a-f]{32}$`)

// numberedSitemapRoute and numberedSitemapFeed are the two halves of the
// doorway routing. Reporting needs both with the same number: real sitemap
// plugins add rewrite rules too, but none of them route sitemap<N>.xml into a
// feed named xmlsitemap<N>.
var (
	numberedSitemapRoute = regexp.MustCompile(`(?i)(?:^|\^|/)sitemap([0-9]+)\\?\.xml(?:\$|$)`)
	numberedSitemapFeed  = regexp.MustCompile(`(?i)(?:^|[?&])feed=xmlsitemap([0-9]+)(?:&|$)`)
)

// hostnameKeyedOption reports whether an option is cloak configuration keyed
// by a digest, returning the decoded size. Both halves are required: a plugin
// may hash a cache key, and base64 alone is ordinary.
func hostnameKeyedOption(name, value string) (int, bool) {
	if !digestOptionName.MatchString(strings.ToLower(name)) {
		return 0, false
	}
	decoded, ok := decodeBase64Payload(value)
	if !ok || !isPHPSerializedArray(decoded) {
		return 0, false
	}
	return len(decoded), true
}

// decodeBase64Payload decodes a stored base64 value. Kits wrap the stored text
// at arbitrary widths, so whitespace is removed before decoding, and padding is
// not always present.
func decodeBase64Payload(value string) ([]byte, bool) {
	if value == "" || len(value) > maxCloakOptionBytes {
		return nil, false
	}

	compactLen := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch c {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			continue
		}
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			compactLen++
			continue
		}
		// Reject base64url, NUL, non-ASCII, and other invalid bytes
		// before allocating a decoder-sized output buffer.
		return nil, false
	}
	if compactLen == 0 {
		return nil, false
	}
	compact := make([]byte, 0, compactLen)
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			continue
		default:
			compact = append(compact, value[i])
		}
	}

	encoding := base64.StdEncoding
	switch len(compact) % 4 {
	case 0:
		// Padded standard base64 and unpadded complete quanta both land
		// here and are accepted by StdEncoding.
	case 2, 3:
		encoding = base64.RawStdEncoding
	default:
		return nil, false
	}
	decoded := make([]byte, encoding.DecodedLen(len(compact)))
	n, err := encoding.Decode(decoded, compact)
	if err != nil {
		// Decode may have written a valid prefix. Never inspect it after an
		// error or trailing garbage could fabricate the serialized marker.
		return nil, false
	}
	return decoded[:n], true
}

type phpSerializedFrame struct {
	remaining int
	closing   byte
	hasKeys   bool
}

// isPHPSerializedArray validates one complete PHP serialization without
// materializing it. Checking the full grammar prevents a decoded prefix such
// as "a:1:{" (including one followed by NUL or garbage) from becoming a
// finding. The explicit frame stack also keeps hostile nesting off Go's call
// stack.
func isPHPSerializedArray(data []byte) bool {
	if len(data) == 0 || data[0] != 'a' {
		return false
	}

	frames := []phpSerializedFrame{{remaining: 1}}
	pos := 0
	for len(frames) > 0 {
		frameIndex := len(frames) - 1
		frame := frames[frameIndex]
		if frame.remaining == 0 {
			if frame.closing == 0 {
				return len(frames) == 1 && pos == len(data)
			}
			if pos >= len(data) || data[pos] != frame.closing {
				return false
			}
			pos++
			frames = frames[:frameIndex]
			continue
		}
		if pos >= len(data) {
			return false
		}

		expectingKey := frame.hasKeys && frame.remaining%2 == 0
		if expectingKey &&
			data[pos] != 'i' && data[pos] != 's' {
			return false
		}

		frames[frameIndex].remaining--
		next, child, hasChild, ok := consumePHPSerializedValue(data, pos)
		if !ok {
			return false
		}
		pos = next
		if hasChild {
			frames = append(frames, child)
		}
	}
	return false
}

func consumePHPSerializedValue(data []byte, pos int) (int, phpSerializedFrame, bool, bool) {
	var noChild phpSerializedFrame
	if pos >= len(data) {
		return pos, noChild, false, false
	}
	switch data[pos] {
	case 'N':
		if pos+2 <= len(data) && string(data[pos:pos+2]) == "N;" {
			return pos + 2, noChild, false, true
		}
	case 'b':
		if pos+4 <= len(data) && data[pos+1] == ':' &&
			(data[pos+2] == '0' || data[pos+2] == '1') && data[pos+3] == ';' {
			return pos + 4, noChild, false, true
		}
	case 'i':
		if pos+2 > len(data) || data[pos+1] != ':' {
			break
		}
		next, ok := consumePHPSerializedInteger(data, pos+2)
		return next, noChild, false, ok
	case 'd':
		if pos+2 > len(data) || data[pos+1] != ':' {
			break
		}
		end := pos + 2
		for end < len(data) && data[end] != ';' {
			end++
		}
		if end == len(data) || end == pos+2 || end-(pos+2) > 64 {
			break
		}
		number := string(data[pos+2 : end])
		if number == "INF" || number == "-INF" || number == "NAN" {
			return end + 1, noChild, false, true
		}
		if _, err := strconv.ParseFloat(number, 64); err == nil {
			return end + 1, noChild, false, true
		}
	case 's', 'E':
		if pos+2 > len(data) || data[pos+1] != ':' {
			break
		}
		next, ok := consumePHPSerializedBytes(data, pos+2, ';')
		return next, noChild, false, ok
	case 'R', 'r':
		if pos+2 > len(data) || data[pos+1] != ':' {
			break
		}
		ref, next, ok := parsePHPSerializedUint(data, pos+2, ';')
		return next, noChild, false, ok && ref > 0
	case 'a':
		if pos+2 > len(data) || data[pos+1] != ':' {
			break
		}
		count, next, ok := parsePHPSerializedUint(data, pos+2, ':')
		if !ok || count > len(data) || count > int(^uint(0)>>1)/2 ||
			next >= len(data) || data[next] != '{' {
			break
		}
		return next + 1, phpSerializedFrame{
			remaining: count * 2,
			closing:   '}',
			hasKeys:   true,
		}, true, true
	case 'O':
		if pos+2 > len(data) || data[pos+1] != ':' {
			break
		}
		next, ok := consumePHPSerializedBytes(data, pos+2, ':')
		if !ok {
			break
		}
		count, next, ok := parsePHPSerializedUint(data, next, ':')
		if !ok || count > len(data) || count > int(^uint(0)>>1)/2 ||
			next >= len(data) || data[next] != '{' {
			break
		}
		return next + 1, phpSerializedFrame{
			remaining: count * 2,
			closing:   '}',
			// __serialize() may return integer as well as string keys.
			hasKeys: true,
		}, true, true
	case 'C':
		if pos+2 > len(data) || data[pos+1] != ':' {
			break
		}
		next, ok := consumePHPSerializedBytes(data, pos+2, ':')
		if !ok {
			break
		}
		payloadLen, next, ok := parsePHPSerializedUint(data, next, ':')
		if !ok || next >= len(data) || data[next] != '{' ||
			payloadLen > len(data)-(next+1) {
			break
		}
		next += 1 + payloadLen
		if next < len(data) && data[next] == '}' {
			return next + 1, noChild, false, true
		}
	}
	return pos, noChild, false, false
}

func consumePHPSerializedInteger(data []byte, pos int) (int, bool) {
	start := pos
	if pos < len(data) && data[pos] == '-' {
		pos++
	}
	digitStart := pos
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		pos++
	}
	if pos == digitStart || pos >= len(data) || data[pos] != ';' || pos-start > 20 {
		return start, false
	}
	if _, err := strconv.ParseInt(string(data[start:pos]), 10, 64); err != nil {
		return start, false
	}
	return pos + 1, true
}

// consumePHPSerializedBytes consumes <length>:"<raw bytes>"<terminator>.
func consumePHPSerializedBytes(data []byte, pos int, terminator byte) (int, bool) {
	length, next, ok := parsePHPSerializedUint(data, pos, ':')
	if !ok || next >= len(data) || data[next] != '"' || length > len(data)-(next+1) {
		return pos, false
	}
	next += 1 + length
	if next+1 >= len(data) || data[next] != '"' || data[next+1] != terminator {
		return pos, false
	}
	return next + 2, true
}

func parsePHPSerializedUint(data []byte, pos int, delimiter byte) (int, int, bool) {
	start := pos
	n := 0
	maxInt := int(^uint(0) >> 1)
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		digit := int(data[pos] - '0')
		if n > (maxInt-digit)/10 {
			return 0, start, false
		}
		n = n*10 + digit
		pos++
	}
	if pos == start || pos >= len(data) || data[pos] != delimiter {
		return 0, start, false
	}
	return n, pos + 1, true
}

// doorwaySitemapRoutes returns the canonical cluster numbers routed from a
// numbered sitemap key into the matching numbered feed value. Requiring both
// halves in the same serialized rewrite-rule pair avoids correlating unrelated
// rules that merely occur in the same option.
func doorwaySitemapRoutes(rewriteRules string) []string {
	routes, _ := doorwaySitemapRoutesChecked(rewriteRules)
	return routes
}

func doorwaySitemapRoutesChecked(rewriteRules string) ([]string, bool) {
	data := []byte(rewriteRules)
	if len(data) < 6 || data[0] != 'a' || data[1] != ':' {
		return nil, false
	}
	count, pos, ok := parsePHPSerializedUint(data, 2, ':')
	if !ok || count > len(data) || pos >= len(data) || data[pos] != '{' {
		return nil, false
	}
	pos++
	routes := make(map[string]struct{})
	for i := 0; i < count; i++ {
		key, next, ok := parsePHPSerializedStringAt(rewriteRules, pos)
		if !ok {
			return nil, false
		}
		value, nextValue, ok := parsePHPSerializedStringAt(rewriteRules, next)
		if !ok {
			return nil, false
		}
		pos = nextValue

		keyNumbers := cloakClusterNumbers(numberedSitemapRoute, key)
		valueNumbers := cloakClusterNumbers(numberedSitemapFeed, value)
		for number := range keyNumbers {
			if _, paired := valueNumbers[number]; paired {
				routes[number] = struct{}{}
			}
		}
	}
	if pos >= len(data) || data[pos] != '}' || pos+1 != len(data) {
		return nil, false
	}

	out := make([]string, 0, len(routes))
	for number := range routes {
		out = append(out, number)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) < len(out[j])
		}
		return out[i] < out[j]
	})
	return out, true
}

func cloakClusterNumbers(pattern *regexp.Regexp, value string) map[string]struct{} {
	numbers := make(map[string]struct{})
	for _, match := range pattern.FindAllStringSubmatch(value, -1) {
		if len(match) < 2 || len(match[1]) > 10 {
			continue
		}
		number := strings.TrimLeft(match[1], "0")
		if number == "" {
			number = "0"
		}
		numbers[number] = struct{}{}
	}
	return numbers
}

type cloakOptionRow struct {
	kind  string
	name  string
	value []byte
}

func parseCloakOptionRow(line string) (cloakOptionRow, bool, bool) {
	var row cloakOptionRow
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 4)
	if len(parts) != 4 {
		return row, false, false
	}
	valueBytes, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || valueBytes < 0 {
		return row, false, false
	}
	encoded := strings.TrimSpace(parts[3])
	if !strings.HasPrefix(encoded, "x") {
		return row, false, false
	}
	value, err := hex.DecodeString(encoded[1:])
	if err != nil {
		return row, false, false
	}
	expected := valueBytes
	if expected > maxCloakOptionBytes {
		expected = maxCloakOptionBytes
	}
	if int64(len(value)) != expected {
		return row, false, false
	}
	return cloakOptionRow{
		kind:  strings.TrimSpace(parts[0]),
		name:  parts[1],
		value: value,
	}, true, valueBytes <= maxCloakOptionBytes
}

// checkWPCloakConfig reports doorway scaffolding kept in the options table.
func checkWPCloakConfig(user string, creds wpDBCreds, prefix string) []alert.Finding {
	query := fmt.Sprintf(
		"(SELECT 'opt' AS kind, option_name, OCTET_LENGTH(option_value), "+
			"CONCAT('x', HEX(LEFT(CAST(option_value AS BINARY), %d))) FROM %soptions "+
			"WHERE autoload IN ('yes', 'on', 'auto-on', 'auto') "+
			"AND OCTET_LENGTH(option_name) = 32 AND UNHEX(option_name) IS NOT NULL "+
			"ORDER BY option_name LIMIT %d) UNION ALL "+
			"(SELECT 'rules', option_name, OCTET_LENGTH(option_value), "+
			"CONCAT('x', HEX(LEFT(CAST(option_value AS BINARY), %d))) FROM %soptions "+
			"WHERE option_name = 'rewrite_rules' LIMIT 1)",
		maxCloakOptionBytes, prefix, maxCloakOptionRows+1, maxCloakOptionBytes, prefix)

	var keyed []string
	routeSet := make(map[string]struct{})
	candidates := 0
	candidatesTruncated := false
	for _, line := range runMySQLQuery(creds, query) {
		row, ok, complete := parseCloakOptionRow(line)
		if !ok {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		if !complete {
			markCheckIncomplete(creds.queryCtx, "db_content")
		}
		switch row.kind {
		case "opt":
			candidates++
			if candidates > maxCloakOptionRows {
				candidatesTruncated = true
				markCheckIncomplete(creds.queryCtx, "db_content")
				continue
			}
			if complete {
				if size, matched := hostnameKeyedOption(row.name, string(row.value)); matched {
					keyed = append(keyed, fmt.Sprintf("%s (%d bytes decoded)", row.name, size))
				}
			}
		case "rules":
			if complete {
				routes, parsed := doorwaySitemapRoutesChecked(string(row.value))
				if !parsed {
					continue
				}
				for _, route := range routes {
					routeSet[route] = struct{}{}
				}
			}
		default:
			markCheckIncomplete(creds.queryCtx, "db_content")
		}
	}
	sort.Strings(keyed)
	routes := make([]string, 0, len(routeSet))
	for route := range routeSet {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i]) != len(routes[j]) {
			return len(routes[i]) < len(routes[j])
		}
		return routes[i] < routes[j]
	})

	var findings []alert.Finding
	if len(keyed) > 0 {
		count := strconv.Itoa(len(keyed))
		if candidatesTruncated {
			count = "at least " + count
		}
		noun, verb, hold := "options", "are", "hold"
		if len(keyed) == 1 {
			noun, verb, hold = "option", "is", "holds"
		}
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "db_hostname_keyed_option",
			Message: fmt.Sprintf("%s autoloaded WordPress %s %s named by digest and %s encoded data (account: %s)",
				count, noun, verb, hold, user),
			Details: dbContentFindingDetails(creds, prefix,
				"An option named after a digest cannot be found without already knowing "+
					"the key, and the base64 layer keeps its contents out of any search of "+
					"the table. Cloak kits key that digest to the site's own hostname so one "+
					"payload serves many sites. The row is autoloaded, so it is read on every request.",
				cloakSample("Options", keyed)),
		})
	}
	if len(routes) > 0 {
		noun, verb := "routes", "feed"
		if len(routes) == 1 {
			noun, verb = "route", "feeds"
		}
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "db_doorway_sitemap_routes",
			Message: fmt.Sprintf("%d numbered sitemap %s %s generated pages to crawlers (account: %s)",
				len(routes), noun, verb, user),
			Details: dbContentFindingDetails(creds, prefix,
				"Each rule routes sitemap<N>.xml straight into a matching feed, one per "+
					"doorway cluster, so crawlers are handed the generated pages without them "+
					"appearing in the site's real sitemap. Sitemap plugins add rewrite rules "+
					"too, but none of them pair a numbered sitemap with a feed of the same number.",
				cloakSample("Clusters", routes)),
		})
	}
	return findings
}

func cloakSample(label string, values []string) string {
	shown := values
	if len(shown) > maxCloakSamplesShown {
		shown = shown[:maxCloakSamplesShown]
		label += fmt.Sprintf(" (showing %d of %d)", len(shown), len(values))
	}
	return label + ": " + strings.Join(shown, ", ")
}
