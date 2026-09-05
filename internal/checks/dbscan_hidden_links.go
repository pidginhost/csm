package checks

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2"
	cssparser "github.com/tdewolff/parse/v2/css"
	"golang.org/x/net/html"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/mysqlclient"
)

// Hidden-container link injection stored in the database.
//
// The kit wraps outbound links in a container the reader never sees -- an
// absolutely positioned block pushed thousands of pixels off the canvas, a
// text-indent far outside the viewport, or a display:none wrapper -- so a
// visitor sees an ordinary page while crawlers follow the links. CSM already
// ships file-side rules for this shape, but these injections live in
// post_content and option rows, where no file scanner ever looks.
//
// A hidden container on its own is ordinary: themes hide screen-reader text,
// mobile menus and collapsed panels. What has no benign reading is a hidden
// container wrapping links to somebody else's domain.

const (
	// maxHiddenLinkRows bounds the rows pulled per table.
	maxHiddenLinkRows = 200
	// maxHiddenLinkValueBytes bounds one row's markup. Injected blocks sit at
	// the top or bottom of the content, so half is read from each end rather
	// than letting padding at the front hide a trailing block.
	maxHiddenLinkValueBytes  = 128 * 1024
	maxHiddenLinkSampleBytes = maxHiddenLinkValueBytes / 2
	// maxHiddenLinkSiteURLBytes prevents a poisoned site address from making
	// the otherwise bounded candidate query return an attacker-sized value.
	maxHiddenLinkSiteURLBytes = 4 * 1024
	// maxHiddenLinkNodes bounds one row's parsed markup. The walk is iterative
	// so nesting cannot exhaust the stack, but a hostile row must not be able
	// to spend unbounded time either.
	maxHiddenLinkNodes = 200000
	// maxHiddenLinkHostsShown bounds the hosts named in the finding.
	maxHiddenLinkHostsShown = 12
	// maxHiddenLinkRowsShown bounds the rows named in the finding.
	maxHiddenLinkRowsShown = 10
	// offScreenPixels is how far outside the canvas an offset must sit before
	// it is cloaking rather than layout. Real layouts nudge elements by a few
	// pixels; the kits observed used four- and five-digit offsets.
	offScreenPixels = 1000
	// Font-relative offsets reach the same distance with smaller numbers. The
	// threshold remains high enough to exclude ordinary indentation.
	offScreenFontUnits = 100
)

// hiddenLinkCandidatePattern mirrors the CSS forms the parser understands.
// Otherwise the database prefilter could discard a row before parsing it.
const hiddenLinkCSSCommentPattern = `/[*]([^*]|[*]+[^*/])*[*]+/`
const hiddenLinkCSSGapPattern = `([[:space:]]|` + hiddenLinkCSSCommentPattern + `)*`
const hiddenLinkEncodedStylePattern = `style[[:space:]]*=[^>]*[&](#(x[0-9a-f]+|[0-9]+)|colon);?`
const hiddenLinkCandidatePattern = `(display|visibility)` + hiddenLinkCSSGapPattern + `:` +
	hiddenLinkCSSGapPattern + `(none|hidden|collapse)` +
	`|opacity` + hiddenLinkCSSGapPattern + `:` + hiddenLinkCSSGapPattern +
	`([+]?0+|[+]?[.]0+|-[0-9]+|-[.][0-9]+)([^0-9]|$)` +
	`|(text-indent|left|top|right|bottom|margin-left|margin-top)` + hiddenLinkCSSGapPattern + `:` +
	hiddenLinkCSSGapPattern + `(calc` + hiddenLinkCSSGapPattern + `[(]` + hiddenLinkCSSGapPattern + `)?` +
	`-([0-9]|[.][0-9])|` + hiddenLinkEncodedStylePattern

// hiddenLinkCandidateCondition builds the row prefilter. Both alternatives
// live in one pattern so the column is scanned once: this runs against every
// published post of every install on the host, and a second REGEXP pass over a
// TEXT column doubles that for nothing.
//
// A CSS escape is a literal backslash in the stored markup, which needs two in
// the regular expression. CHAR() builds them so the result does not depend on
// MySQL's string-escape mode.
func hiddenLinkCandidateCondition(column string) string {
	return fmt.Sprintf("LOWER(%s) REGEXP CONCAT('%s|style[[:space:]]*=[^>]*', CHAR(92), CHAR(92))",
		column, hiddenLinkCandidatePattern)
}

// hiddenLinkHit is what one row's markup revealed.
type hiddenLinkHit struct {
	// offScreen records the strong signal: a container moved outside the
	// canvas. Nothing legitimate positions readable content there.
	offScreen bool
	// hosts are the distinct off-site hosts linked from inside hidden
	// containers, sorted.
	hosts []string
	// domains are the distinct registrable domains behind hosts. Severity is
	// based on these so subdomains of one target do not look like a link farm.
	domains []string
	// multiDomain records that one hidden container, rather than merely one
	// database row, links to at least two registrable domains.
	multiDomain bool
	// spammy records gambling or pharmacy vocabulary in the hidden anchors.
	spammy bool
}

// hiddenOffsiteLinks reports the off-site hosts linked from inside a container
// the page hides from readers. siteHost is the site's own address; links back
// to it are ordinary navigation whatever their styling.
//
// This tokenizes rather than building a tree. x/net/html refuses markup nested
// deeper than 512 elements, and returning nothing for those rows would hand
// every kit a one-line evasion. The tokenizer has no depth limit, and tracking
// open elements on an explicit heap stack keeps attacker-controlled nesting off
// the goroutine stack, where an overflow is fatal and unrecoverable.
func hiddenOffsiteLinks(markup, siteHost string) hiddenLinkHit {
	return hiddenOffsiteLinksForSites(markup, []string{siteHost})
}

func hiddenOffsiteLinksForSites(markup string, siteHosts []string) hiddenLinkHit {
	siteDomains := make(map[string]bool, len(siteHosts))
	for _, host := range siteHosts {
		if domain := registrableDomain(host); domain != "" {
			siteDomains[domain] = true
		}
	}
	if len(siteDomains) == 0 {
		return hiddenLinkHit{}
	}

	type openElement struct {
		name             string
		hidden           bool
		hiddenGroup      int
		visibilityHidden bool
		visibilityGroup  int
		offScreen        bool
	}
	var stack []openElement
	inherited := func() openElement {
		if len(stack) == 0 {
			return openElement{}
		}
		return stack[len(stack)-1]
	}

	var hit hiddenLinkHit
	seenHosts := make(map[string]bool)
	seenDomains := make(map[string]bool)
	nextHiddenGroup := 1
	groupDomains := make(map[int]map[string]bool)
	newHiddenGroup := func() int {
		group := nextHiddenGroup
		nextHiddenGroup++
		return group
	}
	recordGroupDomain := func(group int, domain string) {
		if group == 0 {
			return
		}
		domains := groupDomains[group]
		if domains == nil {
			domains = make(map[string]bool)
			groupDomains[group] = domains
		}
		domains[domain] = true
		if len(domains) >= 2 {
			hit.multiDomain = true
		}
	}
	// anchorHost is the host of the hidden anchor currently open, so its link
	// text can be graded when the anchor closes.
	anchorHost, anchorText := "", strings.Builder{}
	anchorDepth := -1
	closeAnchor := func() {
		if anchorHost == "" {
			return
		}
		if termNameSpamVocabulary.MatchString(anchorText.String()) || termNameSpamVocabulary.MatchString(anchorHost) {
			hit.spammy = true
		}
		anchorHost, anchorText = "", strings.Builder{}
		anchorDepth = -1
	}
	popOpenElement := func(name string) bool {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].name != name {
				continue
			}
			if anchorDepth >= i {
				closeAnchor()
			}
			stack = stack[:i]
			return true
		}
		return false
	}

	z := html.NewTokenizer(strings.NewReader(markup))
	for tokens := 0; tokens < maxHiddenLinkNodes; tokens++ {
		switch z.Next() {
		case html.ErrorToken:
			closeAnchor()
			sort.Strings(hit.hosts)
			sort.Strings(hit.domains)
			return hit
		case html.TextToken:
			if anchorHost != "" && anchorText.Len() < 512 &&
				(len(stack) == 0 || !rawTextHTMLElements[stack[len(stack)-1].name]) {
				text := z.Text()
				remaining := 512 - anchorText.Len()
				if len(text) > remaining {
					text = text[:remaining]
				}
				anchorText.Write(text)
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, style, href := tokenAttrs(z)
			if name == "a" {
				popOpenElement("a")
				closeAnchor()
			}
			state := inherited()
			if style != "" {
				styleState := parseHiddenCSSState(style)
				if styleState.hidden {
					if !state.hidden {
						state.hiddenGroup = newHiddenGroup()
					}
					state.hidden = true
				}
				if styleState.visibilitySet {
					if styleState.visibilityHidden {
						if !state.visibilityHidden {
							state.visibilityGroup = newHiddenGroup()
						}
					} else {
						state.visibilityGroup = 0
					}
					state.visibilityHidden = styleState.visibilityHidden
				}
				if styleState.offScreen {
					state.offScreen = true
				}
			}
			if name == "a" && (state.hidden || state.visibilityHidden) && href != "" {
				if host, ok := absoluteLinkHost(href); ok {
					domain := registrableDomain(host)
					if domain != "" && !siteDomains[domain] {
						if !seenHosts[host] {
							seenHosts[host] = true
							hit.hosts = append(hit.hosts, host)
						}
						if !seenDomains[domain] {
							seenDomains[domain] = true
							hit.domains = append(hit.domains, domain)
						}
						recordGroupDomain(state.hiddenGroup, domain)
						recordGroupDomain(state.visibilityGroup, domain)
						if state.offScreen {
							hit.offScreen = true
						}
						anchorHost = host
						anchorDepth = len(stack)
					}
				}
			}
			if !voidHTMLElements[name] {
				state.name = name
				stack = append(stack, state)
			}
		case html.EndTagToken:
			name, _, _ := tokenAttrs(z)
			// Unclosed tags are ordinary in real content, so pop back to the
			// nearest matching element rather than assuming balance.
			popOpenElement(name)
			if name == "a" {
				closeAnchor()
			}
		}
	}
	closeAnchor()
	sort.Strings(hit.hosts)
	sort.Strings(hit.domains)
	return hit
}

// voidHTMLElements never have an end tag, so they must not be pushed onto the
// open-element stack.
var voidHTMLElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

var rawTextHTMLElements = map[string]bool{
	"script": true, "style": true, "textarea": true, "title": true,
}

// tokenAttrs returns the current token's lowercased tag name plus the two
// attributes this check reads.
func tokenAttrs(z *html.Tokenizer) (name, style, href string) {
	raw, hasAttr := z.TagName()
	name = strings.ToLower(string(raw))
	for hasAttr {
		var key, val []byte
		key, val, hasAttr = z.TagAttr()
		switch strings.ToLower(string(key)) {
		case "style":
			style = string(val)
		case "href":
			href = strings.TrimSpace(string(val))
		}
	}
	return name, style, href
}

// absoluteLinkHost returns the host of a link that leaves the current page. A
// relative link cannot leave the site and is not one.
func absoluteLinkHost(href string) (string, bool) {
	parsed, err := url.Parse(href)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "":
		return normalizeHost(parsed.Hostname()), true
	default:
		return "", false
	}
}

// registrableDomain canonicalizes a host to the public suffix plus one. IP and
// single-label hosts remain their own identity so sites served on either can
// still distinguish their own links from external ones.
func registrableDomain(host string) string {
	host = normalizeHost(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return domain
}

func normalizeHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return ""
	}
	return strings.ToLower(ascii)
}

type cssDeclaration struct {
	value     string
	important bool
}

type hiddenCSSState struct {
	hidden           bool
	visibilitySet    bool
	visibilityHidden bool
	offScreen        bool
}

func parseHiddenCSSState(declarations string) hiddenCSSState {
	effective := make(map[string]cssDeclaration)
	parser := cssparser.NewParser(parse.NewInputString(declarations), true)
	for {
		grammar, _, propertyBytes := parser.Next()
		if grammar == cssparser.ErrorGrammar {
			break
		}
		if grammar != cssparser.DeclarationGrammar {
			continue
		}
		property := strings.ToLower(cssUnescape(string(propertyBytes)))
		var rawValue strings.Builder
		for _, token := range parser.Values() {
			rawValue.Write(token.Data)
		}
		value, important := cssDeclarationValue(strings.ToLower(cssUnescape(rawValue.String())))
		previous, exists := effective[property]
		if exists && previous.important && !important {
			continue
		}
		effective[property] = cssDeclaration{value: value, important: important}
	}

	var state hiddenCSSState
	if declaration, ok := effective["display"]; ok && declaration.value == "none" {
		state.hidden = true
	}
	if declaration, ok := effective["visibility"]; ok {
		switch declaration.value {
		case "hidden", "collapse":
			state.visibilitySet = true
			state.visibilityHidden = true
		case "visible", "initial":
			state.visibilitySet = true
		}
	}
	if declaration, ok := effective["opacity"]; ok && cssOpacityIsHidden(declaration.value) {
		state.hidden = true
	}
	for _, property := range []string{
		"text-indent", "left", "top", "right", "bottom", "margin-left", "margin-top",
	} {
		if declaration, ok := effective[property]; ok && cssLengthIsOffScreen(declaration.value) {
			state.hidden = true
			state.offScreen = true
			break
		}
	}
	return state
}

func cssUnescape(value string) string {
	if !strings.ContainsRune(value, '\\') {
		return value
	}
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		i++
		if i >= len(value) {
			break
		}
		if isCSSHex(value[i]) {
			codePoint := uint32(0)
			digits := 0
			for i < len(value) && digits < 6 && isCSSHex(value[i]) {
				codePoint = codePoint*16 + uint32(cssHexValue(value[i]))
				i++
				digits++
			}
			if codePoint == 0 || codePoint > utf8.MaxRune || 0xD800 <= codePoint && codePoint <= 0xDFFF {
				out.WriteRune(utf8.RuneError)
			} else {
				out.WriteRune(rune(codePoint))
			}
			if i < len(value) && isCSSWhitespace(value[i]) {
				if value[i] == '\r' && i+1 < len(value) && value[i+1] == '\n' {
					i++
				}
			} else {
				i--
			}
			continue
		}
		if value[i] == '\r' && i+1 < len(value) && value[i+1] == '\n' {
			i++
			continue
		}
		if value[i] == '\n' || value[i] == '\r' || value[i] == '\f' {
			continue
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		out.WriteRune(r)
		i += size - 1
	}
	return out.String()
}

func isCSSHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func cssHexValue(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	default:
		return value - 'A' + 10
	}
}

func isCSSWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f'
}

func cssOpacityIsHidden(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	number, err := strconv.ParseFloat(value, 64)
	return err == nil && number <= 0 || math.IsInf(number, -1)
}

func cssDeclarationValue(value string) (string, bool) {
	value = strings.TrimSpace(value)
	marker := strings.LastIndexByte(value, '!')
	if marker < 0 || strings.TrimSpace(value[marker+1:]) != "important" {
		return value, false
	}
	return strings.TrimSpace(value[:marker]), true
}

func cssLengthIsOffScreen(value string) bool {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "calc(") && strings.HasSuffix(value, ")") {
		value = strings.TrimSpace(value[len("calc(") : len(value)-1])
	}

	unit := ""
	for _, candidate := range []string{"vmin", "vmax", "rem", "px", "em", "vw", "vh", "%"} {
		if strings.HasSuffix(value, candidate) {
			unit = candidate
			value = strings.TrimSpace(strings.TrimSuffix(value, candidate))
			break
		}
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return math.IsInf(number, -1)
	}

	threshold := float64(offScreenPixels)
	if unit == "em" || unit == "rem" {
		threshold = offScreenFontUnits
	}
	return number <= -threshold
}

// hiddenLinkRow is one database row that carried a hidden link block.
type hiddenLinkRow struct {
	label string
	hit   hiddenLinkHit
}

// checkWPHiddenLinks reports link blocks the page hides from its readers.
func checkWPHiddenLinks(user string, creds wpDBCreds, prefix string) []alert.Finding {
	siteHosts, optionRows := hiddenLinkOptionRows(creds, prefix)
	if len(siteHosts) == 0 {
		// Every absolute link would look external. Report nothing rather than
		// flood, and let the incomplete marker say why.
		markCheckIncomplete(creds.queryCtx, "db_content")
		return nil
	}

	rows := make([]hiddenLinkRow, 0, len(optionRows))
	for _, row := range optionRows {
		if hit := hiddenOffsiteLinkSamples(row, siteHosts); len(hit.hosts) > 0 {
			rows = append(rows, hiddenLinkRow{label: "option " + strconv.Quote(row.label), hit: hit})
		}
	}
	for _, row := range hiddenLinkPostRows(creds, prefix) {
		if hit := hiddenOffsiteLinkSamples(row, siteHosts); len(hit.hosts) > 0 {
			rows = append(rows, hiddenLinkRow{label: "post " + strconv.Quote(row.label), hit: hit})
		}
	}
	return buildHiddenLinkFindings(user, creds, prefix, rows)
}

type hiddenLinkSource struct {
	label      string
	markup     string
	tailMarkup string
	valueBytes int
}

func hiddenOffsiteLinkSamples(source hiddenLinkSource, siteHosts []string) hiddenLinkHit {
	if source.valueBytes > 0 && source.valueBytes <= maxHiddenLinkValueBytes && source.tailMarkup != "" {
		overlap := len(source.markup) + len(source.tailMarkup) - source.valueBytes
		if overlap >= 0 && overlap <= len(source.markup) && overlap <= len(source.tailMarkup) &&
			source.markup[len(source.markup)-overlap:] == source.tailMarkup[:overlap] {
			source.markup += source.tailMarkup[overlap:]
			source.tailMarkup = ""
		}
	}
	// Treat the two samples as separate fragments. Concatenating them could
	// carry an unclosed hidden container across the omitted middle and turn a
	// visible trailing link into a false positive.
	hit := hiddenOffsiteLinksForSites(source.markup, siteHosts)
	if source.tailMarkup == "" || source.tailMarkup == source.markup {
		return hit
	}
	return mergeHiddenLinkHits(hit, hiddenOffsiteLinksForSites(source.tailMarkup, siteHosts))
}

func mergeHiddenLinkHits(left, right hiddenLinkHit) hiddenLinkHit {
	merged := hiddenLinkHit{
		offScreen:   left.offScreen || right.offScreen,
		multiDomain: left.multiDomain || right.multiDomain,
		spammy:      left.spammy || right.spammy,
	}
	for _, values := range [][]string{left.hosts, right.hosts} {
		for _, value := range values {
			if len(merged.hosts) == 0 || merged.hosts[len(merged.hosts)-1] != value {
				merged.hosts = append(merged.hosts, value)
			}
		}
	}
	for _, values := range [][]string{left.domains, right.domains} {
		for _, value := range values {
			if len(merged.domains) == 0 || merged.domains[len(merged.domains)-1] != value {
				merged.domains = append(merged.domains, value)
			}
		}
	}
	sort.Strings(merged.hosts)
	merged.hosts = compactSortedStrings(merged.hosts)
	sort.Strings(merged.domains)
	merged.domains = compactSortedStrings(merged.domains)
	return merged
}

func compactSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// hiddenLinkOptionRows reads the site address and the option rows worth
// parsing in one round trip.
func hiddenLinkOptionRows(creds wpDBCreds, prefix string) ([]string, []hiddenLinkSource) {
	query := fmt.Sprintf(
		"(SELECT 'site' AS kind, option_name, LEFT(CAST(option_value AS BINARY), %d), "+
			"'', OCTET_LENGTH(option_value), 'site' FROM %soptions "+
			"WHERE option_name IN ('siteurl', 'home') LIMIT 4) UNION ALL "+
			"(SELECT 'opt', option_name, LEFT(CAST(option_value AS BINARY), %d), "+
			"RIGHT(CAST(option_value AS BINARY), %d), OCTET_LENGTH(option_value), 'opt' FROM %soptions "+
			"WHERE %s LIMIT %d)",
		maxHiddenLinkSiteURLBytes, prefix, maxHiddenLinkSampleBytes, maxHiddenLinkSampleBytes, prefix,
		hiddenLinkCandidateCondition("option_value"), maxHiddenLinkRows+1)

	var siteHosts []string
	seenSiteHosts := make(map[string]bool)
	var out []hiddenLinkSource
	rows := runMySQLQuery(creds, query)
	optionRowsSeen := 0
	truncated := false
	for _, line := range rows {
		// Column separators are literal tabs while tabs and newlines inside a
		// value remain batch escapes. Split that transport form before decoding
		// individual columns or an embedded tab becomes indistinguishable from
		// a separator.
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 6)
		if len(parts) != 6 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		kind := strings.TrimSpace(parts[0])
		if kind != "site" {
			optionRowsSeen++
			if optionRowsSeen > maxHiddenLinkRows {
				if !truncated {
					markCheckIncomplete(creds.queryCtx, "db_content")
					truncated = true
				}
				continue
			}
		}
		name := strings.TrimSpace(mysqlclient.BatchUnescape(parts[1]))
		encodedValue := parts[2]
		value := mysqlclient.BatchUnescape(encodedValue)
		valueBytes, err := strconv.Atoi(strings.TrimSpace(parts[4]))
		if err != nil || valueBytes < 0 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		if kind == "site" {
			if valueBytes > maxHiddenLinkSiteURLBytes || len(value) != valueBytes {
				markCheckIncomplete(creds.queryCtx, "db_content")
				continue
			}
			if reason, _ := siteURLPoisonReason(encodedValue); reason != "" {
				continue
			}
			if parsed, err := url.Parse(strings.TrimSpace(value)); err == nil {
				host := normalizeHost(parsed.Hostname())
				if registrableDomain(host) != "" && !seenSiteHosts[host] {
					seenSiteHosts[host] = true
					siteHosts = append(siteHosts, host)
				}
			}
			continue
		}
		tailMarkup := mysqlclient.BatchUnescape(parts[3])
		expectedSampleBytes := valueBytes
		if expectedSampleBytes > maxHiddenLinkSampleBytes {
			expectedSampleBytes = maxHiddenLinkSampleBytes
		}
		if len(value) != expectedSampleBytes || len(tailMarkup) != expectedSampleBytes {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		if valueBytes > maxHiddenLinkValueBytes {
			markCheckIncomplete(creds.queryCtx, "db_content")
		}
		out = append(out, hiddenLinkSource{
			label: name, markup: value, tailMarkup: tailMarkup, valueBytes: valueBytes,
		})
	}
	return siteHosts, out
}

func hiddenLinkPostRows(creds wpDBCreds, prefix string) []hiddenLinkSource {
	query := fmt.Sprintf(
		"SELECT ID, LEFT(CAST(post_content AS BINARY), %d), "+
			"RIGHT(CAST(post_content AS BINARY), %d), OCTET_LENGTH(post_content), 'post' "+
			"FROM %sposts WHERE post_status = 'publish' "+
			"AND post_type NOT IN (%s) AND %s LIMIT %d",
		maxHiddenLinkSampleBytes, maxHiddenLinkSampleBytes, prefix,
		nonScannablePostTypesSQLList(), hiddenLinkCandidateCondition("post_content"), maxHiddenLinkRows+1)

	rows := runMySQLQuery(creds, query)
	if len(rows) > maxHiddenLinkRows {
		markCheckIncomplete(creds.queryCtx, "db_content")
		rows = rows[:maxHiddenLinkRows]
	}
	out := make([]hiddenLinkSource, 0, len(rows))
	for _, line := range rows {
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 5)
		if len(parts) != 5 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		markup := mysqlclient.BatchUnescape(parts[1])
		tailMarkup := mysqlclient.BatchUnescape(parts[2])
		valueBytes, err := strconv.Atoi(strings.TrimSpace(parts[3]))
		if err != nil || valueBytes < 0 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		expectedSampleBytes := valueBytes
		if expectedSampleBytes > maxHiddenLinkSampleBytes {
			expectedSampleBytes = maxHiddenLinkSampleBytes
		}
		if len(markup) != expectedSampleBytes || len(tailMarkup) != expectedSampleBytes {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		if valueBytes > maxHiddenLinkValueBytes {
			markCheckIncomplete(creds.queryCtx, "db_content")
		}
		out = append(out, hiddenLinkSource{
			label:      strings.TrimSpace(mysqlclient.BatchUnescape(parts[0])),
			markup:     markup,
			tailMarkup: tailMarkup,
			valueBytes: valueBytes,
		})
	}
	return out
}

// buildHiddenLinkFindings grades the rows. An off-canvas container has no
// benign reading and is reported on its own. display:none does have one --
// themes hide panels that link out -- so it is reported only once the block
// points at several unrelated domains or carries spam vocabulary.
func buildHiddenLinkFindings(user string, creds wpDBCreds, prefix string, rows []hiddenLinkRow) []alert.Finding {
	var reported []hiddenLinkRow
	offScreen := false
	hosts := make(map[string]bool)
	domains := make(map[string]bool)
	for _, row := range rows {
		if !row.hit.offScreen && !row.hit.multiDomain && !row.hit.spammy {
			continue
		}
		reported = append(reported, row)
		if row.hit.offScreen {
			offScreen = true
		}
		for _, host := range row.hit.hosts {
			hosts[host] = true
		}
		for _, domain := range row.hit.domains {
			domains[domain] = true
		}
	}
	if len(reported) == 0 {
		return nil
	}

	named := make([]string, 0, len(hosts))
	for host := range hosts {
		named = append(named, host)
	}
	sort.Strings(named)
	shownHosts := named
	if len(shownHosts) > maxHiddenLinkHostsShown {
		shownHosts = shownHosts[:maxHiddenLinkHostsShown]
	}

	labels := make([]string, 0, len(reported))
	for _, row := range reported {
		if len(labels) >= maxHiddenLinkRowsShown {
			break
		}
		labels = append(labels, row.label)
	}

	details := []string{
		"A container the page hides from readers wraps links to other domains. " +
			"Crawlers still follow them, which is the point: the site's ranking " +
			"is lent to the linked domains without a visitor ever seeing it.",
		hiddenLinkSample("Linked hosts", shownHosts, len(named)),
		hiddenLinkSample("Rows", labels, len(reported)),
	}

	// An off-canvas container is cloaking by construction; a merely hidden one
	// needed corroboration to be reported at all, which is a weaker claim.
	severity := alert.Warning
	if offScreen {
		severity = alert.High
	}

	return []alert.Finding{{
		Severity: severity,
		Check:    "db_hidden_link_injection",
		Message: fmt.Sprintf("%d WordPress rows hide outbound links to %d hosts across %d domains (account: %s)",
			len(reported), len(named), len(domains), user),
		Details:  dbContentFindingDetails(creds, prefix, details...),
		DedupKey: dbContentDedupKey(creds, prefix, details...),
	}}
}

func hiddenLinkSample(label string, shown []string, total int) string {
	if total > len(shown) {
		label += fmt.Sprintf(" (showing %d of %d)", len(shown), total)
	}
	return label + ": " + strings.Join(shown, ", ")
}
