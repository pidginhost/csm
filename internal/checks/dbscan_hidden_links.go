package checks

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"

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
	// the top or bottom of the content; a row larger than this is truncated by
	// SQL rather than pulled whole into memory.
	maxHiddenLinkValueBytes = 128 * 1024
	// maxHiddenLinkNodes bounds one row's parsed markup. The walk is iterative
	// so nesting cannot exhaust the stack, but a hostile row must not be able
	// to spend unbounded time either.
	maxHiddenLinkNodes = 200000
	// maxHiddenLinkHostsShown bounds the domains named in the finding.
	maxHiddenLinkHostsShown = 12
	// maxHiddenLinkRowsShown bounds the rows named in the finding.
	maxHiddenLinkRowsShown = 10
	// offScreenPixels is how far outside the canvas an offset must sit before
	// it is cloaking rather than layout. Real layouts nudge elements by a few
	// pixels; the kits observed used four- and five-digit offsets.
	offScreenPixels = 1000
)

// hiddenLinkCandidateSQL prefilters rows worth parsing. Spacing after the
// colon varies between kits, so it cannot be a LIKE.
const hiddenLinkCandidateSQL = `'(display|visibility)[[:space:]]*:[[:space:]]*(none|hidden|collapse)` +
	`|(text-indent|left|top|right|bottom)[[:space:]]*:[[:space:]]*-[0-9]'`

// hiddenLinkHit is what one row's markup revealed.
type hiddenLinkHit struct {
	// offScreen records the strong signal: a container moved outside the
	// canvas. Nothing legitimate positions readable content there.
	offScreen bool
	// hosts are the distinct off-site hosts linked from inside hidden
	// containers, sorted.
	hosts []string
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
	siteLabel := registrableLabel(siteHost)
	if siteLabel == "" {
		return hiddenLinkHit{}
	}

	type openElement struct {
		name      string
		hidden    bool
		offScreen bool
	}
	var stack []openElement
	inherited := func() (bool, bool) {
		if len(stack) == 0 {
			return false, false
		}
		top := stack[len(stack)-1]
		return top.hidden, top.offScreen
	}

	var hit hiddenLinkHit
	seen := make(map[string]bool)
	// anchorHost is the host of the hidden anchor currently open, so its link
	// text can be graded when the anchor closes.
	anchorHost, anchorText := "", strings.Builder{}
	closeAnchor := func() {
		if anchorHost == "" {
			return
		}
		if termNameSpamVocabulary.MatchString(anchorText.String()) || termNameSpamVocabulary.MatchString(anchorHost) {
			hit.spammy = true
		}
		anchorHost, anchorText = "", strings.Builder{}
	}

	z := html.NewTokenizer(strings.NewReader(markup))
	for tokens := 0; tokens < maxHiddenLinkNodes; tokens++ {
		switch z.Next() {
		case html.ErrorToken:
			closeAnchor()
			sort.Strings(hit.hosts)
			return hit
		case html.TextToken:
			if anchorHost != "" && anchorText.Len() < 512 {
				anchorText.Write(z.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, style, href := tokenAttrs(z)
			hidden, offScreen := inherited()
			if style != "" {
				if cssOffScreen(style) {
					hidden, offScreen = true, true
				} else if cssDeclarationsHide(style) {
					hidden = true
				}
			}
			if name == "a" && hidden && href != "" {
				if host, ok := absoluteLinkHost(href); ok && offSiteHost(host, siteLabel) {
					if !seen[host] {
						seen[host] = true
						hit.hosts = append(hit.hosts, host)
					}
					if offScreen {
						hit.offScreen = true
					}
					anchorHost = host
				}
			}
			if len(stack) < maxHiddenLinkDepth && !voidHTMLElements[name] {
				stack = append(stack, openElement{name: name, hidden: hidden, offScreen: offScreen})
			}
		case html.EndTagToken:
			name, _, _ := tokenAttrs(z)
			if name == "a" {
				closeAnchor()
			}
			// Unclosed tags are ordinary in real content, so pop back to the
			// nearest matching element rather than assuming balance.
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].name == name {
					stack = stack[:i]
					break
				}
			}
		}
	}
	closeAnchor()
	sort.Strings(hit.hosts)
	return hit
}

// maxHiddenLinkDepth bounds the open-element stack. Content nested deeper than
// this stops contributing containment, but tokenizing continues.
const maxHiddenLinkDepth = 4096

// voidHTMLElements never have an end tag, so they must not be pushed onto the
// open-element stack.
var voidHTMLElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
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
		return strings.ToLower(parsed.Hostname()), true
	default:
		return "", false
	}
}

// offSiteHost reports whether a link leaves the site. siteLabel is non-empty
// by construction: hiddenOffsiteLinks refuses to scan a row without one,
// because an unknown site address makes every absolute link look external.
func offSiteHost(host, siteLabel string) bool {
	label := registrableLabel(host)
	return label != "" && label != siteLabel
}

// cssOffScreen reports whether inline declarations move content outside the
// canvas rather than merely hiding it.
func cssOffScreen(declarations string) bool {
	for _, declaration := range strings.Split(strings.ToLower(declarations), ";") {
		property, value, found := strings.Cut(declaration, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(property) {
		case "text-indent", "left", "top", "right", "bottom", "margin-left", "margin-top":
		default:
			continue
		}
		if px, ok := cssPixels(value); ok && px <= -offScreenPixels {
			return true
		}
	}
	return false
}

// cssPixels reads a pixel-valued declaration. Units other than px are not the
// shape these kits use and are not guessed at.
func cssPixels(value string) (float64, bool) {
	v := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "!important"))
	v = strings.TrimSpace(strings.TrimSuffix(v, "px"))
	px, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, false
	}
	return px, true
}

// hiddenLinkRow is one database row that carried a hidden link block.
type hiddenLinkRow struct {
	label string
	hit   hiddenLinkHit
}

// checkWPHiddenLinks reports link blocks the page hides from its readers.
func checkWPHiddenLinks(user string, creds wpDBCreds, prefix string) []alert.Finding {
	siteHost, optionRows := hiddenLinkOptionRows(creds, prefix)
	if siteHost == "" {
		// Every absolute link would look external. Report nothing rather than
		// flood, and let the incomplete marker say why.
		markCheckIncomplete(creds.queryCtx, "db_content")
		return nil
	}

	rows := make([]hiddenLinkRow, 0, len(optionRows))
	for _, row := range optionRows {
		if hit := hiddenOffsiteLinks(row.markup, siteHost); len(hit.hosts) > 0 {
			rows = append(rows, hiddenLinkRow{label: "option " + row.label, hit: hit})
		}
	}
	for _, row := range hiddenLinkPostRows(creds, prefix) {
		if hit := hiddenOffsiteLinks(row.markup, siteHost); len(hit.hosts) > 0 {
			rows = append(rows, hiddenLinkRow{label: "post " + row.label, hit: hit})
		}
	}
	return buildHiddenLinkFindings(user, creds, prefix, rows)
}

type hiddenLinkSource struct {
	label  string
	markup string
}

// hiddenLinkOptionRows reads the site address and the option rows worth
// parsing in one round trip.
func hiddenLinkOptionRows(creds wpDBCreds, prefix string) (string, []hiddenLinkSource) {
	query := fmt.Sprintf(
		"(SELECT 'site' AS kind, option_name, option_value FROM %soptions "+
			"WHERE option_name IN ('siteurl', 'home') LIMIT 4) UNION ALL "+
			"(SELECT 'opt', option_name, LEFT(option_value, %d) FROM %soptions "+
			"WHERE option_value REGEXP %s LIMIT %d)",
		prefix, maxHiddenLinkValueBytes, prefix, hiddenLinkCandidateSQL, maxHiddenLinkRows+1)

	siteHost := ""
	var out []hiddenLinkSource
	rows := runMySQLQuery(creds, query)
	for _, line := range rows {
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 3)
		if len(parts) != 3 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		name := strings.TrimSpace(mysqlclient.BatchUnescape(parts[1]))
		value := mysqlclient.BatchUnescape(parts[2])
		if strings.TrimSpace(parts[0]) == "site" {
			if siteHost == "" {
				if parsed, err := url.Parse(strings.TrimSpace(value)); err == nil {
					siteHost = parsed.Hostname()
				}
			}
			continue
		}
		if len(out) >= maxHiddenLinkRows {
			markCheckIncomplete(creds.queryCtx, "db_content")
			break
		}
		out = append(out, hiddenLinkSource{label: name, markup: value})
	}
	return siteHost, out
}

func hiddenLinkPostRows(creds wpDBCreds, prefix string) []hiddenLinkSource {
	query := fmt.Sprintf(
		"SELECT ID, LEFT(post_content, %d) FROM %sposts WHERE post_status = 'publish' "+
			"AND post_type NOT IN (%s) AND post_content REGEXP %s LIMIT %d",
		maxHiddenLinkValueBytes, prefix, nonScannablePostTypesSQLList(), hiddenLinkCandidateSQL, maxHiddenLinkRows+1)

	rows := runMySQLQuery(creds, query)
	if len(rows) > maxHiddenLinkRows {
		markCheckIncomplete(creds.queryCtx, "db_content")
		rows = rows[:maxHiddenLinkRows]
	}
	out := make([]hiddenLinkSource, 0, len(rows))
	for _, line := range rows {
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), "\t", 2)
		if len(parts) != 2 {
			markCheckIncomplete(creds.queryCtx, "db_content")
			continue
		}
		out = append(out, hiddenLinkSource{
			label:  strings.TrimSpace(mysqlclient.BatchUnescape(parts[0])),
			markup: mysqlclient.BatchUnescape(parts[1]),
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
	for _, row := range rows {
		if !row.hit.offScreen && len(row.hit.hosts) < 2 && !row.hit.spammy {
			continue
		}
		reported = append(reported, row)
		if row.hit.offScreen {
			offScreen = true
		}
		for _, host := range row.hit.hosts {
			hosts[host] = true
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
		hiddenLinkSample("Linked domains", shownHosts, len(named)),
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
		Message: fmt.Sprintf("%d WordPress rows hide outbound links to %d domains (account: %s)",
			len(reported), len(named), user),
		Details: dbContentFindingDetails(creds.dbName, prefix, details...),
	}}
}

func hiddenLinkSample(label string, shown []string, total int) string {
	if total > len(shown) {
		label += fmt.Sprintf(" (showing %d of %d)", len(shown), total)
	}
	return label + ": " + strings.Join(shown, ", ")
}
