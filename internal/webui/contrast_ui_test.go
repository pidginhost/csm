package webui

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// contrast is the WCAG 2 contrast ratio of two #rrggbb colours.
func contrast(t *testing.T, a, b string) float64 {
	t.Helper()
	lum := func(hex string) float64 {
		hex = strings.TrimPrefix(hex, "#")
		if len(hex) != 6 {
			t.Fatalf("not a #rrggbb colour: %q", hex)
		}
		var ch [3]float64
		for i := range ch {
			v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
			if err != nil {
				t.Fatal(err)
			}
			c := float64(v) / 255
			if c <= 0.03928 {
				ch[i] = c / 12.92
			} else {
				ch[i] = math.Pow((c+0.055)/1.055, 2.4)
			}
		}
		return 0.2126*ch[0] + 0.7152*ch[1] + 0.0722*ch[2]
	}
	la, lb := lum(a), lum(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func cssTokens(t *testing.T, css, selector string) map[string]string {
	t.Helper()
	start := strings.Index(css, selector+" {")
	if start < 0 {
		t.Fatalf("no %s block", selector)
	}
	block := css[start : start+strings.Index(css[start:], "}")]
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(--csm-[a-z-]+):\s*(#[0-9a-fA-F]{6})`).FindAllStringSubmatch(block, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// Severity and status text meets WCAG AA (4.5:1) on the page and card
// backgrounds of both themes.
func TestStatusTextHasReadableContrast(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(src)
	for _, theme := range []string{":root", ".theme-dark"} {
		tok := cssTokens(t, css, theme)
		for _, name := range []string{"--csm-critical-text", "--csm-high-text", "--csm-warning-text", "--csm-low-text", "--csm-info-text", "--csm-text-muted"} {
			fg, ok := tok[name]
			if !ok {
				t.Errorf("%s has no %s", theme, name)
				continue
			}
			for _, bg := range []string{"--csm-bg-page", "--csm-bg-card"} {
				if r := contrast(t, fg, tok[bg]); r < 4.5 {
					t.Errorf("%s %s %s on %s: %.2f:1", theme, name, fg, bg, r)
				}
			}
		}
	}
	for _, rule := range []string{
		".text-critical { color: var(--csm-critical-text); }",
		".text-high { color: var(--csm-high-text); }",
		".text-warning { color: var(--csm-warning-text) !important; }",
		".stat-delta.up   { color: var(--csm-critical-text); }",
		".stat-delta.down { color: var(--csm-low-text); }",
		"#system-health-pill.health-ok   { background: rgba(47, 179, 68, 0.12); color: var(--csm-low-text); }",
		"#system-health-pill.health-warn { background: rgba(245, 159, 0, 0.14); color: var(--csm-warning-text); }",
		"    color: var(--csm-info-text);\n    font-weight: 600;",
	} {
		if !strings.Contains(css, rule) {
			t.Errorf("csm.css missing readable rule %q", rule)
		}
	}
}

// Badge and toast text is readable on its background.
func TestBadgeAndToastColoursHaveReadableContrast(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(src)
	// Tabler's solid badge colours and the text CSM puts on them.
	tabler := map[string]string{
		"green": "#2fb344", "success": "#2fb344", "teal": "#0ca678", "cyan": "#17a2b8",
		"orange": "#f76707", "info": "#4299e1", "yellow": "#f59f00", "warning": "#f59f00",
		"red": "#d63939", "danger": "#d63939", "blue": "#206bc4", "purple": "#ae3ec9",
		"dark": "#1d273b", "secondary": "#6c757d",
	}
	group := regexp.MustCompile(`((?:\.badge\.bg-[a-z]+,?\s*)+)\{\s*color: (#[0-9a-f]{6}) !important;`)
	seen := map[string]bool{}
	for _, m := range group.FindAllStringSubmatch(css, -1) {
		for _, name := range regexp.MustCompile(`\.badge\.bg-([a-z]+)`).FindAllStringSubmatch(m[1], -1) {
			bg, ok := tabler[name[1]]
			if !ok {
				t.Fatalf("no reference colour for bg-%s", name[1])
			}
			seen[name[1]] = true
			if r := contrast(t, m[2], bg); r < 4.5 {
				t.Errorf("badge bg-%s text %s: %.2f:1", name[1], m[2], r)
			}
		}
	}
	for name := range tabler {
		if !seen[name] {
			t.Errorf("badge bg-%s has no readable text colour", name)
		}
	}
	toast := regexp.MustCompile(`\.csm-toast--([a-z]+) \{ background: (#[0-9a-f]{6}); color: (#[0-9a-f]{6}); \}`)
	kinds := map[string]bool{}
	for _, m := range toast.FindAllStringSubmatch(css, -1) {
		kinds[m[1]] = true
		if r := contrast(t, m[3], m[2]); r < 4.5 {
			t.Errorf("%s toast: %.2f:1", m[1], r)
		}
	}
	for _, kind := range []string{"success", "error", "warning", "info"} {
		if !kinds[kind] {
			t.Errorf("no readable colours for %s toasts", kind)
		}
	}
	if !strings.Contains(readUIScript(t, "toast.js"), "csm-toast--' + type") {
		t.Error("toasts do not use the readable toast colours")
	}
}

// Chart axis labels are readable on the card they sit on.
func TestChartAxisTextHasReadableContrast(t *testing.T) {
	for _, file := range []string{"csm-ui.js", "dashboard.js", "threat.js"} {
		src := readUIScript(t, file)
		for _, m := range regexp.MustCompile(`[tT]extColor = (?:isDark|dark) \? '(#[0-9a-f]{6})' : '(#[0-9a-f]{6})'`).FindAllStringSubmatch(src, -1) {
			if r := contrast(t, m[1], "#1e293b"); r < 4.5 {
				t.Errorf("%s dark axis text %s: %.2f:1", file, m[1], r)
			}
			if r := contrast(t, m[2], "#ffffff"); r < 4.5 {
				t.Errorf("%s light axis text %s: %.2f:1", file, m[2], r)
			}
		}
	}
}

// Check actual surfaces and opacity, not just opaque tokens on white.
func TestCompositedStatusTextHasReadableContrast(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(src)
	declaration := func(selector, property string) string {
		t.Helper()
		re := regexp.MustCompile(regexp.QuoteMeta(selector) + `\s*\{([^}]+)\}`)
		m := re.FindStringSubmatch(css)
		if m == nil {
			t.Fatalf("missing selector %s", selector)
		}
		for _, part := range strings.Split(m[1], ";") {
			k, v, _ := strings.Cut(part, ":")
			if strings.TrimSpace(k) == property {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	mix := func(fg, bg string, alpha float64) string {
		a, err := strconv.ParseUint(strings.TrimPrefix(fg, "#"), 16, 32)
		if err != nil {
			t.Fatalf("invalid foreground %q: %v", fg, err)
		}
		b, err := strconv.ParseUint(strings.TrimPrefix(bg, "#"), 16, 32)
		if err != nil {
			t.Fatalf("invalid background %q: %v", bg, err)
		}
		var rgb uint64
		for _, shift := range []uint{16, 8, 0} {
			v := math.Round(float64((a>>shift)&255)*alpha + float64((b>>shift)&255)*(1-alpha))
			rgb |= uint64(v) << shift
		}
		return fmt.Sprintf("#%06x", rgb)
	}
	for _, theme := range []string{":root", ".theme-dark"} {
		tok := cssTokens(t, css, theme)
		resolve := func(v string) string {
			v = strings.TrimSuffix(v, " !important")
			if strings.HasPrefix(v, "var(") {
				return tok[strings.TrimSuffix(strings.TrimPrefix(v, "var("), ")")]
			}
			return v
		}
		for _, selector := range []string{".stat-delta.up", ".stat-delta.down", ".stat-delta.flat", "#system-health-pill.health-crit", ".csm-palette__hint", ".csm-palette__empty"} {
			fg := resolve(declaration(selector, "color"))
			bg := tok["--csm-bg-card"]
			alpha := 1.0
			if strings.HasPrefix(selector, ".stat-delta.") {
				if opacity := declaration(".stat-delta", "opacity"); opacity != "" {
					alpha, err = strconv.ParseFloat(opacity, 64)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if strings.HasPrefix(selector, "#system-health-pill") {
				bg = mix("#d63939", bg, 0.15)
			}
			if r := contrast(t, mix(fg, bg, alpha), bg); r < 4.5 {
				t.Errorf("%s %s renders at %.2f:1", theme, selector, r)
			}
		}
		fg := resolve(declaration(".csm-palette__row.is-selected .csm-palette__rowgroup", "color"))
		if r := contrast(t, fg, mix("#206bc4", tok["--csm-bg-card"], 0.18)); r < 4.5 {
			t.Errorf("%s selected palette group renders at %.2f:1", theme, r)
		}
	}
}

func TestWarningTextOverridesVendorUtility(t *testing.T) {
	vendor, err := os.ReadFile("../../ui/static/css/tabler.min.css")
	if err != nil {
		t.Fatal(err)
	}
	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	vendorRule := regexp.MustCompile(`\.text-warning\{[^}]*color:[^}]*!important`).Match(vendor)
	customRule := regexp.MustCompile(`\.text-warning\s*\{[^}]*color:\s*var\(--csm-warning-text\)\s*!important`).Match(css)
	if vendorRule && !customRule {
		t.Fatal("Tabler's important warning color overrides the readable theme token")
	}
}
