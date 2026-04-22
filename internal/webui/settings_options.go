package webui

import (
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/geoip"
)

// resolveFieldOptions populates Options / OptionGroups for any []enum field
// that declares an OptionsSource. Called once per GET /api/v1/settings/:id
// so the UI always sees a fresh list (for check_names this matters if the
// registry grows over time).
//
// The section's Fields slice header points into the package-level
// settingsSections backing array. Writing into it directly would race
// across concurrent requests. Copy the slice first so mutations are local
// to this request.
func resolveFieldOptions(section *SettingsSection) {
	fields := make([]SettingsField, len(section.Fields))
	copy(fields, section.Fields)
	section.Fields = fields
	for i := range section.Fields {
		f := &section.Fields[i]
		if f.OptionsSource == "" {
			continue
		}
		switch f.OptionsSource {
		case "check_names":
			applyCheckNameOptions(f)
		case "geoip_editions":
			applyGeoIPEditionOptions(f)
		}
	}
}

func applyCheckNameOptions(f *SettingsField) {
	infos := checks.PublicCheckInfos()
	byCategory := make(map[string][]string)
	var order []string
	for _, info := range infos {
		if _, ok := byCategory[info.Category]; !ok {
			order = append(order, info.Category)
		}
		byCategory[info.Category] = append(byCategory[info.Category], info.Name)
	}
	groups := make([]OptionGroup, 0, len(order))
	flat := make([]string, 0, len(infos))
	for _, cat := range order {
		groups = append(groups, OptionGroup{Label: cat, Values: byCategory[cat]})
		flat = append(flat, byCategory[cat]...)
	}
	f.Options = flat
	f.OptionGroups = groups
}

func applyGeoIPEditionOptions(f *SettingsField) {
	free, commercial := geoip.KnownEditions()
	flat := append([]string{}, free...)
	flat = append(flat, commercial...)
	f.Options = flat
	f.OptionGroups = []OptionGroup{
		{Label: "GeoLite2 (free)", Values: free},
		{Label: "GeoIP2 (paid)", Values: commercial},
	}
}
