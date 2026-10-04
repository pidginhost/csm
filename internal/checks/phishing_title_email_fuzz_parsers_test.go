package checks

import (
	"strings"
	"testing"
)

func FuzzPhishingTitleEmailSeparators(f *testing.F) {
	for _, title := range []string{"user@example.net", "user@example.net-", "user@", "@example.net", "jane@gmail.com", ""} {
		f.Add(title)
	}
	f.Fuzz(func(t *testing.T, title string) {
		title = strings.ToLower(title)
		// An ellipsis separates a visible brand from surrounding title text,
		// even when that text resembles an email address.
		for _, decorated := range []string{"gmail..." + title, title + "...gmail"} {
			if !titleNamesBrand(decorated, "gmail", true) {
				t.Fatalf("title separators hid a visible brand: %q", decorated)
			}
		}
	})
}
