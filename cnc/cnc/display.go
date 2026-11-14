package cnc

import (
	"regexp"
	"unicode/utf8"
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

func truncateDisplay(s string, max int) string {
	clean := stripANSI(s)
	if max <= 0 || utf8.RuneCountInString(clean) <= max {
		return s
	}
	ellipsis := "..."
	maxVisible := max - utf8.RuneCountInString(ellipsis)
	if maxVisible <= 0 {
		return ellipsis
	}
	runes := []rune(clean)
	if len(runes) <= maxVisible {
		return s
	}
	return string(runes[:maxVisible]) + ellipsis
}
