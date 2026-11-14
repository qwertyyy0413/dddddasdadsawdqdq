package cnc

import (
	"fmt"
	"strings"

	"overbyte-cnc/theme"
)

func RenderTable(headers []string, rows [][]string, widths []int, t *theme.Theme) string {
	if t == nil {
		t = theme.Current()
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\r\033[%sm%s\033[0m\r\n", t.Primary, formatRow(headers, widths)))
	totalWidth := 0
	for _, w := range widths {
		totalWidth += w
	}
	if totalWidth == 0 {
		totalWidth = 60
	}
	b.WriteString(fmt.Sprintf("\r\033[%sm%s\033[0m\r\n", t.Separator, strings.Repeat("-", totalWidth)))
	for _, row := range rows {
		b.WriteString(fmt.Sprintf("\r\033[%sm%s\033[0m\r\n", t.Secondary, formatRow(row, widths)))
	}
	b.WriteString("\r\n")
	return b.String()
}

func formatRow(cells []string, widths []int) string {
	var parts []string
	for i, cell := range cells {
		w := 10
		if i < len(widths) {
			w = widths[i]
		}
		s := truncateDisplay(cell, w)
		parts = append(parts, fmt.Sprintf("%-*s", w, s))
	}
	return strings.Join(parts, " ")
}
