package theme

import (
	"encoding/json"
	"fmt"
	"os"
)

type Theme struct {
	Primary   string `json:"primary"`
	Secondary string `json:"secondary"`
	Separator string `json:"separator"`
	Success   string `json:"success"`
	Warning   string `json:"warning"`
	Error     string `json:"error"`
	Info      string `json:"info"`
	Muted     string `json:"muted"`
	Header    string `json:"header"`
	Prompt    string `json:"prompt"`
}

var current *Theme

func Default() *Theme {
	return &Theme{
		Primary:   "38;5;160",
		Secondary: "38;5;231",
		Separator: "38;5;245",
		Success:   "38;5;82",
		Warning:   "38;5;214",
		Error:     "38;5;160",
		Info:      "38;5;39",
		Muted:     "38;5;245",
		Header:    "38;5;231",
		Prompt:    "38;5;231",
	}
}

func Load(path string) (*Theme, error) {
	theme := Default()

	file, err := os.Open(path)
	if err != nil {
		current = theme
		return theme, nil
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(theme); err != nil {
		current = Default()
		return current, err
	}

	current = theme
	return theme, nil
}

func Current() *Theme {
	if current == nil {
		current = Default()
	}
	return current
}

func (t *Theme) Label(text string) string {
	return fmt.Sprintf("\033[%sm%s\033[0m", t.Primary, text)
}

func (t *Theme) LabelValue(label, value string) string {
	return fmt.Sprintf("\033[%sm%s \033[%sm: \033[%sm%s\033[0m",
		t.Primary, label, t.Separator, t.Secondary, value)
}

func (t *Theme) Succ(text string) string {
	return fmt.Sprintf("\033[%sm%s\033[0m", t.Success, text)
}

func (t *Theme) Err(text string) string {
	return fmt.Sprintf("\033[%sm%s\033[0m", t.Error, text)
}

func (t *Theme) Inf(text string) string {
	return fmt.Sprintf("\033[%sm%s\033[0m", t.Info, text)
}

func (t *Theme) Hint(text string) string {
	return fmt.Sprintf("\033[%sm%s\033[0m", t.Muted, text)
}

func (t *Theme) ErrorMsg(desc string) string {
	return fmt.Sprintf("\033[%smError \033[%sm: \033[%sm%s\033[0m",
		t.Error, t.Separator, t.Primary, desc)
}

func (t *Theme) SuccMsg(desc string) string {
	return fmt.Sprintf("\033[%smSuccess \033[%sm: \033[%sm%s\033[0m",
		t.Success, t.Separator, t.Secondary, desc)
}

func (t *Theme) WarningMsg(msgType, desc string) string {
	return fmt.Sprintf("\033[%sm%s \033[%sm: \033[%sm%s\033[0m",
		t.Warning, msgType, t.Separator, t.Secondary, desc)
}

func (t *Theme) UsageMsg(cmd, args string) string {
	return fmt.Sprintf("\033[%smUsage \033[%sm: \033[%sm%s \033[%sm%s\033[0m",
		t.Warning, t.Separator, t.Secondary, cmd, t.Muted, args)
}

func (t *Theme) InfoMsg(msgType, desc string) string {
	return fmt.Sprintf("\033[%sm%s \033[%sm: \033[%sm%s\033[0m",
		t.Info, msgType, t.Separator, t.Secondary, desc)
}

func (t *Theme) PromptColor() string {
	return t.Prompt
}

func (t *Theme) SecondaryColor() string {
	return t.Secondary
}

func (t *Theme) PrimaryColor() string {
	return t.Primary
}

func (t *Theme) TableSeparator(width int) string {
	sep := ""
	for i := 0; i < width; i++ {
		sep += "-"
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", t.Primary, sep)
}
