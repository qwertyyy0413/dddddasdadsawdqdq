package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"overbyte-cnc/theme"
)

type UIManager struct {
	basePath string
	mapping  map[string]string
}

func New(basePath string) (*UIManager, error) {
	manager := &UIManager{
		basePath: basePath,
		mapping:  make(map[string]string),
	}

	mappingPath := filepath.Join(basePath, "config/ui/ui.json")
	if err := manager.loadMapping(mappingPath); err != nil {
		manager.mapping = map[string]string{
			"home":           "home.tfx",
			"help":           "help.tfx",
			"methods":        "methods.tfx",
			"attacksent":     "attacksent.tfx",
			"stats":          "stats.tfx",
			"ongoing_header": "ongoing.tfx",
			"prompt":         "prompt.tfx",
			"admin":          "admin.tfx",
			"plan":           "plan.tfx",
		}
	}

	return manager, nil
}

func (u *UIManager) loadMapping(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(&u.mapping)
}

func (u *UIManager) GetScreen(name string, vars map[string]string) string {
	filename, exists := u.mapping[name]
	if !exists {
		return ""
	}

	content, err := u.readTFX(filename)
	if err != nil {
		return ""
	}

	return u.replaceVariables(content, vars)
}

func (u *UIManager) readTFX(filename string) (string, error) {
	path := filepath.Join(u.basePath, "config/ui", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	content := string(data)

	content = processEscapeCodes(content)

	return content, nil
}

func processEscapeCodes(content string) string {
	content = strings.ReplaceAll(content, "\\033", "\033")
	content = strings.ReplaceAll(content, "\\x1b", "\033")
	content = strings.ReplaceAll(content, "\\e", "\033")
	content = strings.ReplaceAll(content, "\\001", "\001")
	content = strings.ReplaceAll(content, "\\002", "\002")
	content = strings.ReplaceAll(content, "\\007", "\007")
	content = strings.ReplaceAll(content, "\\r\\n", "\r\n")
	content = strings.ReplaceAll(content, "\\r", "\r")
	content = strings.ReplaceAll(content, "\\n", "\n")

	return content
}

func (u *UIManager) replaceVariables(content string, vars map[string]string) string {
	result := content

	t := theme.Current()
	result = strings.ReplaceAll(result, "{primary}", t.PrimaryColor())
	result = strings.ReplaceAll(result, "{secondary}", t.SecondaryColor())
	result = strings.ReplaceAll(result, "{separator}", t.Separator)
	result = strings.ReplaceAll(result, "{success}", t.Success)
	result = strings.ReplaceAll(result, "{warning}", t.Warning)
	result = strings.ReplaceAll(result, "{error}", t.Error)
	result = strings.ReplaceAll(result, "{info}", t.Info)
	result = strings.ReplaceAll(result, "{muted}", t.Muted)
	result = strings.ReplaceAll(result, "{header}", t.Header)
	result = strings.ReplaceAll(result, "{prompt}", t.PromptColor())

	if vars != nil {
		for key, value := range vars {
			placeholder := "{" + key + "}"
			result = strings.ReplaceAll(result, placeholder, value)
		}
	}

	return result
}

func (u *UIManager) HasScreen(name string) bool {
	filename, exists := u.mapping[name]
	if !exists {
		return false
	}

	path := filepath.Join(u.basePath, "config/ui", filename)
	_, err := os.Stat(path)
	return err == nil
}
