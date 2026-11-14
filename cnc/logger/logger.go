package logger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"overbyte-cnc/config"

	"golang.org/x/term"
	"gopkg.in/natefinch/lumberjack.v2"
)

type lineRing struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newLineRing(max int) *lineRing {
	if max < 1 {
		max = 1000
	}
	return &lineRing{max: max}
}

func (r *lineRing) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) < r.max {
		r.lines = append(r.lines, line)
		return
	}
	copy(r.lines, r.lines[1:])
	r.lines[len(r.lines)-1] = line
}

func (r *lineRing) recent(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || len(r.lines) == 0 {
		return nil
	}
	if n > len(r.lines) {
		n = len(r.lines)
	}
	start := len(r.lines) - n
	out := make([]string, n)
	copy(out, r.lines[start:])
	return out
}

var globalRing *lineRing

type compositeHandler struct {
	level  *slog.LevelVar
	stderr slog.Handler
	file   slog.Handler
	ring   *lineRing
}

func (c *compositeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= c.level.Level()
}

func (c *compositeHandler) Handle(ctx context.Context, r slog.Record) error {
	if c.ring != nil {
		c.ring.add(formatRecordLine(&r))
	}
	err := c.stderr.Handle(ctx, r.Clone())
	if c.file != nil {
		err = errors.Join(err, c.file.Handle(ctx, r.Clone()))
	}
	return err
}

func (c *compositeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nc := &compositeHandler{
		level:  c.level,
		ring:   c.ring,
		stderr: c.stderr.WithAttrs(attrs),
		file:   nil,
	}
	if c.file != nil {
		nc.file = c.file.WithAttrs(attrs)
	}
	return nc
}

func (c *compositeHandler) WithGroup(name string) slog.Handler {
	nc := &compositeHandler{
		level:  c.level,
		ring:   c.ring,
		stderr: c.stderr.WithGroup(name),
		file:   nil,
	}
	if c.file != nil {
		nc.file = c.file.WithGroup(name)
	}
	return nc
}

func formatRecordLine(r *slog.Record) string {
	var b strings.Builder
	b.WriteString(r.Time.Format("2006-01-02 15:04:05"))
	b.WriteByte(' ')
	b.WriteString(r.Level.String())
	b.WriteByte(' ')
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	return b.String()
}

func parseSlogLevel(s string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Init configures slog with stderr (journald-friendly) and optional rotated file output,
// plus an in-memory ring for GetRecentLogs.
func Init(cfg config.LoggingConfig) error {
	var levelVar slog.LevelVar
	levelVar.Set(parseSlogLevel(cfg.Level))

	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "text" {
		return fmt.Errorf("logging.format must be json or text, got %q", cfg.Format)
	}

	ringMax := cfg.RingLines
	if ringMax <= 0 {
		ringMax = 1000
	}
	globalRing = newLineRing(ringMax)

	opts := &slog.HandlerOptions{
		Level: &levelVar,
	}

	var stderrHandler slog.Handler
	switch format {
	case "json":
		stderrHandler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		if term.IsTerminal(int(os.Stderr.Fd())) {
			opts.ReplaceAttr = colorizeLevelAttr
		}
		stderrHandler = slog.NewTextHandler(os.Stderr, opts)
	}

	var fileHandler slog.Handler
	if strings.TrimSpace(cfg.File) != "" {
		maxSize := cfg.MaxSizeMB
		if maxSize <= 0 {
			maxSize = 10
		}
		maxBackups := cfg.MaxBackups
		if maxBackups <= 0 {
			maxBackups = 3
		}
		lj := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     cfg.MaxAgeDays,
			Compress:   cfg.Compress,
		}
		switch format {
		case "json":
			fileHandler = slog.NewJSONHandler(lj, &slog.HandlerOptions{Level: &levelVar})
		default:
			fileHandler = slog.NewTextHandler(lj, &slog.HandlerOptions{Level: &levelVar})
		}
	}

	root := &compositeHandler{
		level:  &levelVar,
		stderr: stderrHandler,
		file:   fileHandler,
		ring:   globalRing,
	}
	slog.SetDefault(slog.New(root))
	return nil
}

func colorizeLevelAttr(groups []string, a slog.Attr) slog.Attr {
	if a.Key != slog.LevelKey {
		return a
	}
	lvl, ok := a.Value.Any().(slog.Level)
	if !ok {
		return a
	}
	var code string
	switch {
	case lvl < slog.LevelInfo:
		code = "\033[36m"
	case lvl < slog.LevelWarn:
		code = "\033[32m"
	case lvl < slog.LevelError:
		code = "\033[33m"
	default:
		code = "\033[31m"
	}
	a.Value = slog.StringValue(code + lvl.String() + "\033[0m")
	return a
}

// Close is a no-op; file output uses lumberjack which manages handles.
func Close() {}

func Debug(format string, args ...any) {
	slog.Debug(fmt.Sprintf(format, args...))
}

func Info(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...))
}

func Warn(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}

func Error(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
}

func LogAttack(username, method, target string, port, duration int) {
	slog.Info("attack",
		slog.String("user", username),
		slog.String("method", method),
		slog.String("target", target),
		slog.Int("port", port),
		slog.Int("duration_sec", duration),
	)
}

func LogLogin(username, ip string, success bool) {
	if success {
		slog.Info("login", slog.String("user", username), slog.String("ip", ip), slog.Bool("success", true))
	} else {
		slog.Warn("login", slog.String("user", username), slog.String("ip", ip), slog.Bool("success", false))
	}
}

func LogLogout(username, ip string) {
	slog.Info("logout", slog.String("user", username), slog.String("channel", ip))
}

func LogUserAction(username, action string) {
	slog.Info("user_action", slog.String("user", username), slog.String("action", action))
}

func GetRecentLogs(n int) []string {
	if globalRing == nil {
		return nil
	}
	return globalRing.recent(n)
}

// Discard sets the default logger to discard all output (tests).
func Discard() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1})))
}
