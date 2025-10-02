package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/containrrr/shoutrrr"
	"github.com/containrrr/shoutrrr/pkg/router"
	"github.com/containrrr/shoutrrr/pkg/types"
	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	dd, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dd
	return nil
}

type Config struct {
	Prometheus    PrometheusConfig    `yaml:"prometheus"`
	LogCollection LogCollectionConfig `yaml:"logCollection"`
	Watchers      []WatcherConfig     `yaml:"watchers"`
}

type PrometheusConfig struct {
	Enabled bool `yaml:"enabled"`
}

type LogCollectionConfig struct {
	LogRenewalInterval  Duration `yaml:"logRenewalInterval"`
	MaxHandleableLogGap int64    `yaml:"maxHandleableLogGap"`

	GoogleLogListURL string   `yaml:"googleLogListURL"`
	LogsURLs         []string `yaml:"logsURLs"`
}

type NotifierConfig struct {
	ShoutrrrURL string `yaml:"shoutrrrURL"`
}

type patternKind uint8

const (
	pkNone patternKind = iota
	pkRegex
	pkGlob
)

type WatcherConfig struct {
	Glob      string           `yaml:"glob"`   // wildcard pattern
	RegexpRaw string           `yaml:"regexp"` // raw regular expression
	Notifiers []NotifierConfig `yaml:"notifiers"`

	sender *router.ServiceRouter
	kind   patternKind    `yaml:"-"`
	re     *regexp.Regexp `yaml:"-"`
	gl     glob.Glob      `yaml:"-"`
}

func (w *WatcherConfig) Match(s string) bool {
	switch w.kind {
	case pkRegex:
		return w.re.MatchString(s)
	case pkGlob:
		return w.gl.Match(s)
	default:
		return false
	}
}
func (w *WatcherConfig) Notify(title string, message string) []error {

	return w.sender.Send(message, &types.Params{
		"title": title,
	})

}

func (c *Config) WatchersFor(s string) ([]WatcherConfig, bool) {
	if len(c.Watchers) == 0 {
		return nil, false
	}
	var out []WatcherConfig
	for _, watcher := range c.Watchers {
		if watcher.Match(s) {
			out = append(out, watcher)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func LoadConfigFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return LoadConfig(b)
}

func LoadConfig(yamlBytes []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(yamlBytes, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	// Validate presence of either googleLogListURL or logsURLs.
	if strings.TrimSpace(cfg.LogCollection.GoogleLogListURL) == "" && len(cfg.LogCollection.LogsURLs) == 0 {
		return nil, fmt.Errorf("validation: either logCollection.googleLogListURL or logCollection.logsURLs must be provided")
	}

	// Validate / prepare watchers.
	if len(cfg.Watchers) == 0 {
		return nil, fmt.Errorf("validation: at least one watcher must be provided")
	}
	for i := range cfg.Watchers {
		w := &cfg.Watchers[i]

		hasRegex := strings.TrimSpace(w.RegexpRaw) != ""
		hasQuery := strings.TrimSpace(w.Glob) != ""

		switch {
		case hasRegex && hasQuery:
			return nil, fmt.Errorf("watcher[%d]: provide only one of 'regexp' or 'glob', not both", i)

		case hasRegex:
			re, err := regexp.Compile(w.RegexpRaw)
			if err != nil {
				return nil, fmt.Errorf("watcher[%d]: invalid regexp %q: %w", i, w.RegexpRaw, err)
			}
			w.kind = pkRegex
			w.re = re

		case hasQuery:
			// Compile an efficient glob (wildcard) matcher.
			// gobwas/glob matches the entire string by default (like ^...$).
			g, err := glob.Compile(w.Glob)
			if err != nil {
				return nil, fmt.Errorf("watcher[%d]: invalid wildcard %q: %w", i, w.Glob, err)
			}
			w.kind = pkGlob
			w.gl = g

		default:
			return nil, fmt.Errorf("watcher[%d]: must provide either 'query' (wildcard) or 'regexp'", i)
		}

		if len(w.Notifiers) == 0 {
			return nil, fmt.Errorf("watcher[%d]: at least one notifier is required", i)
		}

		shoutrrrSenderURLs := []string{}

		for j, n := range w.Notifiers {
			if strings.TrimSpace(n.ShoutrrrURL) == "" {
				return nil, fmt.Errorf("watcher[%d].notifiers[%d]: shoutrrrURL is empty", i, j)
			}

			shoutrrrSenderURLs = append(shoutrrrSenderURLs, n.ShoutrrrURL)

		}

		shoutrrrSender, err := shoutrrr.NewSender(log.Default(), shoutrrrSenderURLs...)
		if err != nil {
			return nil, fmt.Errorf("watcher[%d]: unable to create sender: %s", i, err.Error())
		}
		w.sender = shoutrrrSender
	}

	return &cfg, nil
}
