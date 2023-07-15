package ruleset

import (
	"os"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

func NewFromFile(sourceFile string) (*RuleSet, error) {
	filedata, err := os.ReadFile(sourceFile)
	if err != nil {
		return nil, err
	}
	var ruleSet RuleSet
	err = yaml.Unmarshal(filedata, &ruleSet)
	return &ruleSet, err
}

type RuleSetWatcher struct {
	watcher        *fsnotify.Watcher
	currentRuleSet *RuleSet
}

func NewFileWatcher(sourceFile string) (*RuleSetWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	err = watcher.Add(sourceFile)
	if err != nil {
		return nil, err
	}
	current, err := NewFromFile(sourceFile)
	if err != nil {
		return nil, err
	}
	err = current.Prepare()
	if err != nil {
		return nil, err
	}
	w := &RuleSetWatcher{
		watcher:        watcher,
		currentRuleSet: current,
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				logger.Info("fsnotify watch event", "event", event)
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Chmod) || event.Has(fsnotify.Rename) {
					rs, err := NewFromFile(sourceFile)
					if err != nil {
						logger.Error(err, "unable to create ruleset from file", "file", sourceFile)
						continue
					}
					err = rs.Prepare()
					if err != nil {
						logger.Error(err, "unable to prepare ruleset")
						continue
					}
					w.currentRuleSet = rs
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Error(err, "fsnotify watch error")
			}
		}
	}()

	return w, nil
}

func (w *RuleSetWatcher) Get() *RuleSet {
	return w.currentRuleSet
}

func (w *RuleSetWatcher) Close() error {
	return w.watcher.Close()
}
