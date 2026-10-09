package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rajsinghtech/tailnetlink/internal/config"
)

// TestDocsJSONParses loads every fenced json block in the repo's markdown.
// Each block is a complete config file. A fragment or a stale field fails
// this test. config.example.json is checked the same way.
func TestDocsJSONParses(t *testing.T) {
	root := filepath.Join("..", "..")
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".md") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no markdown files found")
	}

	var blocks int
	for _, path := range paths {
		fences, err := jsonFences(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fences {
			blocks++
			dir := t.TempDir()
			file := filepath.Join(dir, "config.json")
			if err := os.WriteFile(file, []byte(f.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Load(file); err != nil {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d: %v\n%s", rel, f.line, err, f.body)
			}
		}
	}
	example := filepath.Join(root, "config.example.json")
	if _, err := config.Load(example); err != nil {
		t.Errorf("config.example.json: %v", err)
	}
	if blocks == 0 {
		t.Fatal("no json config examples found")
	}
}

type jsonFence struct {
	line int
	body string
}

func jsonFences(path string) ([]jsonFence, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	var out []jsonFence
	var buf []string
	start := 0
	in := false
	for i, line := range lines {
		if !in {
			if strings.TrimSpace(line) == "```json" {
				in = true
				start = i + 1
				buf = nil
			}
			continue
		}
		if strings.TrimSpace(line) == "```" {
			out = append(out, jsonFence{line: start, body: strings.Join(buf, "\n") + "\n"})
			in = false
			continue
		}
		buf = append(buf, line)
	}
	if in {
		return nil, fmt.Errorf("%s:%d: json fence is not closed", path, start)
	}
	return out, nil
}
