package main

import (
	"sort"
	"strings"
)

type kubectlSnippet struct {
	Command string `json:"command"`
	Output  string `json:"output"`
}

func summarizeKubectlForPrecheck(kubectl map[string]string) []kubectlSnippet {
	if len(kubectl) == 0 {
		return nil
	}

	type item struct {
		cmd string
		out string
		err bool
	}
	items := make([]item, 0, len(kubectl))
	for cmd, out := range kubectl {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		o := strings.TrimSpace(out)
		items = append(items, item{cmd: cmd, out: o, err: strings.Contains(o, "ERROR:")})
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].err != items[j].err {
			return items[i].err && !items[j].err
		}
		return items[i].cmd < items[j].cmd
	})

	const maxItems = 24
	const maxChars = 900

	if len(items) > maxItems {
		items = items[:maxItems]
	}

	out := make([]kubectlSnippet, 0, len(items))
	for _, it := range items {
		text := it.out
		if len(text) > maxChars {
			text = strings.TrimSpace(text[:maxChars]) + "…"
		}
		out = append(out, kubectlSnippet{Command: it.cmd, Output: text})
	}
	return out
}

