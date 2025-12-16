package main

import (
	"encoding/json"
	"errors"
	"strings"
)

// normalizeLLMJSON tries to coerce common LLM outputs into raw JSON by:
// - stripping markdown code fences (``` / ```json)
// - trimming any non-JSON prefix/suffix around the first {/[ and last }/]
func normalizeLLMJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	// Strip markdown fenced blocks.
	if strings.HasPrefix(s, "```") {
		// Drop the opening fence line (``` or ```json).
		if idx := strings.Index(s, "\n"); idx >= 0 {
			s = s[idx+1:]
		} else {
			s = ""
		}
		// Drop the closing fence (last ```).
		if end := strings.LastIndex(s, "```"); end >= 0 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}

	// If it already looks like JSON, keep it.
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return strings.TrimSpace(s)
	}

	// Otherwise, try to extract the JSON-ish part.
	start := strings.IndexAny(s, "{[")
	if start >= 0 {
		s = s[start:]
	}
	s = strings.TrimSpace(s)

	lastObj := strings.LastIndex(s, "}")
	lastArr := strings.LastIndex(s, "]")
	last := lastObj
	if lastArr > last {
		last = lastArr
	}
	if last >= 0 && last+1 < len(s) {
		s = s[:last+1]
	}
	return strings.TrimSpace(s)
}

func stripTrailingCommas(s string) string {
	// Remove trailing commas before } or ] (common LLM mistake).
	// Simple loop to handle nested occurrences without regex.
	for {
		changed := false
		var b strings.Builder
		b.Grow(len(s))
		for i := 0; i < len(s); i++ {
			if s[i] == ',' {
				j := i + 1
				for j < len(s) && (s[j] == ' ' || s[j] == '\n' || s[j] == '\r' || s[j] == '\t') {
					j++
				}
				if j < len(s) && (s[j] == '}' || s[j] == ']') {
					changed = true
					// Skip the comma; keep whitespace + bracket.
					continue
				}
			}
			b.WriteByte(s[i])
		}
		if !changed {
			return s
		}
		s = b.String()
	}
}

// decodeFirstJSONObject returns the first JSON object/array from the string (ignores trailing text).
func decodeFirstJSONObject(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty")
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// coerceLLMJSON applies normalization + small repairs and returns canonical JSON for unmarshalling.
func coerceLLMJSON(s string) string {
	s = normalizeLLMJSON(s)
	s = stripTrailingCommas(s)
	if canon, err := decodeFirstJSONObject(s); err == nil && canon != "" {
		return canon
	}
	return s
}
