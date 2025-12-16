package main

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
)

func llmDebugEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("LLM_DEBUG")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func llmDebugBodiesEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("LLM_DEBUG_BODIES")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func sha1Hex(b []byte) string {
	sum := sha1.Sum(b)
	return hex.EncodeToString(sum[:])
}

var (
	reJSONAPIKey = regexp.MustCompile(`(?i)"apiKey"\s*:\s*"[^"]*"`)
	reBearer     = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._-]+`)
	reKeyParam   = regexp.MustCompile(`(?i)([?&]key=)[^&\s"]+`)
	// Common key formats (best-effort).
	reAIza = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{20,}`)
	reSK   = regexp.MustCompile(`sk-[0-9A-Za-z\-_]{10,}`)
)

func redactLLMSecrets(s string) string {
	if s == "" {
		return s
	}
	s = reJSONAPIKey.ReplaceAllString(s, `"apiKey":"REDACTED"`)
	s = reKeyParam.ReplaceAllString(s, `${1}REDACTED`)
	s = reBearer.ReplaceAllString(s, `Bearer REDACTED`)
	s = reAIza.ReplaceAllString(s, `AIzaREDACTED`)
	s = reSK.ReplaceAllString(s, `sk-REDACTED`)
	return s
}

func truncateForLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "…"
}

