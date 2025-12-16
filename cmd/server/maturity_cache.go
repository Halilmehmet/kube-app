package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"sync"
	"time"
)

type maturityEvidenceCacheEntry struct {
	ev      MaturityEvidence
	expires time.Time
}

var maturityEvidenceCacheMu sync.Mutex
var maturityEvidenceCache = map[string]maturityEvidenceCacheEntry{}

func maturityEvidenceCacheKey(clusterName string, conn *ClusterConnection) string {
	h := sha1.New()
	h.Write([]byte(clusterName))
	if conn != nil {
		h.Write([]byte{0})
		h.Write([]byte(conn.Context))
		h.Write([]byte{0})
		if conn.Insecure {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
		h.Write([]byte{0})
		h.Write(conn.Kubeconfig)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cloneEvidence(ev MaturityEvidence) MaturityEvidence {
	out := ev
	out.Zones = append([]string(nil), ev.Zones...)
	out.DetectedAddons = map[string]bool{}
	for k, v := range ev.DetectedAddons {
		out.DetectedAddons[k] = v
	}
	out.Permissions = map[string]string{}
	for k, v := range ev.Permissions {
		out.Permissions[k] = v
	}
	out.Kubectl = map[string]string{}
	for k, v := range ev.Kubectl {
		out.Kubectl[k] = v
	}
	out.InferredScores = append([]MaturityCriterionScore(nil), ev.InferredScores...)
	return out
}

func CollectMaturityEvidenceCached(ctx context.Context, clusterName string, conn *ClusterConnection) (MaturityEvidence, error) {
	ttl := time.Duration(envInt("EVIDENCE_CACHE_TTL_SECONDS", 180)) * time.Second
	if ttl <= 0 {
		return CollectMaturityEvidence(ctx, clusterName, conn)
	}
	key := maturityEvidenceCacheKey(clusterName, conn)
	now := time.Now()

	maturityEvidenceCacheMu.Lock()
	if ent, ok := maturityEvidenceCache[key]; ok && now.Before(ent.expires) {
		ev := cloneEvidence(ent.ev)
		maturityEvidenceCacheMu.Unlock()
		return ev, nil
	}
	maturityEvidenceCacheMu.Unlock()

	ev, err := CollectMaturityEvidence(ctx, clusterName, conn)
	if err != nil {
		return ev, err
	}

	maturityEvidenceCacheMu.Lock()
	maturityEvidenceCache[key] = maturityEvidenceCacheEntry{ev: cloneEvidence(ev), expires: now.Add(ttl)}
	maturityEvidenceCacheMu.Unlock()

	return ev, nil
}
