package main

// buildEvidenceForLLM reduces prompt size by avoiding full kubectl dumps and large maps.
func buildEvidenceForLLM(ev MaturityEvidence) map[string]any {
	return map[string]any{
		"cluster":           ev.Cluster,
		"collectedAt":       ev.CollectedAt,
		"kubernetesVersion": ev.KubernetesVersion,
		"nodeCount":         ev.NodeCount,
		"controlPlaneNodes": ev.ControlPlaneNodeCount,
		"zoneCount":         ev.ZoneCount,
		"zones":             ev.Zones,
		"namespaceCount":    ev.NamespaceCount,

		// High-signal detected components / counts (cheap and useful).
		"detectedAddons": ev.DetectedAddons,
		"permissions":    ev.Permissions,

		"ingressCount":       ev.IngressCount,
		"networkPolicyCount": ev.NetworkPolicyCount,
		"storageClassCount":  ev.StorageClassCount,
		"csiDriverCount":     ev.CSIDriverCount,

		"hasPrometheusOperator": ev.HasPrometheusOperator,
		"hasKubeStateMetrics":   ev.HasKubeStateMetrics,
		"hasGrafana":            ev.HasGrafana,
		"hasLoki":               ev.HasLoki,
		"hasMetricsServer":      ev.HasMetricsServer,

		// Instead of full kubectl outputs, send a bounded list of snippets.
		"kubectl": summarizeKubectlForPrecheck(ev.Kubectl),
	}
}

