package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

type MaturityCriterion struct {
	Key      string   `json:"key"`
	Name     string   `json:"name"`
	Levels   []string `json:"levels"`   // len=5
	Category string   `json:"category"` // category title
}

type MaturityCategory struct {
	ID       string              `json:"id"`
	Title    string              `json:"title"`
	Target   string              `json:"target,omitempty"`
	Criteria []MaturityCriterion `json:"criteria"`
}

type MaturityCriteriaDoc struct {
	SourcePath string             `json:"sourcePath"`
	LoadedAt   time.Time          `json:"loadedAt"`
	Categories []MaturityCategory `json:"categories"`
}

type MaturityEvidence struct {
	CollectedAt                                 time.Time `json:"collectedAt"`
	Cluster                                     string    `json:"cluster"`
	KubernetesVersion                           string    `json:"kubernetesVersion,omitempty"`
	NodeCount                                   int       `json:"nodeCount,omitempty"`
	ControlPlaneNodeCount                       int       `json:"controlPlaneNodeCount,omitempty"`
	EtcdPodCount                                int       `json:"etcdPodCount,omitempty"`
	APIServerPodCount                           int       `json:"apiServerPodCount,omitempty"`
	APIServerAnonymousAuthDisabled              bool      `json:"apiServerAnonymousAuthDisabled,omitempty"`
	APIServerProfilingDisabled                  bool      `json:"apiServerProfilingDisabled,omitempty"`
	APIServerNodeRestrictionEnabled             bool      `json:"apiServerNodeRestrictionEnabled,omitempty"`
	APIServerAuthorizationMode                  string    `json:"apiServerAuthorizationMode,omitempty"`
	APIServerEncryptionEnabled                  bool      `json:"apiServerEncryptionEnabled,omitempty"`
	APIServerPSSConfigEnabled                   bool      `json:"apiServerPssConfigEnabled,omitempty"`
	ZoneCount                                   int       `json:"zoneCount,omitempty"`
	Zones                                       []string  `json:"zones,omitempty"`
	NamespaceCount                              int       `json:"namespaceCount,omitempty"`
	NamespacePSAEnforceCount                    int       `json:"namespacePsaEnforceCount,omitempty"`
	NamespacePSARestrictedCount                 int       `json:"namespacePsaRestrictedCount,omitempty"`
	DefaultServiceAccountCount                  int       `json:"defaultServiceAccountCount,omitempty"`
	DefaultServiceAccountAutomountDisabledCount int       `json:"defaultServiceAccountAutomountDisabledCount,omitempty"`
	ClusterAdminBindingCount                    int       `json:"clusterAdminBindingCount,omitempty"`
	SealedSecretCount                           int       `json:"sealedSecretCount,omitempty"`
	ExternalSecretCount                         int       `json:"externalSecretCount,omitempty"`
	TrivyReportCount                            int       `json:"trivyReportCount,omitempty"`
	CertManagerCertificateCount                 int       `json:"certManagerCertificateCount,omitempty"`
	CertManagerIssuerCount                      int       `json:"certManagerIssuerCount,omitempty"`
	CertManagerClusterIssuerCount               int       `json:"certManagerClusterIssuerCount,omitempty"`
	MutatingWebhookConfigCount                  int       `json:"mutatingWebhookConfigCount,omitempty"`
	ValidatingWebhookConfigCount                int       `json:"validatingWebhookConfigCount,omitempty"`
	WebhookCABundleCount                        int       `json:"webhookCaBundleCount,omitempty"`
	HasPrometheusOperator                       bool      `json:"hasPrometheusOperator,omitempty"`
	HasKubeStateMetrics                         bool      `json:"hasKubeStateMetrics,omitempty"`
	HasGrafana                                  bool      `json:"hasGrafana,omitempty"`
	HasLoki                                     bool      `json:"hasLoki,omitempty"`
	HasMetricsServer                            bool      `json:"hasMetricsServer,omitempty"`
	StorageClassCount                           int       `json:"storageClassCount,omitempty"`
	DefaultStorageClassName                     string    `json:"defaultStorageClassName,omitempty"`
	DefaultStorageClassProvisioner              string    `json:"defaultStorageClassProvisioner,omitempty"`
	CSIDriverCount                              int       `json:"csiDriverCount,omitempty"`
	LoadBalancerServiceCount                    int       `json:"loadBalancerServiceCount,omitempty"`
	PodDisruptionBudgetCount                    int       `json:"podDisruptionBudgetCount,omitempty"`
	APIServerHost                               string    `json:"apiServerHost,omitempty"`
	APIServerHostMatchesNode                    bool      `json:"apiServerHostMatchesNode,omitempty"`
	IngressCount                                int       `json:"ingressCount,omitempty"`
	IngressTLSCount                             int       `json:"ingressTLSCount,omitempty"`
	IngressClassCount                           int       `json:"ingressClassCount,omitempty"`
	NetworkPolicyCount                          int       `json:"networkPolicyCount,omitempty"`
	DefaultDenyNamespaceCount                   int       `json:"defaultDenyNamespaceCount,omitempty"`
	CiliumNetworkPolicyCount                    int       `json:"ciliumNetworkPolicyCount,omitempty"`
	CiliumClusterwideNetworkPolicyCount         int       `json:"ciliumClusterwideNetworkPolicyCount,omitempty"`
	ResourceQuotaCount                          int       `json:"resourceQuotaCount,omitempty"`
	LimitRangeCount                             int       `json:"limitRangeCount,omitempty"`
	HpaCount                                    int       `json:"hpaCount,omitempty"`
	SpotNodeCount                               int       `json:"spotNodeCount,omitempty"`
	NodePoolCount                               int       `json:"nodePoolCount,omitempty"`
	HasClusterAutoscaler                        bool      `json:"hasClusterAutoscaler,omitempty"`
	HelmReleaseCount                            int       `json:"helmReleaseCount,omitempty"`
	EventCount                                  int       `json:"eventCount,omitempty"`
	HasLonghorn                                 bool      `json:"hasLonghorn,omitempty"`
	LonghornBackupCount                         int       `json:"longhornBackupCount,omitempty"`
	LonghornRestoreCount                        int       `json:"longhornRestoreCount,omitempty"`
	PrometheusRuleCount                         int       `json:"prometheusRuleCount,omitempty"`
	ServiceMonitorCount                         int       `json:"serviceMonitorCount,omitempty"`
	PodMonitorCount                             int       `json:"podMonitorCount,omitempty"`
	VeleroScheduleCount                         int       `json:"veleroScheduleCount,omitempty"`
	VeleroBSLCount                              int       `json:"veleroBslCount,omitempty"`
	VeleroBSLEncrypted                          bool      `json:"veleroBslEncrypted,omitempty"`
	VeleroBackupCount                           int       `json:"veleroBackupCount,omitempty"`
	VeleroRestoreCount                          int       `json:"veleroRestoreCount,omitempty"`
	UpgradePlanCount                            int       `json:"upgradePlanCount,omitempty"`
	SystemUpgradeControllerDetected             bool      `json:"systemUpgradeControllerDetected,omitempty"`

	DetectedAddons map[string]bool          `json:"detectedAddons,omitempty"`
	Permissions    map[string]string        `json:"permissions,omitempty"` // api -> error string
	Kubectl        map[string]string        `json:"kubectl,omitempty"`     // command -> stdout (truncated)
	InferredScores []MaturityCriterionScore `json:"inferredScores,omitempty"`
}

type MaturityAnalyzeRequest struct {
	UserNotes   string                 `json:"userNotes"`
	TargetLevel string                 `json:"targetLevel,omitempty"`
	Overrides   map[string]int         `json:"overrides,omitempty"` // criterion key -> 1..5
	Answers     map[string]string      `json:"answers,omitempty"`   // criterion key -> free-text answer
	LLM         *LLMRequestConfig      `json:"llm,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

type MaturityQuestionsRequest struct {
	MaxQuestions  int               `json:"maxQuestions,omitempty"`
	MinConfidence float64           `json:"minConfidence,omitempty"` // e.g. 0.6
	LLM           *LLMRequestConfig `json:"llm,omitempty"`
	Answers       map[string]string `json:"answers,omitempty"`
	UserNotes     string            `json:"userNotes,omitempty"`
}

type MaturityQuestion struct {
	Key       string   `json:"key"`
	Category  string   `json:"category"`
	Criterion string   `json:"criterion"`
	Question  string   `json:"question"`
	Choices   []string `json:"choices,omitempty"`
	Hints     []string `json:"hints,omitempty"`
	Priority  int      `json:"priority,omitempty"` // 1 = highest
}

type MaturityQuestionsResponse struct {
	GeneratedAt time.Time          `json:"generatedAt"`
	Cluster     string             `json:"cluster"`
	Questions   []MaturityQuestion `json:"questions"`
	LLM         *LLMMetadata       `json:"llm,omitempty"`
	Note        string             `json:"note,omitempty"`
}

type MaturityCriterionScore struct {
	Key        string   `json:"key"`
	Category   string   `json:"category"`
	Criterion  string   `json:"criterion"`
	Level      int      `json:"level"` // 0..5 (0 = unscored)
	Confidence float64  `json:"confidence"`
	Rationale  string   `json:"rationale,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Missing    []string `json:"missing,omitempty"`
	NextSteps  []string `json:"nextSteps,omitempty"`
}

type MaturityCategoryScore struct {
	Category string  `json:"category"`
	Level    float64 `json:"level"`
}

type MaturityReport struct {
	GeneratedAt    time.Time                `json:"generatedAt"`
	Cluster        string                   `json:"cluster"`
	OverallLevel   float64                  `json:"overallLevel"`
	CategoryScores []MaturityCategoryScore  `json:"categoryScores"`
	CriteriaScores []MaturityCriterionScore `json:"criteriaScores"`
	Notes          string                   `json:"notes,omitempty"`
	LLM            *LLMMetadata             `json:"llm,omitempty"`
}

var (
	reMDCheckbox = regexp.MustCompile(`\\\[\s*[xX ]\s*\\\]`)
	reMDBold     = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	reMDCode     = regexp.MustCompile("`([^`]+)`")
	reMDLink     = regexp.MustCompile(`\[(?P<text>[^\]]+)\]\([^)]+\)`)
)

func cleanMarkdownCell(s string) string {
	s = strings.TrimSpace(s)
	s = reMDCheckbox.ReplaceAllString(s, "")
	s = reMDBold.ReplaceAllString(s, "$1")
	s = reMDCode.ReplaceAllString(s, "$1")
	s = reMDLink.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, `\|`, "|")
	s = strings.ReplaceAll(s, `\[`, "[")
	s = strings.ReplaceAll(s, `\]`, "]")
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimSpace(s)
}

func stableKey(categoryTitle, criterionName string) string {
	h := sha1.Sum([]byte(strings.ToLower(strings.TrimSpace(categoryTitle)) + "::" + strings.ToLower(strings.TrimSpace(criterionName))))
	return hex.EncodeToString(h[:8])
}

func LoadMaturityCriteriaDoc(path string) (MaturityCriteriaDoc, error) {
	f, err := os.Open(path)
	if err != nil {
		return MaturityCriteriaDoc{}, err
	}
	defer f.Close()

	var doc MaturityCriteriaDoc
	doc.SourcePath = path
	doc.LoadedAt = time.Now()

	var currentCategory *MaturityCategory
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "## ") {
			title := strings.TrimSpace(strings.TrimPrefix(trimmed, "## "))
			id := ""
			if parts := strings.SplitN(title, ".", 2); len(parts) == 2 {
				id = strings.TrimSpace(parts[0])
			}
			cat := MaturityCategory{ID: id, Title: title}
			doc.Categories = append(doc.Categories, cat)
			currentCategory = &doc.Categories[len(doc.Categories)-1]
			continue
		}

		// Detect the criteria table by header.
		if currentCategory == nil {
			continue
		}
		if strings.HasPrefix(trimmed, "|") && strings.Contains(trimmed, "Kriter") && strings.Contains(trimmed, "Level 1") && strings.Contains(trimmed, "Level 5") {
			// alignment row
			if !scanner.Scan() {
				break
			}
			for scanner.Scan() {
				rowLine := strings.TrimSpace(scanner.Text())
				if rowLine == "" || !strings.HasPrefix(rowLine, "|") {
					break
				}
				cells := splitMDTableRow(rowLine)
				if len(cells) < 6 {
					continue
				}
				name := cleanMarkdownCell(cells[0])
				if name == "" || strings.HasPrefix(name, ":---") {
					continue
				}
				levels := make([]string, 0, 5)
				for i := 1; i <= 5; i++ {
					levels = append(levels, cleanMarkdownCell(cells[i]))
				}
				key := stableKey(currentCategory.Title, name)
				currentCategory.Criteria = append(currentCategory.Criteria, MaturityCriterion{
					Key:      key,
					Name:     name,
					Levels:   levels,
					Category: currentCategory.Title,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return MaturityCriteriaDoc{}, err
	}

	// Drop headings without a criteria table (e.g. Executive Summary).
	filtered := doc.Categories[:0]
	for _, c := range doc.Categories {
		if len(c.Criteria) == 0 {
			continue
		}
		filtered = append(filtered, c)
	}
	doc.Categories = filtered

	return doc, nil
}

func splitMDTableRow(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")
	parts := strings.Split(trimmed, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func CollectMaturityEvidence(ctx context.Context, clusterName string, conn *ClusterConnection) (MaturityEvidence, error) {
	if conn == nil || conn.Client == nil {
		return MaturityEvidence{}, errors.New("no cluster configured")
	}
	client := conn.Client
	ev := MaturityEvidence{
		CollectedAt:    time.Now(),
		Cluster:        clusterName,
		DetectedAddons: map[string]bool{},
		Permissions:    map[string]string{},
		Kubectl:        map[string]string{},
	}

	if sv, err := client.Discovery().ServerVersion(); err == nil && sv != nil {
		ev.KubernetesVersion = sv.GitVersion
	}

	nodeAddrSet := map[string]struct{}{}
	if nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); err == nil {
		ev.NodeCount = len(nodes.Items)
		zoneSet := map[string]struct{}{}
		cpCount := 0
		nodePoolSet := map[string]struct{}{}
		spotCount := 0
		for _, n := range nodes.Items {
			if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok {
				cpCount++
			} else if _, ok := n.Labels["node-role.kubernetes.io/master"]; ok {
				cpCount++
			}
			zone := n.Labels["topology.kubernetes.io/zone"]
			if zone == "" {
				zone = n.Labels["failure-domain.beta.kubernetes.io/zone"]
			}
			if zone != "" {
				zoneSet[zone] = struct{}{}
			}
			for _, a := range n.Status.Addresses {
				addr := strings.TrimSpace(a.Address)
				if addr != "" {
					nodeAddrSet[addr] = struct{}{}
				}
			}
			// Node pool detection via common labels
			for _, key := range []string{"eks.amazonaws.com/nodegroup", "node.kubernetes.io/nodepool", "kops.k8s.io/instancegroup", "cloud.google.com/gke-nodepool"} {
				if v, ok := n.Labels[key]; ok {
					if trimmed := strings.TrimSpace(v); trimmed != "" {
						nodePoolSet[trimmed] = struct{}{}
					}
				}
			}
			// Spot/preemptible detection
			spotLabels := []string{"lifecycle", "node.kubernetes.io/lifecycle", "cloud.google.com/gke-preemptible"}
			spotDetected := false
			for _, key := range spotLabels {
				if val, ok := n.Labels[key]; ok {
					lower := strings.ToLower(strings.TrimSpace(val))
					if lower != "" && (strings.Contains(lower, "spot") || strings.Contains(lower, "preemptible")) {
						spotDetected = true
						break
					}
				}
			}
			if !spotDetected && strings.Contains(strings.ToLower(n.Name), "spot") {
				spotDetected = true
			}
			if spotDetected {
				spotCount++
			}
		}
		ev.ControlPlaneNodeCount = cpCount
		for z := range zoneSet {
			ev.Zones = append(ev.Zones, z)
		}
		sort.Strings(ev.Zones)
		ev.ZoneCount = len(ev.Zones)
		ev.NodePoolCount = len(nodePoolSet)
		ev.SpotNodeCount = spotCount
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["nodes.list"] = err.Error()
	} else {
		ev.Permissions["nodes.list"] = err.Error()
	}

	// kube-system pods: etcd/apiserver (best-effort)
	if pods, err := client.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{}); err == nil {
		etcd := 0
		apiserver := 0
		parseArgValue := func(args []string, prefix string) (string, bool) {
			for _, a := range args {
				if strings.HasPrefix(a, prefix) {
					return strings.TrimPrefix(a, prefix), true
				}
			}
			return "", false
		}
		hasArg := func(args []string, exact string) bool {
			for _, a := range args {
				if a == exact {
					return true
				}
			}
			return false
		}
		parseCommaList := func(v string) []string {
			var out []string
			for _, p := range strings.Split(v, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, p)
				}
			}
			return out
		}
		for _, p := range pods.Items {
			if p.Status.Phase != "Running" {
				continue
			}
			name := strings.ToLower(p.Name)
			switch {
			case strings.Contains(name, "etcd"):
				etcd++
			case strings.Contains(name, "kube-apiserver") || strings.Contains(name, "apiserver"):
				apiserver++
			}

			// Parse kube-apiserver flags for security posture (best-effort).
			if strings.HasPrefix(name, "kube-apiserver") || strings.Contains(name, "kube-apiserver") {
				for _, c := range p.Spec.Containers {
					args := c.Args
					if len(args) == 0 {
						continue
					}
					if hasArg(args, "--anonymous-auth=false") {
						ev.APIServerAnonymousAuthDisabled = true
					}
					if hasArg(args, "--profiling=false") {
						ev.APIServerProfilingDisabled = true
					}
					if v, ok := parseArgValue(args, "--enable-admission-plugins="); ok {
						for _, plug := range parseCommaList(v) {
							if plug == "NodeRestriction" {
								ev.APIServerNodeRestrictionEnabled = true
							}
						}
					}
					if v, ok := parseArgValue(args, "--authorization-mode="); ok {
						// Prefer the first observed value (same across nodes typically).
						if ev.APIServerAuthorizationMode == "" {
							ev.APIServerAuthorizationMode = strings.TrimSpace(v)
						}
					}
					if _, ok := parseArgValue(args, "--encryption-provider-config="); ok {
						ev.APIServerEncryptionEnabled = true
					}
					if _, ok := parseArgValue(args, "--admission-control-config-file="); ok {
						// RKE2 often uses rke2-pss.yaml here.
						ev.APIServerPSSConfigEnabled = true
					}
				}
			}
		}
		ev.EtcdPodCount = etcd
		ev.APIServerPodCount = apiserver
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["pods.kube-system.list"] = err.Error()
	} else {
		ev.Permissions["pods.kube-system.list"] = err.Error()
	}

	if ds, err := client.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{}); err == nil {
		for _, item := range ds.Items {
			lower := strings.ToLower(item.Name)
			if strings.Contains(lower, "cilium") {
				ev.DetectedAddons["cilium.ds"] = true
				break
			}
		}
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["daemonsets.kube-system.list"] = err.Error()
	} else {
		ev.Permissions["daemonsets.kube-system.list"] = err.Error()
	}

	checkWorkloads := func(ns string, keywords []string) bool {
		if ns == "" {
			ns = "monitoring"
		}
		var names []string
		if deps, err := client.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{}); err == nil {
			for _, d := range deps.Items {
				names = append(names, strings.ToLower(d.Name))
			}
		}
		if sts, err := client.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{}); err == nil {
			for _, s := range sts.Items {
				names = append(names, strings.ToLower(s.Name))
			}
		}
		if dss, err := client.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{}); err == nil {
			for _, d := range dss.Items {
				names = append(names, strings.ToLower(d.Name))
			}
		}
		for _, name := range names {
			for _, kw := range keywords {
				if strings.Contains(name, kw) {
					return true
				}
			}
		}
		return false
	}

	checkDeploymentAny := func(namespaces []string, keywords []string) bool {
		for _, ns := range namespaces {
			if checkWorkloads(ns, keywords) {
				return true
			}
		}
		return false
	}

	monitoringNamespaces := []string{"monitoring", "kube-system", "cattle-monitoring-system", "cattle-monitoring"}

	if checkDeploymentAny(monitoringNamespaces, []string{"prometheus-operator", "prometheus"}) {
		ev.HasPrometheusOperator = true
	}
	if checkDeploymentAny(monitoringNamespaces, []string{"kube-state-metrics"}) {
		ev.HasKubeStateMetrics = true
	}
	if checkDeploymentAny(monitoringNamespaces, []string{"grafana"}) {
		ev.HasGrafana = true
	}
	if checkDeploymentAny(monitoringNamespaces, []string{"loki"}) {
		ev.HasLoki = true
	}
	if checkWorkloads("kube-system", []string{"cluster-autoscaler", "kube-system-cluster-autoscaler", "clusterautoscaler"}) {
		ev.HasClusterAutoscaler = true
		ev.DetectedAddons["cluster-autoscaler"] = true
	}
	if checkWorkloads("kube-system", []string{"metrics-server"}) {
		ev.HasMetricsServer = true
	}
	if checkWorkloads("cattle-system", []string{"system-upgrade-controller"}) {
		ev.SystemUpgradeControllerDetected = true
		ev.DetectedAddons["system-upgrade-controller"] = true
	}

	// kubeconfig endpoint host heuristic (LB vs node IP)
	if len(conn.Kubeconfig) > 0 {
		if host := extractAPIServerHostFromKubeconfig(conn.Kubeconfig, conn.Context); host != "" {
			ev.APIServerHost = host
			if _, ok := nodeAddrSet[host]; ok {
				ev.APIServerHostMatchesNode = true
			}
		}
	}

	if nss, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err == nil {
		ev.NamespaceCount = len(nss.Items)
		for _, ns := range nss.Items {
			name := ns.Name
			lower := strings.ToLower(name)
			switch name {
			case "cert-manager", "monitoring", "prometheus", "argocd", "velero", "istio-system", "linkerd", "gatekeeper-system", "kyverno", "flux-system":
				ev.DetectedAddons[name] = true
			}
			// Heuristic namespace detection
			if strings.Contains(lower, "grafana") {
				ev.DetectedAddons["grafana"] = true
			}
			if strings.Contains(lower, "prometheus") || lower == "monitoring" {
				ev.DetectedAddons["prometheus"] = true
			}
			if strings.Contains(lower, "loki") {
				ev.DetectedAddons["loki"] = true
			}
			if strings.Contains(lower, "elastic") || strings.Contains(lower, "elasticsearch") {
				ev.DetectedAddons["elasticsearch"] = true
			}
			if strings.Contains(lower, "kibana") {
				ev.DetectedAddons["kibana"] = true
			}
			if strings.Contains(lower, "logging") {
				ev.DetectedAddons["logging"] = true
			}
			if strings.Contains(lower, "longhorn") {
				ev.DetectedAddons["longhorn"] = true
				ev.HasLonghorn = true
			}
			if strings.Contains(lower, "kubecost") || strings.Contains(lower, "cost") || strings.Contains(lower, "opencost") {
				ev.DetectedAddons["kubecost"] = true
			}
			if strings.Contains(lower, "tekton") {
				ev.DetectedAddons["tekton"] = true
			}
			if strings.Contains(lower, "harbor") {
				ev.DetectedAddons["harbor"] = true
			}
			if v := strings.ToLower(strings.TrimSpace(ns.Labels["pod-security.kubernetes.io/enforce"])); v != "" {
				ev.NamespacePSAEnforceCount++
				if v == "restricted" {
					ev.NamespacePSARestrictedCount++
				}
			}
		}
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["namespaces.list"] = err.Error()
	} else {
		ev.Permissions["namespaces.list"] = err.Error()
	}

	// Cilium detection via kube-system DaemonSet (best-effort).
	if ds, err := client.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{}); err == nil {
		for _, item := range ds.Items {
			lower := strings.ToLower(item.Name)
			if strings.Contains(lower, "cilium") {
				ev.DetectedAddons["cilium.ds"] = true
				break
			}
		}
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["daemonsets.kube-system.list"] = err.Error()
	} else {
		ev.Permissions["daemonsets.kube-system.list"] = err.Error()
	}

	if sas, err := client.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{}); err == nil {
		defaultCount := 0
		disabled := 0
		for _, sa := range sas.Items {
			if sa.Name != "default" {
				continue
			}
			defaultCount++
			if sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken {
				disabled++
			}
		}
		ev.DefaultServiceAccountCount = defaultCount
		ev.DefaultServiceAccountAutomountDisabledCount = disabled
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["serviceaccounts.list"] = err.Error()
	} else {
		ev.Permissions["serviceaccounts.list"] = err.Error()
	}

	if crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); err == nil {
		count := 0
		for _, b := range crbs.Items {
			if b.RoleRef.APIGroup != rbacv1.GroupName {
				continue
			}
			if b.RoleRef.Kind == "ClusterRole" && b.RoleRef.Name == "cluster-admin" {
				count++
			}
		}
		ev.ClusterAdminBindingCount = count
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["clusterrolebindings.list"] = err.Error()
	} else {
		ev.Permissions["clusterrolebindings.list"] = err.Error()
	}

	if scs, err := client.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{}); err == nil {
		ev.StorageClassCount = len(scs.Items)
		for _, sc := range scs.Items {
			ann := sc.Annotations
			if ann == nil {
				ann = map[string]string{}
			}
			if ann["storageclass.kubernetes.io/is-default-class"] == "true" || ann["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
				ev.DefaultStorageClassName = sc.Name
				ev.DefaultStorageClassProvisioner = sc.Provisioner
				break
			}
		}
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["storageclasses.list"] = err.Error()
	} else {
		ev.Permissions["storageclasses.list"] = err.Error()
	}

	if drivers, err := client.StorageV1().CSIDrivers().List(ctx, metav1.ListOptions{}); err == nil {
		ev.CSIDriverCount = len(drivers.Items)
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["csidrivers.list"] = err.Error()
	} else {
		ev.Permissions["csidrivers.list"] = err.Error()
	}

	if svcs, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{}); err == nil {
		lb := 0
		for _, s := range svcs.Items {
			if strings.EqualFold(string(s.Spec.Type), "LoadBalancer") {
				lb++
			}
		}
		ev.LoadBalancerServiceCount = lb
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["services.list"] = err.Error()
	} else {
		ev.Permissions["services.list"] = err.Error()
	}

	if pdbs, err := client.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{}); err == nil {
		ev.PodDisruptionBudgetCount = len(pdbs.Items)
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["poddisruptionbudgets.list"] = err.Error()
	} else {
		ev.Permissions["poddisruptionbudgets.list"] = err.Error()
	}

	if ics, err := client.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{}); err == nil {
		ev.IngressClassCount = len(ics.Items)
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["ingressclasses.list"] = err.Error()
	} else {
		ev.Permissions["ingressclasses.list"] = err.Error()
	}

	if ings, err := client.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{}); err == nil {
		ev.IngressCount = len(ings.Items)
		tlsCount := 0
		for _, ing := range ings.Items {
			if len(ing.Spec.TLS) > 0 {
				tlsCount++
			}
		}
		ev.IngressTLSCount = tlsCount
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["ingresses.list"] = err.Error()
	} else {
		ev.Permissions["ingresses.list"] = err.Error()
	}

	if nps, err := client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{}); err == nil {
		ev.NetworkPolicyCount = len(nps.Items)
		defaultDenyNS := map[string]struct{}{}
		for _, np := range nps.Items {
			if len(np.Spec.PodSelector.MatchLabels) != 0 || len(np.Spec.PodSelector.MatchExpressions) != 0 {
				continue
			}
			pt := map[networkingv1.PolicyType]bool{}
			for _, t := range np.Spec.PolicyTypes {
				pt[t] = true
			}
			denyIngress := pt[networkingv1.PolicyTypeIngress] && len(np.Spec.Ingress) == 0
			denyEgress := pt[networkingv1.PolicyTypeEgress] && len(np.Spec.Egress) == 0
			if denyIngress || denyEgress {
				defaultDenyNS[np.Namespace] = struct{}{}
			}
		}
		ev.DefaultDenyNamespaceCount = len(defaultDenyNS)
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["networkpolicies.list"] = err.Error()
	} else {
		ev.Permissions["networkpolicies.list"] = err.Error()
	}

	if rqs, err := client.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{}); err == nil {
		ev.ResourceQuotaCount = len(rqs.Items)
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["resourcequotas.list"] = err.Error()
	} else {
		ev.Permissions["resourcequotas.list"] = err.Error()
	}

	if lrs, err := client.CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{}); err == nil {
		ev.LimitRangeCount = len(lrs.Items)
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["limitranges.list"] = err.Error()
	} else {
		ev.Permissions["limitranges.list"] = err.Error()
	}

	if hpas, err := client.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{}); err == nil {
		ev.HpaCount = len(hpas.Items)
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["hpas.list"] = err.Error()
	} else {
		ev.Permissions["hpas.list"] = err.Error()
	}

	// Best-effort addon checks via API discovery.
	if _, err := client.Discovery().ServerResourcesForGroupVersion(storagev1.SchemeGroupVersion.String()); err == nil {
		ev.DetectedAddons["storagev1"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion(networkingv1.SchemeGroupVersion.String()); err == nil {
		ev.DetectedAddons["networkingv1"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion(autoscalingv2.SchemeGroupVersion.String()); err == nil {
		ev.DetectedAddons["autoscalingv2"] = true
	}
	// Common addon CRDs
	if _, err := client.Discovery().ServerResourcesForGroupVersion("cert-manager.io/v1"); err == nil {
		ev.DetectedAddons["cert-manager.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("kyverno.io/v1"); err == nil {
		ev.DetectedAddons["kyverno.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("templates.gatekeeper.sh/v1"); err == nil {
		ev.DetectedAddons["gatekeeper.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("argoproj.io/v1alpha1"); err == nil {
		ev.DetectedAddons["argocd.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("velero.io/v1"); err == nil {
		ev.DetectedAddons["velero.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("monitoring.coreos.com/v1"); err == nil {
		ev.DetectedAddons["prometheus-operator.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("networking.istio.io/v1beta1"); err == nil {
		ev.DetectedAddons["istio.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("linkerd.io/v1alpha2"); err == nil {
		ev.DetectedAddons["linkerd.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("kiali.io/v1alpha1"); err == nil {
		ev.DetectedAddons["kiali.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("cilium.io/v2"); err == nil {
		ev.DetectedAddons["cilium.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("external-secrets.io/v1beta1"); err == nil {
		ev.DetectedAddons["external-secrets.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("bitnami.com/v1alpha1"); err == nil {
		ev.DetectedAddons["sealed-secrets.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("aquasecurity.github.io/v1alpha1"); err == nil {
		ev.DetectedAddons["trivy-operator.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("upgrade.cattle.io/v1"); err == nil {
		ev.DetectedAddons["system-upgrade.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("tekton.dev/v1"); err == nil {
		ev.DetectedAddons["tekton.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("kubecost.com/v1"); err == nil {
		ev.DetectedAddons["kubecost.crd"] = true
	}
	if _, err := client.Discovery().ServerResourcesForGroupVersion("wgpolicyk8s.io/v1alpha2"); err == nil {
		ev.DetectedAddons["policy-report.crd"] = true
	}

	// Webhook configurations (best-effort)
	if mws, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{}); err == nil {
		ev.MutatingWebhookConfigCount = len(mws.Items)
		ca := 0
		for _, w := range mws.Items {
			for _, wh := range w.Webhooks {
				if len(wh.ClientConfig.CABundle) > 0 {
					ca++
					break
				}
			}
		}
		ev.WebhookCABundleCount += ca
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["mutatingwebhookconfigurations.list"] = err.Error()
	} else {
		ev.Permissions["mutatingwebhookconfigurations.list"] = err.Error()
	}
	if vws, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{}); err == nil {
		ev.ValidatingWebhookConfigCount = len(vws.Items)
		ca := 0
		for _, w := range vws.Items {
			for _, wh := range w.Webhooks {
				if len(wh.ClientConfig.CABundle) > 0 {
					ca++
					break
				}
			}
		}
		ev.WebhookCABundleCount += ca
	} else if apierrors.IsForbidden(err) {
		ev.Permissions["validatingwebhookconfigurations.list"] = err.Error()
	} else {
		ev.Permissions["validatingwebhookconfigurations.list"] = err.Error()
	}

	collectKubectlEvidence(ctx, conn, &ev)
	return ev, nil
}

func extractAPIServerHostFromKubeconfig(kubeconfig []byte, contextName string) string {
	cfg, err := clientcmd.Load(kubeconfig)
	if err != nil || cfg == nil {
		return ""
	}
	if contextName == "" {
		contextName = cfg.CurrentContext
	}
	ctx, ok := cfg.Contexts[contextName]
	if !ok || ctx == nil || ctx.Cluster == "" {
		return ""
	}
	cluster, ok := cfg.Clusters[ctx.Cluster]
	if !ok || cluster == nil || cluster.Server == "" {
		return ""
	}
	u, err := url.Parse(cluster.Server)
	if err != nil {
		return ""
	}
	host := strings.TrimSpace(u.Hostname())
	return host
}

func InferScoresFromEvidence(doc MaturityCriteriaDoc, ev MaturityEvidence) []MaturityCriterionScore {
	hasAddon := func(keys ...string) bool {
		for _, k := range keys {
			if ev.DetectedAddons[k] {
				return true
			}
		}
		return false
	}
	hasPermErr := func(key string) bool {
		if ev.Permissions == nil {
			return false
		}
		_, ok := ev.Permissions[key]
		return ok
	}

	hasKubectlCmd := func(keyword string) bool {
		if ev.Kubectl == nil {
			return false
		}
		for cmd := range ev.Kubectl {
			if strings.Contains(strings.ToLower(cmd), strings.ToLower(keyword)) {
				return true
			}
		}
		return false
	}

	hasKubectlError := func() bool {
		if ev.Kubectl == nil {
			return false
		}
		for _, out := range ev.Kubectl {
			if strings.Contains(out, "ERROR:") {
				return true
			}
		}
		return false
	}

	handlers := []struct {
		match func(name string) bool
		eval  func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string)
	}{
		{
			match: func(name string) bool { return strings.EqualFold(name, "Control Plane Redundancy") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				cp := ev.ControlPlaneNodeCount
				if cp <= 0 {
					return 0, 0, "Control plane node label bilgisi yok.", []string{"node labels: node-role.kubernetes.io/control-plane/master"}
				}
				level := 1
				if cp == 2 {
					level = 2
				} else if cp >= 3 {
					level = 3
				}
				r := fmt.Sprintf("Auto (cluster): controlPlaneNodeCount=%d, zoneCount=%d", cp, ev.ZoneCount)
				return level, 0.7, r, []string{"nodes.list", fmt.Sprintf("controlPlaneNodeCount=%d", cp)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "etcd Konfigürasyonu") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("pods.kube-system.list") {
					return 0, 0, "etcd bilgisi alınamadı (kube-system pod list izni yok).", []string{"pods.kube-system.list"}
				}
				if ev.EtcdPodCount == 0 {
					return 0, 0, "etcd pod tespit edilemedi (managed control-plane olabilir).", []string{fmt.Sprintf("etcdPodCount=%d", ev.EtcdPodCount)}
				}
				if ev.EtcdPodCount == 1 {
					return 1, 0.65, "Auto (cluster): Tek etcd pod görünüyor.", []string{fmt.Sprintf("etcdPodCount=%d", ev.EtcdPodCount)}
				}
				if ev.EtcdPodCount >= 5 {
					return 4, 0.55, "Auto (cluster): 5+ etcd pod görünüyor (snapshot policy doğrulanmalı).", []string{fmt.Sprintf("etcdPodCount=%d", ev.EtcdPodCount)}
				}
				return 3, 0.6, "Auto (cluster): 3+ etcd pod görünüyor (backup/auto doğrulanmalı).", []string{fmt.Sprintf("etcdPodCount=%d", ev.EtcdPodCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "API Server LB") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				// Heuristic: if kubeconfig host matches a node IP, likely direct access to a node; otherwise likely LB/DNS.
				if ev.APIServerHost == "" {
					return 0, 0, "API endpoint host tespit edilemedi.", []string{}
				}
				if ev.APIServerHostMatchesNode {
					return 1, 0.55, "Auto (cluster): API endpoint bir node adresi gibi görünüyor (LB doğrulanmadı).", []string{"apiServerHostMatchesNode=true"}
				}
				level := 3
				conf := 0.55
				if ev.ControlPlaneNodeCount >= 3 {
					level = 4
					conf = 0.5
				}
				return level, conf, "Auto (cluster): API endpoint node adresi değil (LB/DNS olma ihtimali).", []string{"apiServerHost=" + ev.APIServerHost}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Drift Detection") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("argocd", "argocd.crd") || hasAddon("flux-system") {
					return 4, 0.55, "Auto (cluster): GitOps aracı tespit edildi (drift detection/reconcile varsayımı).", []string{}
				}
				return 0, 0, "Drift detection otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool {
				return strings.EqualFold(name, "Upgrade Planlama") ||
					strings.EqualFold(name, "Control Plane Upgrade") ||
					strings.EqualFold(name, "Worker Node Upgrade") ||
					strings.EqualFold(name, "Rollback Capability")
			},
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.UpgradePlanCount > 0 {
					return 4, 0.6, "Auto (cluster): system-upgrade plan tespit edildi (otomasyon varsayımı).", []string{
						fmt.Sprintf("upgradePlanCount=%d", ev.UpgradePlanCount),
					}
				}
				if ev.SystemUpgradeControllerDetected || hasAddon("system-upgrade.crd") || hasAddon("system-upgrade-controller") {
					return 3, 0.55, "Auto (cluster): system-upgrade-controller/CRD tespit edildi (plan detayları doğrulanmalı).", []string{}
				}
				return 0, 0, "Upgrade/rollback otomasyonu otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Version Control") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("argocd", "argocd.crd") || hasAddon("flux-system") {
					return 4, 0.55, "Auto (cluster): GitOps tespit edildi (version control + ops varsayımı).", []string{}
				}
				return 0, 0, "Version control seviyesi otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "NetworkPolicy Adoption") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("networkpolicies.list") {
					return 0, 0, "NetworkPolicy bilgisi alınamadı (izin/erişim).", []string{"networkpolicies.list"}
				}
				ciliumTotal := ev.CiliumNetworkPolicyCount + ev.CiliumClusterwideNetworkPolicyCount
				if ev.NetworkPolicyCount == 0 && ciliumTotal > 0 {
					level := 2
					conf := 0.65
					r := "Auto (cluster): Kubernetes NetworkPolicy yok ama CiliumNetworkPolicy mevcut (default-deny/kapsam doğrulanmalı)."
					if ev.CiliumClusterwideNetworkPolicyCount > 0 {
						level = 3
						conf = 0.6
					}
					return level, conf, r, []string{
						fmt.Sprintf("networkPolicyCount=%d", ev.NetworkPolicyCount),
						fmt.Sprintf("ciliumNetworkPolicyCount=%d", ev.CiliumNetworkPolicyCount),
						fmt.Sprintf("ciliumClusterwideNetworkPolicyCount=%d", ev.CiliumClusterwideNetworkPolicyCount),
					}
				}
				if ev.NetworkPolicyCount == 0 {
					return 1, 0.8, "Auto (cluster): NetworkPolicy bulunamadı.", []string{fmt.Sprintf("networkPolicyCount=%d", ev.NetworkPolicyCount)}
				}
				if ev.DefaultDenyNamespaceCount > 0 {
					level := 3
					conf := 0.65
					if ev.NamespaceCount > 0 && float64(ev.DefaultDenyNamespaceCount)/float64(ev.NamespaceCount) >= 0.8 {
						level = 4
						conf = 0.6
					}
					return level, conf, "Auto (cluster): Default-deny NetworkPolicy tespit edildi (kapsam doğrulanmalı).", []string{
						fmt.Sprintf("networkPolicyCount=%d", ev.NetworkPolicyCount),
						fmt.Sprintf("defaultDenyNamespaceCount=%d", ev.DefaultDenyNamespaceCount),
					}
				}
				return 2, 0.7, "Auto (cluster): NetworkPolicy mevcut (default-deny tespit edilmedi).", []string{fmt.Sprintf("networkPolicyCount=%d", ev.NetworkPolicyCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "CNI Support") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				cilium := ev.DetectedAddons["cilium.crd"] || ev.DetectedAddons["cilium.ds"] || ev.CiliumNetworkPolicyCount > 0 || ev.CiliumClusterwideNetworkPolicyCount > 0
				if !cilium {
					return 0, 0, "CNI türü otomatik tespit edilemedi.", []string{}
				}
				if ev.CiliumNetworkPolicyCount+ev.CiliumClusterwideNetworkPolicyCount > 0 {
					return 4, 0.6, "Auto (cluster): Cilium + CiliumNetworkPolicy tespit edildi (advanced varsayımı, doğrula).", []string{
						fmt.Sprintf("ciliumNetworkPolicyCount=%d", ev.CiliumNetworkPolicyCount),
						fmt.Sprintf("ciliumClusterwideNetworkPolicyCount=%d", ev.CiliumClusterwideNetworkPolicyCount),
					}
				}
				return 3, 0.6, "Auto (cluster): Cilium tespit edildi (prod readiness doğrulanmalı).", []string{"cilium.io/v2 or kube-system daemonset"}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Egress Control") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.CiliumClusterwideNetworkPolicyCount > 0 {
					return 3, 0.55, "Auto (cluster): Cilium clusterwide policy mevcut (egress kontrol varsayımı, doğrula).", []string{
						fmt.Sprintf("ciliumClusterwideNetworkPolicyCount=%d", ev.CiliumClusterwideNetworkPolicyCount),
					}
				}
				if ev.CiliumNetworkPolicyCount > 0 {
					return 2, 0.5, "Auto (cluster): CiliumNetworkPolicy mevcut (egress kapsamı doğrulanmalı).", []string{
						fmt.Sprintf("ciliumNetworkPolicyCount=%d", ev.CiliumNetworkPolicyCount),
					}
				}
				return 0, 0, "Egress kontrolü otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Webhook Certs") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("mutatingwebhookconfigurations.list") && hasPermErr("validatingwebhookconfigurations.list") {
					return 0, 0, "Webhook bilgisi alınamadı (izin/erişim).", []string{"mutatingwebhookconfigurations.list", "validatingwebhookconfigurations.list"}
				}
				if ev.WebhookCABundleCount == 0 {
					if hasAddon("cert-manager", "cert-manager.crd") {
						return 3, 0.55, "Auto (cluster): cert-manager var ama webhook CA bundle tespit edilmedi (doğrula).", []string{
							fmt.Sprintf("mutatingWebhookConfigCount=%d", ev.MutatingWebhookConfigCount),
							fmt.Sprintf("validatingWebhookConfigCount=%d", ev.ValidatingWebhookConfigCount),
						}
					}
					return 1, 0.6, "Auto (cluster): Webhook CA bundle tespit edilmedi.", []string{
						fmt.Sprintf("mutatingWebhookConfigCount=%d", ev.MutatingWebhookConfigCount),
						fmt.Sprintf("validatingWebhookConfigCount=%d", ev.ValidatingWebhookConfigCount),
					}
				}
				level := 3
				conf := 0.6
				if hasAddon("cert-manager", "cert-manager.crd") {
					level = 4
					conf = 0.55
				}
				return level, conf, "Auto (cluster): Webhook CA bundle tespit edildi (otomasyon/pinning doğrulanmalı).", []string{
					fmt.Sprintf("webhookCaBundleCount=%d", ev.WebhookCABundleCount),
				}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Cert Rotation") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.CertManagerCertificateCount > 0 || ev.CertManagerIssuerCount > 0 || ev.CertManagerClusterIssuerCount > 0 {
					return 3, 0.6, "Auto (cluster): cert-manager Certificate/Issuer tespit edildi (auto-renew varsayımı, doğrula).", []string{
						fmt.Sprintf("certificates=%d", ev.CertManagerCertificateCount),
						fmt.Sprintf("issuers=%d", ev.CertManagerIssuerCount),
						fmt.Sprintf("clusterIssuers=%d", ev.CertManagerClusterIssuerCount),
					}
				}
				if hasAddon("cert-manager", "cert-manager.crd") {
					return 2, 0.55, "Auto (cluster): cert-manager tespit edildi (Certificate/Issuer listesi boş olabilir).", []string{}
				}
				return 1, 0.6, "Auto (cluster): Sertifika rotasyonu tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Secrets Mgmt") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.SealedSecretCount > 0 || hasAddon("sealed-secrets.crd") {
					return 4, 0.6, "Auto (cluster): Sealed Secrets tespit edildi (kapsam doğrulanmalı).", []string{
						fmt.Sprintf("sealedSecretCount=%d", ev.SealedSecretCount),
					}
				}
				if ev.ExternalSecretCount > 0 || hasAddon("external-secrets.crd") {
					return 3, 0.6, "Auto (cluster): External Secrets tespit edildi (backend/Vault/KMS doğrulanmalı).", []string{
						fmt.Sprintf("externalSecretCount=%d", ev.ExternalSecretCount),
					}
				}
				return 1, 0.55, "Auto (cluster): Secrets yönetimi aracı tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Image Scanning") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.TrivyReportCount > 0 || hasAddon("trivy-operator.crd") {
					return 2, 0.6, "Auto (cluster): Trivy Operator/raporları tespit edildi (pipeline/registry doğrulanmalı).", []string{
						fmt.Sprintf("trivyReportCount=%d", ev.TrivyReportCount),
					}
				}
				return 1, 0.55, "Auto (cluster): Image scanning aracı tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "API Server Config") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				// Best-effort: kube-apiserver static pod args (RKE2/K8s self-managed).
				if !ev.APIServerAnonymousAuthDisabled && ev.APIServerAuthorizationMode == "" && !ev.APIServerNodeRestrictionEnabled && !ev.APIServerEncryptionEnabled && !ev.APIServerPSSConfigEnabled {
					return 0, 0, "API server config otomatik tespit edilemedi (kube-apiserver arg bilgisi yok/izin yok olabilir).", []string{}
				}
				level := 2
				conf := 0.55
				if ev.APIServerAnonymousAuthDisabled && strings.Contains(strings.ToUpper(ev.APIServerAuthorizationMode), "RBAC") {
					level = 3
					conf = 0.6
				}
				if level >= 3 && ev.APIServerNodeRestrictionEnabled && ev.APIServerProfilingDisabled {
					level = 4
					conf = 0.6
				}
				if level >= 4 && ev.APIServerEncryptionEnabled && ev.APIServerPSSConfigEnabled {
					level = 5
					conf = 0.55
				}
				return level, conf, "Auto (cluster): kube-apiserver arg’larından güvenlik konfigürasyonu sinyali alındı (audit vb. ayrı doğrulanmalı).", []string{
					fmt.Sprintf("apiServerAnonymousAuthDisabled=%t", ev.APIServerAnonymousAuthDisabled),
					fmt.Sprintf("apiServerAuthorizationMode=%s", ev.APIServerAuthorizationMode),
					fmt.Sprintf("apiServerNodeRestrictionEnabled=%t", ev.APIServerNodeRestrictionEnabled),
					fmt.Sprintf("apiServerProfilingDisabled=%t", ev.APIServerProfilingDisabled),
					fmt.Sprintf("apiServerEncryptionEnabled=%t", ev.APIServerEncryptionEnabled),
					fmt.Sprintf("apiServerPssConfigEnabled=%t", ev.APIServerPSSConfigEnabled),
				}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "etcd Encryption") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				// etcd at-rest encryption is configured via kube-apiserver flag.
				if ev.APIServerEncryptionEnabled {
					return 4, 0.7, "Auto (cluster): kube-apiserver üzerinde encryption-provider-config tespit edildi (at-rest encryption varsayımı).", []string{
						"apiServerEncryptionEnabled=true",
					}
				}
				if ev.APIServerPodCount > 0 {
					return 1, 0.6, "Auto (cluster): encryption-provider-config tespit edilmedi (at-rest encryption belirsiz).", []string{
						"apiServerEncryptionEnabled=false",
					}
				}
				return 0, 0, "etcd encryption otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Ingress HTTPS") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("ingresses.list") {
					return 0, 0, "Ingress bilgisi alınamadı (izin/erişim).", []string{"ingresses.list"}
				}
				if ev.IngressCount == 0 {
					return 0, 0, "Ingress bulunamadı.", []string{fmt.Sprintf("ingressCount=%d", ev.IngressCount)}
				}
				if ev.IngressTLSCount == 0 {
					return 1, 0.75, "Auto (cluster): TLS tanımlı Ingress yok.", []string{fmt.Sprintf("ingressTLSCount=%d", ev.IngressTLSCount)}
				}
				return 2, 0.65, "Auto (cluster): TLS tanımlı Ingress var (tam kapsama doğrulanmadı).", []string{fmt.Sprintf("ingressTLSCount=%d", ev.IngressTLSCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Ingress Controller") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("ingressclasses.list") && hasPermErr("ingresses.list") {
					return 0, 0, "IngressClass/Ingress bilgisi alınamadı (izin/erişim).", []string{"ingressclasses.list", "ingresses.list"}
				}
				if ev.IngressClassCount == 0 && ev.IngressCount == 0 {
					return 1, 0.75, "Auto (cluster): IngressClass/Ingress bulunamadı.", []string{fmt.Sprintf("ingressClassCount=%d", ev.IngressClassCount), fmt.Sprintf("ingressCount=%d", ev.IngressCount)}
				}
				if ev.IngressClassCount > 0 {
					if ev.IngressCount > 0 {
						return 3, 0.6, "Auto (cluster): IngressClass ve Ingress mevcut (prod readiness doğrulanmadı).", []string{fmt.Sprintf("ingressClassCount=%d", ev.IngressClassCount), fmt.Sprintf("ingressCount=%d", ev.IngressCount)}
					}
					return 2, 0.6, "Auto (cluster): IngressClass mevcut.", []string{fmt.Sprintf("ingressClassCount=%d", ev.IngressClassCount)}
				}
				return 2, 0.5, "Auto (cluster): Ingress mevcut (IngressClass listesi yok/izin yok olabilir).", []string{fmt.Sprintf("ingressCount=%d", ev.IngressCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Load Balancer") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("services.list") {
					return 0, 0, "Service listesi alınamadı (LoadBalancer tespiti yapılamadı).", []string{"services.list"}
				}
				if ev.LoadBalancerServiceCount == 0 {
					return 1, 0.6, "Auto (cluster): LoadBalancer type Service bulunamadı.", []string{
						fmt.Sprintf("loadBalancerServiceCount=%d", ev.LoadBalancerServiceCount),
					}
				}
				if ev.LoadBalancerServiceCount >= 3 {
					return 4, 0.55, "Auto (cluster): Birden fazla LoadBalancer type Service var (LB katmanı varsayımı).", []string{
						fmt.Sprintf("loadBalancerServiceCount=%d", ev.LoadBalancerServiceCount),
					}
				}
				return 3, 0.6, "Auto (cluster): LoadBalancer type Service tespit edildi.", []string{
					fmt.Sprintf("loadBalancerServiceCount=%d", ev.LoadBalancerServiceCount),
				}
			},
		},
		{
			match: func(name string) bool {
				return strings.EqualFold(name, "TLS Certificate") || strings.EqualFold(name, "cert-manager")
			},
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("cert-manager", "cert-manager.crd") {
					return 3, 0.75, "Auto (cluster): cert-manager tespit edildi.", []string{"namespace=cert-manager or CRD cert-manager.io/v1"}
				}
				if ev.IngressTLSCount > 0 {
					return 2, 0.55, "Auto (cluster): TLS kullanılan Ingress var (cert-manager tespit edilmedi).", []string{fmt.Sprintf("ingressTLSCount=%d", ev.IngressTLSCount)}
				}
				return 1, 0.6, "Auto (cluster): TLS otomasyonu tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "TLS Terminasyonu") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.IngressCount == 0 {
					return 0, 0, "Ingress yok (TLS terminasyonu tespit edilemedi).", []string{fmt.Sprintf("ingressCount=%d", ev.IngressCount)}
				}
				if ev.IngressTLSCount == 0 {
					return 1, 0.7, "Auto (cluster): TLS terminasyonu görünmüyor (Ingress TLS yok).", []string{fmt.Sprintf("ingressTLSCount=%d", ev.IngressTLSCount)}
				}
				if hasAddon("cert-manager", "cert-manager.crd") {
					return 4, 0.6, "Auto (cluster): Ingress TLS + cert-manager (otomasyon varsayımı, doğrula).", []string{fmt.Sprintf("ingressTLSCount=%d", ev.IngressTLSCount)}
				}
				return 3, 0.6, "Auto (cluster): Ingress TLS mevcut (sertifika yönetimi doğrulanmadı).", []string{fmt.Sprintf("ingressTLSCount=%d", ev.IngressTLSCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Policy Audit") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("kyverno", "kyverno.crd") || hasAddon("gatekeeper-system", "gatekeeper.crd") {
					return 3, 0.7, "Auto (cluster): Kyverno/OPA Gatekeeper tespit edildi.", []string{}
				}
				return 1, 0.6, "Auto (cluster): Policy engine tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Enforcement") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("kyverno", "kyverno.crd") || hasAddon("gatekeeper-system", "gatekeeper.crd") {
					return 4, 0.65, "Auto (cluster): OPA/Kyverno tespit edildi (enforcement doğrulanmalı).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Enforcement agent tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "GitOps Tool") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("argocd", "argocd.crd") {
					return 3, 0.7, "Auto (cluster): Argo CD tespit edildi.", []string{}
				}
				if hasAddon("flux-system") {
					return 3, 0.65, "Auto (cluster): Flux tespit edildi (namespace).", []string{}
				}
				return 1, 0.6, "Auto (cluster): GitOps aracı tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Deployment") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("argocd", "flux-system") {
					return 3, 0.6, "Auto (cluster): GitOps aracı var (deployment otomasyonu varsayımı).", []string{}
				}
				return 1, 0.5, "Auto (cluster): Deployment süreci otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Git Structure") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("argocd", "flux-system") {
					return 3, 0.55, "Auto (cluster): GitOps aracı + repo yönetimi varsayımı.", []string{}
				}
				return 1, 0.5, "Auto (cluster): Git yapısı otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Rollback") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroScheduleCount > 0 || hasAddon("velero", "velero.crd") {
					return 3, 0.55, "Auto (cluster): Velero/backup aracı var (rollback varsayımı).", []string{}
				}
				return 1, 0.5, "Auto (cluster): Rollback mekanizması tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Audit Trail") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.EventCount > 0 {
					return 3, 0.55, fmt.Sprintf("Auto (cluster): %d event bulunuyor (audit trail varsayımı).", ev.EventCount), []string{fmt.Sprintf("eventCount=%d", ev.EventCount)}
				}
				return 1, 0.45, "Auto (cluster): Event verisi tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Helm Usage") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HelmReleaseCount > 0 {
					return 3, 0.6, fmt.Sprintf("Auto (cluster): %d Helm release tespit edildi.", ev.HelmReleaseCount), []string{fmt.Sprintf("helmReleaseCount=%d", ev.HelmReleaseCount)}
				}
				return 1, 0.5, "Auto (cluster): Helm usage bilgisi tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Values Mgmt") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.SealedSecretCount > 0 || ev.ExternalSecretCount > 0 {
					return 3, 0.55, "Auto (cluster): External/Sealed secrets tespit edildi (values management varsayımı).", []string{}
				}
				return 1, 0.5, "Auto (cluster): Values management bilgisi tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Chart Testing") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HelmReleaseCount >= 5 {
					return 3, 0.5, "Auto (cluster): Çok sayıda Helm release (chart testing varsayımı).", []string{}
				}
				if ev.HelmReleaseCount > 0 {
					return 2, 0.45, "Auto (cluster): Helm release var (chart testing olabilir).", []string{}
				}
				return 1, 0.4, "Auto (cluster): Chart testing bilgisi bulunamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Release Mgmt") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("argocd", "flux-system") {
					return 3, 0.55, "Auto (cluster): GitOps aracı var (release management varsayımı).", []string{}
				}
				return 1, 0.45, "Auto (cluster): Release management prosedürü tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool {
				return strings.EqualFold(name, "Backup Tool") || strings.EqualFold(name, "Backup Strategy") || strings.EqualFold(name, "Backup Stratejisi")
			},
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("velero", "velero.crd") {
					return 3, 0.7, "Auto (cluster): Velero tespit edildi (schedule/policy doğrulanmalı).", []string{}
				}
				if hasAddon("longhorn") || ev.LonghornBackupCount > 0 {
					return 3, 0.7, "Auto (cluster): Longhorn backup aracı tespit edildi.", []string{}
				}
				return 1, 0.6, "Auto (cluster): Backup aracı tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Backup Location") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroBSLCount > 0 {
					return 3, 0.6, fmt.Sprintf("Auto (cluster): %d Velero storage location tespit edildi.", ev.VeleroBSLCount), []string{fmt.Sprintf("veleroBslCount=%d", ev.VeleroBSLCount)}
				}
				if ev.HasLonghorn || ev.LonghornBackupCount > 0 {
					return 2, 0.55, "Auto (cluster): Longhorn backup aracı var (location detayları manuel doğrulanmalı).", []string{}
				}
				if hasAddon("velero", "velero.crd") {
					return 2, 0.55, "Auto (cluster): Velero var ancak storage location listesi alınamadı.", []string{}
				}
				return 1, 0.5, "Auto (cluster): Backup location tespiti yapılamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Backup Encryption") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroBSLEncrypted {
					return 3, 0.6, "Auto (cluster): Velero storage location üzerinde encryption konfigürasyonu mevcut.", []string{}
				}
				if ev.HasLonghorn || ev.LonghornBackupCount > 0 {
					return 2, 0.55, "Auto (cluster): Longhorn backup var (encryption manual/tekrar doğrulanmalı).", []string{}
				}
				if ev.VeleroBSLCount > 0 {
					return 2, 0.55, "Auto (cluster): Storage location var ama encryption bilgisi tespit edilemedi.", []string{}
				}
				return 1, 0.5, "Auto (cluster): Backup encryption bilgisi otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Backup Scope") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroBackupCount > 5 {
					return 3, 0.55, fmt.Sprintf("Auto (cluster): %d Velero backup objesi (farklı namespace/cihaz) tespit edildi.", ev.VeleroBackupCount), []string{fmt.Sprintf("veleroBackupCount=%d", ev.VeleroBackupCount)}
				}
				if ev.VeleroBackupCount > 0 {
					return 2, 0.5, "Auto (cluster): Velero backup objesi var (scope genişliği/klasör doğrulanmalı).", []string{fmt.Sprintf("veleroBackupCount=%d", ev.VeleroBackupCount)}
				}
				if ev.LonghornBackupCount > 5 {
					return 3, 0.55, fmt.Sprintf("Auto (cluster): %d Longhorn backup tespit edildi (scope varsayımı).", ev.LonghornBackupCount), []string{fmt.Sprintf("longhornBackupCount=%d", ev.LonghornBackupCount)}
				}
				if ev.LonghornBackupCount > 0 {
					return 2, 0.5, "Auto (cluster): Longhorn backup var (scope detayları doğrulanmalı).", []string{fmt.Sprintf("longhornBackupCount=%d", ev.LonghornBackupCount)}
				}
				return 1, 0.45, "Auto (cluster): Backup scope otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Restore Testing") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroRestoreCount > 0 {
					return 3, 0.6, fmt.Sprintf("Auto (cluster): %d Velero restore entrysi tespit edildi (testing varsayımı).", ev.VeleroRestoreCount), []string{fmt.Sprintf("veleroRestoreCount=%d", ev.VeleroRestoreCount)}
				}
				if ev.LonghornRestoreCount > 0 {
					return 3, 0.6, fmt.Sprintf("Auto (cluster): %d Longhorn restore entrysi tespit edildi (testing varsayımı).", ev.LonghornRestoreCount), []string{fmt.Sprintf("longhornRestoreCount=%d", ev.LonghornRestoreCount)}
				}
				return 1, 0.5, "Auto (cluster): Restore testing bilgisi bulunamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Restore Proc") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroRestoreCount > 1 || ev.LonghornRestoreCount > 1 {
					return 3, 0.55, "Auto (cluster): Birden fazla restore tespit edildi (proc dokümante olabilir).", []string{
						fmt.Sprintf("veleroRestoreCount=%d", ev.VeleroRestoreCount),
						fmt.Sprintf("longhornRestoreCount=%d", ev.LonghornRestoreCount),
					}
				}
				if ev.VeleroRestoreCount > 0 || ev.LonghornRestoreCount > 0 {
					return 2, 0.5, "Auto (cluster): Restore var (proc/automation doğrulanmalı).", []string{
						fmt.Sprintf("veleroRestoreCount=%d", ev.VeleroRestoreCount),
						fmt.Sprintf("longhornRestoreCount=%d", ev.LonghornRestoreCount),
					}
				}
				return 1, 0.45, "Auto (cluster): Restore prosedürü otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "RTO/RPO Tanımı") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroScheduleCount > 0 {
					level := 3
					conf := 0.6
					if ev.VeleroScheduleCount == 1 {
						level = 2
						conf = 0.55
					}
					return level, conf, fmt.Sprintf("Auto (cluster): Velero schedule tespit edildi (count=%d). RTO/RPO tanımı dokümante olabilir.", ev.VeleroScheduleCount), []string{fmt.Sprintf("veleroScheduleCount=%d", ev.VeleroScheduleCount)}
				}
				if hasAddon("velero", "velero.crd") {
					return 2, 0.5, "Auto (cluster): Velero var ama schedule listesi alınamadı (RTO/RPO belirsiz).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Backup schedule/RTO-RPO tanımı otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Prometheus Deploy") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasPrometheusOperator {
					if ev.PrometheusRuleCount > 20 {
						return 4, 0.55, "Auto (cluster): Prometheus Operator + çok sayıda PrometheusRule (HA varsayımı).", []string{
							fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount),
						}
					}
					return 3, 0.6, "Auto (cluster): Prometheus Operator tespit edildi.", []string{
						fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount),
					}
				}
				if hasAddon("prometheus-operator.crd") && (ev.PrometheusRuleCount > 0 || ev.ServiceMonitorCount+ev.PodMonitorCount > 0) {
					return 3, 0.55, "Auto (cluster): Prometheus Operator CRD + monitoring objeleri var (operator tespit varsayımı).", []string{
						fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount),
						fmt.Sprintf("serviceMonitorCount=%d", ev.ServiceMonitorCount),
						fmt.Sprintf("podMonitorCount=%d", ev.PodMonitorCount),
					}
				}
				if ev.HasMetricsServer && (ev.PrometheusRuleCount > 0 || ev.ServiceMonitorCount+ev.PodMonitorCount > 0) {
					return 2, 0.5, "Auto (cluster): metrics-server + bazı monitoring objeleri var (Prometheus deploy belirsiz).", []string{
						fmt.Sprintf("monitorCount=%d", ev.ServiceMonitorCount+ev.PodMonitorCount),
					}
				}
				if ev.PrometheusRuleCount > 0 {
					return 2, 0.55, "Auto (cluster): PrometheusRule objesi var (Operator/helm olmayabilir).", []string{
						fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount),
					}
				}
				return 1, 0.6, "Auto (cluster): Prometheus tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Grafana Dashboards") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasGrafana {
					return 3, 0.55, "Auto (cluster): Grafana deployment/namespace tespit edildi (dashboard sayısı doğrulanmalı).", []string{}
				}
				if hasAddon("grafana") || hasAddon("monitoring") {
					return 2, 0.5, "Auto (cluster): Grafana/monitoring namespace var (deployment doğrulanmalı).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Grafana tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool {
				return strings.EqualFold(name, "Log Collection") ||
					strings.EqualFold(name, "Centralized Storage") ||
					strings.EqualFold(name, "Log Query") ||
					strings.EqualFold(name, "Logs Analysis")
			},
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasLoki {
					return 3, 0.6, "Auto (cluster): Loki tespit edildi (full pipeline doğrulanmalı).", []string{}
				}
				if hasAddon("loki") {
					return 3, 0.6, "Auto (cluster): Loki tespit edildi (full pipeline doğrulanmalı).", []string{}
				}
				if hasAddon("elasticsearch") || hasAddon("kibana") || hasAddon("logging") {
					return 3, 0.55, "Auto (cluster): Logging stack tespit edildi (HA/retention doğrulanmalı).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Merkezi log toplama tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Data Retention") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				hasLogStack := ev.HasLoki || hasAddon("loki") || hasAddon("elasticsearch") || hasAddon("kibana") || hasAddon("logging")
				if hasLogStack {
					return 3, 0.6, "Auto (cluster): Merkezi log/veri retention aracı tespit edildi (retention politikası doğrulanmalı).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Data retention politikası otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Log Retention") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasLoki || hasAddon("loki") {
					return 3, 0.6, "Auto (cluster): Loki tespit edildi (log retention politikası dokümante olabilir).", []string{}
				}
				if hasAddon("elasticsearch") || hasAddon("logging") {
					return 3, 0.55, "Auto (cluster): Elasticsearch/Logging stack tespit edildi (retention ayarları doğrulanmalı).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Log retention bilgisi alınamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Audit Log") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("elasticsearch") || hasAddon("logging") || hasAddon("kibana") {
					return 3, 0.55, "Auto (cluster): Audit log pipeline için Elastic/Kibana/Logging stack tespit edildi (pipeline doğrulanmalı).", []string{}
				}
				if ev.HasLoki {
					return 2, 0.5, "Auto (cluster): Loki var (audit stream varsayımı, doğrula).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Audit log pipeline tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool {
				return strings.EqualFold(name, "Service Mesh") || strings.EqualFold(name, "mTLS") || strings.EqualFold(name, "Observability")
			},
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				mesh := hasAddon("istio-system", "istio.crd") || hasAddon("linkerd", "linkerd.crd")
				if !mesh {
					return 1, 0.6, "Auto (cluster): Service mesh tespit edilmedi.", []string{}
				}
				switch c.Name {
				case "Service Mesh":
					return 3, 0.55, "Auto (cluster): Mesh tespit edildi (prod/coverage doğrulanmalı).", []string{}
				case "mTLS":
					return 2, 0.5, "Auto (cluster): Mesh tespit edildi (mTLS kapsamı doğrulanmalı).", []string{}
				case "Observability":
					if hasAddon("kiali.crd") {
						return 3, 0.55, "Auto (cluster): Kiali tespit edildi (tracing doğrulanmalı).", []string{}
					}
					return 2, 0.5, "Auto (cluster): Mesh metrics varsayımı (observability araçları doğrulanmalı).", []string{}
				default:
					return 0, 0, "", nil
				}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "StorageClass") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("storageclasses.list") {
					return 0, 0, "StorageClass bilgisi alınamadı (izin/erişim).", []string{"storageclasses.list"}
				}
				if ev.StorageClassCount == 0 {
					return 1, 0.8, "Auto (cluster): StorageClass bulunamadı.", []string{fmt.Sprintf("storageClassCount=%d", ev.StorageClassCount)}
				}
				if ev.StorageClassCount == 1 {
					return 2, 0.7, "Auto (cluster): 1 StorageClass bulundu.", []string{fmt.Sprintf("storageClassCount=%d", ev.StorageClassCount)}
				}
				return 3, 0.7, "Auto (cluster): Birden fazla StorageClass bulundu.", []string{fmt.Sprintf("storageClassCount=%d", ev.StorageClassCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Dynamic Provisioning") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("storageclasses.list") {
					return 0, 0, "StorageClass bilgisi alınamadı (dinamik provisioning tespit edilemedi).", []string{"storageclasses.list"}
				}
				if ev.StorageClassCount == 0 {
					return 1, 0.7, "Auto (cluster): StorageClass yok.", []string{fmt.Sprintf("storageClassCount=%d", ev.StorageClassCount)}
				}
				if ev.DefaultStorageClassName != "" && ev.DefaultStorageClassProvisioner != "" && ev.CSIDriverCount > 0 {
					return 3, 0.65, "Auto (cluster): Default StorageClass + CSI driver mevcut (dynamic provisioning varsayımı).", []string{
						fmt.Sprintf("defaultStorageClass=%s", ev.DefaultStorageClassName),
						fmt.Sprintf("defaultStorageClassProvisioner=%s", ev.DefaultStorageClassProvisioner),
						fmt.Sprintf("csiDriverCount=%d", ev.CSIDriverCount),
					}
				}
				if ev.CSIDriverCount > 0 {
					return 2, 0.6, "Auto (cluster): CSI driver var ama default StorageClass tespit edilmedi.", []string{
						fmt.Sprintf("storageClassCount=%d", ev.StorageClassCount),
						fmt.Sprintf("csiDriverCount=%d", ev.CSIDriverCount),
					}
				}
				return 2, 0.55, "Auto (cluster): StorageClass var (dynamic provisioning belirsiz).", []string{
					fmt.Sprintf("storageClassCount=%d", ev.StorageClassCount),
				}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "ResourceQuota") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("resourcequotas.list") {
					return 0, 0, "ResourceQuota bilgisi alınamadı (izin/erişim).", []string{"resourcequotas.list"}
				}
				if ev.ResourceQuotaCount == 0 {
					return 1, 0.75, "Auto (cluster): ResourceQuota yok.", []string{fmt.Sprintf("resourceQuotaCount=%d", ev.ResourceQuotaCount)}
				}
				return 3, 0.6, "Auto (cluster): ResourceQuota mevcut (kapsam/katılık doğrulanmadı).", []string{fmt.Sprintf("resourceQuotaCount=%d", ev.ResourceQuotaCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "LimitRange") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("limitranges.list") {
					return 0, 0, "LimitRange bilgisi alınamadı (izin/erişim).", []string{"limitranges.list"}
				}
				if ev.LimitRangeCount == 0 {
					return 1, 0.75, "Auto (cluster): LimitRange yok.", []string{fmt.Sprintf("limitRangeCount=%d", ev.LimitRangeCount)}
				}
				return 3, 0.6, "Auto (cluster): LimitRange mevcut (kapsam/katılık doğrulanmadı).", []string{fmt.Sprintf("limitRangeCount=%d", ev.LimitRangeCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "HPA") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasPermErr("hpas.list") {
					return 0, 0, "HPA bilgisi alınamadı (izin/erişim).", []string{"hpas.list"}
				}
				if ev.HpaCount == 0 {
					return 1, 0.75, "Auto (cluster): HPA yok.", []string{fmt.Sprintf("hpaCount=%d", ev.HpaCount)}
				}
				return 2, 0.7, "Auto (cluster): HPA mevcut (metric kapsamı doğrulanmadı).", []string{fmt.Sprintf("hpaCount=%d", ev.HpaCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Service Account Policy") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.DefaultServiceAccountCount == 0 {
					return 0, 0, "ServiceAccount listesi yok/izin yok olabilir.", []string{}
				}
				if ev.DefaultServiceAccountAutomountDisabledCount == 0 {
					return 1, 0.65, "Auto (cluster): default ServiceAccount automount kapalı görünmüyor.", []string{
						fmt.Sprintf("defaultServiceAccountCount=%d", ev.DefaultServiceAccountCount),
						fmt.Sprintf("defaultServiceAccountAutomountDisabledCount=%d", ev.DefaultServiceAccountAutomountDisabledCount),
					}
				}
				level := 2
				conf := 0.6
				if float64(ev.DefaultServiceAccountAutomountDisabledCount)/float64(ev.DefaultServiceAccountCount) >= 0.8 {
					level = 3
					conf = 0.55
				}
				return level, conf, "Auto (cluster): bazı namespace’lerde default SA automount kapalı (tam policy doğrulanmalı).", []string{
					fmt.Sprintf("defaultServiceAccountAutomountDisabledCount=%d", ev.DefaultServiceAccountAutomountDisabledCount),
					fmt.Sprintf("defaultServiceAccountCount=%d", ev.DefaultServiceAccountCount),
				}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "User Access Model") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.ClusterAdminBindingCount == 0 {
					return 0, 0, "ClusterRoleBinding bilgisi yok/izin yok olabilir.", []string{}
				}
				if ev.ClusterAdminBindingCount > 5 {
					return 2, 0.5, "Auto (cluster): cluster-admin bağları fazla görünüyor (kimlere verildiği doğrulanmalı).", []string{fmt.Sprintf("clusterAdminBindingCount=%d", ev.ClusterAdminBindingCount)}
				}
				return 3, 0.5, "Auto (cluster): cluster-admin bağları sınırlı görünüyor (RBAC audit doğrulanmalı).", []string{fmt.Sprintf("clusterAdminBindingCount=%d", ev.ClusterAdminBindingCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Pod Security") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.NamespacePSAEnforceCount == 0 {
					if ev.APIServerPSSConfigEnabled {
						return 3, 0.55, "Auto (cluster): kube-apiserver admission-control-config-file tespit edildi (PSS/PSA varsayımı; namespace label’ları görünmüyor).", []string{
							"apiServerPssConfigEnabled=true",
						}
					}
					return 1, 0.65, "Auto (cluster): Pod Security Admission enforce etiketi tespit edilmedi.", []string{}
				}
				level := 2
				conf := 0.6
				if ev.NamespacePSARestrictedCount > 0 {
					level = 3
					conf = 0.6
				}
				if ev.NamespaceCount > 0 && float64(ev.NamespacePSAEnforceCount)/float64(ev.NamespaceCount) >= 0.8 {
					level = 4
					conf = 0.55
				}
				return level, conf, "Auto (cluster): Namespace’lerde PSA enforce label tespit edildi (kapsam/policy doğrulanmalı).", []string{
					fmt.Sprintf("namespacePsaEnforceCount=%d", ev.NamespacePSAEnforceCount),
					fmt.Sprintf("namespacePsaRestrictedCount=%d", ev.NamespacePSARestrictedCount),
					fmt.Sprintf("namespaceCount=%d", ev.NamespaceCount),
				}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Alert Rules") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.PrometheusRuleCount == 0 {
					return 1, 0.6, "Auto (cluster): PrometheusRule bulunamadı (izin/CRD eksik olabilir).", []string{fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount)}
				}
				if ev.PrometheusRuleCount >= 30 {
					return 4, 0.55, "Auto (cluster): Çok sayıda PrometheusRule var (susturma/on-call doğrulanmalı).", []string{fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount)}
				}
				if ev.PrometheusRuleCount >= 10 {
					return 3, 0.6, "Auto (cluster): PrometheusRule mevcut (kapsam doğrulanmalı).", []string{fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount)}
				}
				return 2, 0.6, "Auto (cluster): Az sayıda PrometheusRule var.", []string{fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount)}
			},
		},
		{
			match: func(name string) bool {
				return strings.EqualFold(name, "Metrics Collection") || strings.EqualFold(name, "Scrape Config")
			},
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				total := ev.ServiceMonitorCount + ev.PodMonitorCount
				if total == 0 {
					return 1, 0.55, "Auto (cluster): ServiceMonitor/PodMonitor bulunamadı (izin/CRD eksik olabilir).", []string{
						fmt.Sprintf("serviceMonitorCount=%d", ev.ServiceMonitorCount),
						fmt.Sprintf("podMonitorCount=%d", ev.PodMonitorCount),
					}
				}
				if total >= 25 {
					return 4, 0.5, "Auto (cluster): Çok sayıda monitor objesi var (dinamik discovery varsayımı).", []string{fmt.Sprintf("monitorCount=%d", total)}
				}
				return 3, 0.55, "Auto (cluster): Monitor objeleri mevcut.", []string{fmt.Sprintf("monitorCount=%d", total)}
			},
		},
		{
			match: func(name string) bool {
				return strings.EqualFold(name, "Backup Schedule") || strings.EqualFold(name, "Backup Frequency")
			},
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.VeleroScheduleCount == 0 {
					if hasAddon("velero", "velero.crd") {
						return 2, 0.5, "Auto (cluster): Velero var ama Schedule tespit edilmedi (izin/namespace kontrol).", []string{fmt.Sprintf("veleroScheduleCount=%d", ev.VeleroScheduleCount)}
					}
					return 1, 0.55, "Auto (cluster): Backup schedule tespit edilmedi.", []string{fmt.Sprintf("veleroScheduleCount=%d", ev.VeleroScheduleCount)}
				}
				if ev.VeleroScheduleCount >= 2 {
					return 4, 0.55, "Auto (cluster): Birden fazla backup schedule var (sıklık doğrulanmalı).", []string{fmt.Sprintf("veleroScheduleCount=%d", ev.VeleroScheduleCount)}
				}
				return 3, 0.6, "Auto (cluster): Backup schedule tespit edildi.", []string{fmt.Sprintf("veleroScheduleCount=%d", ev.VeleroScheduleCount)}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Utilization Analysis") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				hasUtilization := ev.HasPrometheusOperator || ev.HasKubeStateMetrics
				if hasUtilization {
					if ev.HasPrometheusOperator && ev.HasKubeStateMetrics {
						return 4, 0.55, "Auto (cluster): Prometheus + kube-state-metrics verisi mevcut.", []string{}
					}
					return 3, 0.6, "Auto (cluster): Prometheus veya kube-state-metrics tespit edildi (utilization analiz varsayımı).", []string{}
				}
				return 1, 0.55, "Auto (cluster): Utilization analiz aracı tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Over-provisioning") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				hasQuota := ev.ResourceQuotaCount > 0
				hasLimit := ev.LimitRangeCount > 0
				switch {
				case hasQuota && hasLimit:
					return 3, 0.6, "Auto (cluster): ResourceQuota + LimitRange mevcut (over-provisioning kontrolü varsayımı).", []string{}
				case hasQuota || hasLimit:
					return 2, 0.55, "Auto (cluster): Resource quota/limit politikası tespit edildi (kapsam/katılık doğrulanmalı).", []string{}
				default:
					return 1, 0.5, "Auto (cluster): Over-provisioning kontrolü tespit edilemedi.", []string{}
				}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Auto Rightsizing") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasClusterAutoscaler && ev.HpaCount > 0 {
					return 4, 0.55, "Auto (cluster): Cluster autoscaler + HPA mevcut.", []string{fmt.Sprintf("hpaCount=%d", ev.HpaCount)}
				}
				if ev.HasClusterAutoscaler || ev.HpaCount > 0 {
					return 3, 0.6, "Auto (cluster): Auto-rightsizing sinyalleri (HPA/cluster-autoscaler) var.", []string{fmt.Sprintf("hpaCount=%d", ev.HpaCount)}
				}
				return 1, 0.55, "Auto (cluster): Auto-rightsizing araçları tespit edilmedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Cost Reporting") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("kubecost", "kubecost.crd") || hasAddon("opencost") {
					return 4, 0.6, "Auto (cluster): Kubecost/OpenCost tespit edildi.", []string{}
				}
				if ev.HasGrafana || hasAddon("grafana") {
					return 3, 0.55, "Auto (cluster): Grafana/monitoring stack tespit edildi (cost reporting varsayımı).", []string{}
				}
				return 1, 0.5, "Auto (cluster): Cost reporting aracı tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Instance Strategy") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasClusterAutoscaler {
					return 4, 0.6, "Auto (cluster): Cluster autoscaler tespit edildi (instance strategy otomasyonu varsayımı).", []string{}
				}
				if ev.NodePoolCount > 1 {
					return 3, 0.55, fmt.Sprintf("Auto (cluster): %d node pool tespit edildi (instance strategy düşünülmüş olabilir).", ev.NodePoolCount), []string{}
				}
				return 1, 0.5, "Auto (cluster): Instance strategy bilgisi otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Spot Usage") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.SpotNodeCount > 0 {
					return 3, 0.55, fmt.Sprintf("Auto (cluster): %d spot/preemptible node tespit edildi.", ev.SpotNodeCount), []string{}
				}
				return 1, 0.5, "Auto (cluster): Spot/preemptible node etiketi bulunamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Node Pool Strategy") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.NodePoolCount > 2 {
					return 3, 0.6, fmt.Sprintf("Auto (cluster): %d farklı node pool tespit edildi.", ev.NodePoolCount), []string{}
				}
				if ev.NodePoolCount > 1 {
					return 2, 0.55, fmt.Sprintf("Auto (cluster): %d node pool var (strategy varsayımı).", ev.NodePoolCount), []string{}
				}
				return 1, 0.5, "Auto (cluster): Node pool stratejisi tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Cost Savings") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasClusterAutoscaler || ev.HpaCount > 0 {
					return 3, 0.55, "Auto (cluster): Cluster autoscaler/HPA var (cost savings varsayımı).", []string{}
				}
				return 1, 0.5, "Auto (cluster): Cost savings aracı tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Cost Allocation") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.ResourceQuotaCount > 0 {
					return 3, 0.6, fmt.Sprintf("Auto (cluster): ResourceQuota sayısı=%d (cost allocation varsayımı).", ev.ResourceQuotaCount), []string{}
				}
				return 1, 0.5, "Auto (cluster): Cost allocation politikası tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Budget Control") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasPrometheusOperator || ev.HasGrafana {
					return 2, 0.5, "Auto (cluster): Monitoring stack mevcut (budget control süreçleri olabilir).", []string{}
				}
				return 1, 0.45, "Auto (cluster): Budget control sinyali bulunamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "FinOps Culture") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasAddon("argocd", "argocd.crd") || hasAddon("flux-system") || hasAddon("velero", "velero.crd") {
					return 2, 0.5, "Auto (cluster): GitOps/backup araçları var (FinOps culture varsayımı).", []string{}
				}
				return 1, 0.45, "Auto (cluster): FinOps culture otomatik tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Savings Tracking") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasPrometheusOperator && (ev.HasGrafana || hasAddon("grafana")) {
					return 3, 0.55, "Auto (cluster): Prometheus + Grafana var (savings tracking varsayımı).", []string{}
				}
				if ev.HasPrometheusOperator {
					return 2, 0.5, "Auto (cluster): Prometheus var (tracking/budget varsayımı).", []string{}
				}
				return 1, 0.45, "Auto (cluster): Savings tracking bilgisi tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "kubectl Commands") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if len(ev.Kubectl) == 0 {
					return 1, 0.5, "Auto (cluster): Kubectl komutu çalıştırılamadı.", []string{}
				}
				if hasKubectlError() {
					return 1, 0.4, "Auto (cluster): Bazı kubectl komutları hatayla sonuçlandı.", []string{}
				}
				return 3, 0.6, "Auto (cluster): Kubectl komutları başarıyla çalıştı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Pod Debugging") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if hasKubectlCmd("get pods") {
					return 3, 0.6, "Auto (cluster): kubectl get pods çalıştı (pod debugging varsayımı).", []string{}
				}
				return 1, 0.5, "Auto (cluster): Pod debugging komutu engellendi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Event Analysis") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.EventCount > 0 {
					return 3, 0.6, "Auto (cluster): Event count verisi mevcut.", []string{fmt.Sprintf("eventCount=%d", ev.EventCount)}
				}
				return 1, 0.5, "Auto (cluster): Event analiz verisi bulunamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Alert System") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.PrometheusRuleCount > 0 {
					return 3, 0.6, "Auto (cluster): PrometheusRule var (alert system varsayımı).", []string{fmt.Sprintf("prometheusRuleCount=%d", ev.PrometheusRuleCount)}
				}
				return 1, 0.5, "Auto (cluster): Alert sistemi tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "Alert Fatigue") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.PrometheusRuleCount >= 30 {
					return 3, 0.55, "Auto (cluster): Çok sayıda alert (tuning/alert fatigue varsayımı).", []string{}
				}
				if ev.PrometheusRuleCount > 0 {
					return 2, 0.5, "Auto (cluster): Alert sayısı sınırlı (tuning gerektiği varsayımı).", []string{}
				}
				return 1, 0.45, "Auto (cluster): Alert fatigue bilgisi tespit edilemedi.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "On-Call Runbook") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasGrafana || hasAddon("grafana") || ev.HasPrometheusOperator {
					return 2, 0.5, "Auto (cluster): Monitoring stack var (on-call runbook varsayımı).", []string{}
				}
				return 1, 0.45, "Auto (cluster): On-call runbook sinyali bulunamadı.", []string{}
			},
		},
		{
			match: func(name string) bool { return strings.EqualFold(name, "MTTR") },
			eval: func(c MaturityCriterion, ev MaturityEvidence) (int, float64, string, []string) {
				if ev.HasLoki || hasAddon("loki") {
					return 3, 0.6, "Auto (cluster): Loki var (MTTR düşüklüğü varsayımı).", []string{}
				}
				return 1, 0.5, "Auto (cluster): MTTR ile ilgili veri bulunamadı.", []string{}
			},
		},
	}

	var out []MaturityCriterionScore
	for _, cat := range doc.Categories {
		for _, c := range cat.Criteria {
			for _, h := range handlers {
				if !h.match(c.Name) {
					continue
				}
				level, conf, rationale, evidence := h.eval(c, ev)
				if level <= 0 {
					continue
				}
				out = append(out, MaturityCriterionScore{
					Key:        c.Key,
					Category:   c.Category,
					Criterion:  c.Name,
					Level:      level,
					Confidence: conf,
					Rationale:  rationale,
					Evidence:   evidence,
				})
				break
			}
		}
	}
	return out
}

func collectKubectlEvidence(ctx context.Context, conn *ClusterConnection, ev *MaturityEvidence) {
	if ev == nil || conn == nil {
		return
	}
	if len(conn.Kubeconfig) == 0 {
		return
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		return
	}
	if ev.Kubectl == nil {
		ev.Kubectl = map[string]string{}
	}

	tmp, err := os.CreateTemp("", "kube-app-kubeconfig-*.yaml")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(conn.Kubeconfig); err != nil {
		_ = tmp.Close()
		return
	}
	_ = tmp.Close()

	kubectlInsecure := conn.Insecure
	if !kubectlInsecure {
		if cfg, err := clientcmd.Load(conn.Kubeconfig); err == nil && cfg != nil {
			ctxName := conn.Context
			if ctxName == "" {
				ctxName = cfg.CurrentContext
			}
			if ctxObj, ok := cfg.Contexts[ctxName]; ok && ctxObj != nil {
				if cl, ok := cfg.Clusters[ctxObj.Cluster]; ok && cl != nil {
					if cl.InsecureSkipTLSVerify {
						kubectlInsecure = true
					}
				}
			}
		}
	}

	labelPrefix := "kubectl"
	if conn.Context != "" {
		labelPrefix += " --context " + conn.Context
	}

	var mu sync.Mutex
	store := func(key, val string) {
		mu.Lock()
		ev.Kubectl[key] = val
		mu.Unlock()
	}
	storeNote := func(val string) {
		store("kubectl NOTE", val)
	}

	buildKubectlArgs := func(insecure bool, args ...string) []string {
		cmdArgs := []string{"--kubeconfig", tmp.Name()}
		cmdArgs = append(cmdArgs, args...)
		if insecure {
			cmdArgs = append(cmdArgs, "--insecure-skip-tls-verify=true")
		}
		if conn.Context != "" {
			cmdArgs = append([]string{"--context", conn.Context}, cmdArgs...)
		}
		return cmdArgs
	}

	execKubectl := func(insecure bool, args ...string) (raw string, key string, text string, err error) {
		cmdArgs := buildKubectlArgs(insecure, args...)
		cmd := exec.CommandContext(ctx, "kubectl", cmdArgs...)
		out, err := cmd.CombinedOutput()
		raw = string(out)
		text = truncateForKubectl(raw, 1200)
		key = strings.TrimSpace(labelPrefix + " " + strings.Join(args, " "))
		if err != nil {
			// Treat missing CRDs as expected (not an "error" for evidence collection).
			if isKubectlMissingResourceType(raw) {
				return "", key, strings.TrimSpace(text + "\nNOTE: resource type not found (CRD not installed)."), nil
			}
			return raw, key, text, err
		}
		if insecure && !kubectlInsecure {
			text = strings.TrimSpace(text + "\nNOTE: executed with --insecure-skip-tls-verify=true.")
		}
		return raw, key, text, nil
	}

	runWithRetry := func(args ...string) (raw string, key string, text string, err error, retried bool) {
		raw, key, text, err = execKubectl(kubectlInsecure, args...)
		if err == nil || kubectlInsecure {
			return raw, key, text, err, false
		}
		if strings.Contains(raw, "x509: certificate signed by unknown authority") {
			if retryRaw, _, _, retryErr := execKubectl(true, args...); retryErr == nil {
				// Override the original entry with the successful output to avoid noisy error lists.
				return retryRaw, key, strings.TrimSpace(truncateForKubectl(retryRaw, 1200) + "\nNOTE: retried with --insecure-skip-tls-verify=true due to x509 unknown authority."), nil, true
			}
		}
		return raw, key, text, err, false
	}

	run := func(args ...string) {
		out, key, text, err, retried := runWithRetry(args...)
		if err != nil {
			store(key, strings.TrimSpace(truncateForKubectl(out, 1200)+"\nERROR: "+err.Error()))
			return
		}
		if retried {
			storeNote("Some kubectl calls were retried with --insecure-skip-tls-verify=true due to x509 unknown authority.")
		}
		store(key, text)
	}

	setInt := func(dst *int, v int) {
		if dst == nil {
			return
		}
		mu.Lock()
		*dst = v
		mu.Unlock()
	}
	maxInt := func(dst *int, v int) {
		if dst == nil {
			return
		}
		mu.Lock()
		if v > *dst {
			*dst = v
		}
		mu.Unlock()
	}

	runCount := func(apply func(int), args ...string) {
		out, key, text, err, retried := runWithRetry(args...)
		if err != nil {
			store(key, strings.TrimSpace(truncateForKubectl(out, 1200)+"\nERROR: "+err.Error()))
			return
		}
		if retried {
			storeNote("Some kubectl calls were retried with --insecure-skip-tls-verify=true due to x509 unknown authority.")
		}
		store(key, text)
		lines := strings.TrimSpace(out)
		if lines == "" {
			apply(0)
			return
		}
		apply(len(strings.Split(lines, "\n")))
	}

	runTasks := func(concurrency int, tasks ...func()) {
		if concurrency <= 0 {
			concurrency = 1
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, t := range tasks {
			t := t
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				t()
			}()
		}
		wg.Wait()
	}

	var tasks []func()

	// Keep it small (summary only). Some kubectl versions don't support --short.
	tasks = append(tasks,
		func() { run("version", "-o", "yaml") },
		func() { run("get", "nodes", "-o", "wide") },
		func() { run("get", "ns", "--no-headers") },
		// Avoid huge `pods -A` on large clusters; addon detection is done via client-go + CRD checks.
		func() { run("get", "pods", "-n", "kube-system", "--no-headers") },
	)

	// CRD-based counts (best-effort; may be 0 if CRD or permission missing).
	tasks = append(tasks,
		func() {
			runCount(func(n int) { setInt(&ev.PrometheusRuleCount, n) }, "get", "prometheusrules.monitoring.coreos.com", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.ServiceMonitorCount, n) }, "get", "servicemonitors.monitoring.coreos.com", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.PodMonitorCount, n) }, "get", "podmonitors.monitoring.coreos.com", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.VeleroScheduleCount, n) }, "get", "schedules.velero.io", "-n", "velero", "-o", "name")
		},
		// Flux HelmRelease CRD group changed across versions; take max across both.
		func() {
			runCount(func(n int) { maxInt(&ev.HelmReleaseCount, n) }, "get", "helmreleases.helm.toolkit.fluxcd.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { maxInt(&ev.HelmReleaseCount, n) }, "get", "helmreleases.fluxcd.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.UpgradePlanCount, n) }, "get", "plans.upgrade.cattle.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.LonghornBackupCount, n) }, "get", "backups.longhorn.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.LonghornRestoreCount, n) }, "get", "restores.longhorn.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.CertManagerCertificateCount, n) }, "get", "certificates.cert-manager.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.CertManagerIssuerCount, n) }, "get", "issuers.cert-manager.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.CertManagerClusterIssuerCount, n) }, "get", "clusterissuers.cert-manager.io", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.ExternalSecretCount, n) }, "get", "externalsecrets.external-secrets.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.SealedSecretCount, n) }, "get", "sealedsecrets.bitnami.com", "-A", "-o", "name")
		},
	)
	// Trivy operator reports
	tasks = append(tasks,
		func() {
			runCount(func(n int) { maxInt(&ev.TrivyReportCount, n) }, "get", "vulnerabilityreports.aquasecurity.github.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { maxInt(&ev.TrivyReportCount, n) }, "get", "configauditreports.aquasecurity.github.io", "-A", "-o", "name")
		},
	)
	// Cilium resources sometimes work better without group suffix depending on kubectl discovery/cache.
	tasks = append(tasks,
		func() {
			runCount(func(n int) { maxInt(&ev.CiliumNetworkPolicyCount, n) }, "get", "ciliumnetworkpolicies", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { maxInt(&ev.CiliumNetworkPolicyCount, n) }, "get", "ciliumnetworkpolicies.cilium.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { maxInt(&ev.CiliumClusterwideNetworkPolicyCount, n) }, "get", "ciliumclusterwidenetworkpolicies", "-o", "name")
		},
		func() {
			runCount(func(n int) { maxInt(&ev.CiliumClusterwideNetworkPolicyCount, n) }, "get", "ciliumclusterwidenetworkpolicies.cilium.io", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.VeleroBackupCount, n) }, "get", "backups.velero.io", "-A", "-o", "name")
		},
		func() {
			runCount(func(n int) { setInt(&ev.VeleroRestoreCount, n) }, "get", "restores.velero.io", "-A", "-o", "name")
		},
	)

	tasks = append(tasks, func() {
		bslRaw, key, text, err, retried := runWithRetry("get", "backupstoragelocations.velero.io", "-n", "velero", "-o", "json")
		if err != nil {
			store(key, strings.TrimSpace(truncateForKubectl(bslRaw, 1200)+"\nERROR: "+err.Error()))
			return
		}
		if retried {
			storeNote("Some kubectl calls were retried with --insecure-skip-tls-verify=true due to x509 unknown authority.")
		}
		store(key, text)

		var bsl struct {
			Items []struct {
				Spec struct {
					Config map[string]string `json:"config"`
				} `json:"spec"`
			} `json:"items"`
		}
		if err := json.Unmarshal([]byte(bslRaw), &bsl); err != nil {
			return
		}
		encrypted := false
		for _, item := range bsl.Items {
			for _, k := range []string{"kmsKeyId", "kmsCustomerMasterKeyId", "encryption", "kmsProject"} {
				if val, ok := item.Spec.Config[k]; ok && strings.TrimSpace(val) != "" {
					encrypted = true
					break
				}
			}
			if encrypted {
				break
			}
		}
		mu.Lock()
		ev.VeleroBSLCount = len(bsl.Items)
		ev.VeleroBSLEncrypted = encrypted
		mu.Unlock()
	})

	tasks = append(tasks, func() { runCount(func(n int) { setInt(&ev.EventCount, n) }, "get", "events", "-A", "--no-headers") })

	// Keep kubectl load bounded; these calls can be slow on large clusters.
	runTasks(4, tasks...)
}

func isKubectlMissingResourceType(out string) bool {
	lower := strings.ToLower(out)
	if strings.Contains(lower, "the server doesn't have a resource type") {
		return true
	}
	if strings.Contains(lower, "the server doesn\\u2019t have a resource type") {
		return true
	}
	if strings.Contains(lower, "no matches for kind") {
		return true
	}
	return false
}

func truncateForKubectl(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "..."
}

func handleMaturityCriteria(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	doc, err := LoadMaturityCriteriaDoc("test.md")
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to load criteria: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func handleMaturityEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		cluster = "default"
	}
	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	doc, err := LoadMaturityCriteriaDoc("test.md")
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to load criteria: "+err.Error())
		return
	}
	ev, err := CollectMaturityEvidenceCached(r.Context(), cluster, conn)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ev.InferredScores = InferScoresFromEvidence(doc, ev)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ev)
}

func handleMaturityAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		cluster = "default"
	}
	wantPDF := r.URL.Query().Get("pdf") == "true"

	var req MaturityAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	doc, err := LoadMaturityCriteriaDoc("test.md")
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to load criteria: "+err.Error())
		return
	}

	conn := getClusterConn(r)
	var ev MaturityEvidence
	if conn == nil {
		ev = MaturityEvidence{
			CollectedAt:    time.Now(),
			Cluster:        cluster,
			DetectedAddons: map[string]bool{},
			Permissions:    map[string]string{"cluster": "no cluster configured (upload kubeconfig or provide notes)"},
			Kubectl:        map[string]string{},
		}
	} else {
		evStart := time.Now()
		ev, err = CollectMaturityEvidenceCached(r.Context(), cluster, conn)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to collect evidence: "+err.Error())
			return
		}
		log.Printf("maturity evidence collected cluster=%s in=%s", cluster, time.Since(evStart))
	}
	ev.InferredScores = InferScoresFromEvidence(doc, ev)

	llmBudget := time.Duration(envInt("LLM_BUDGET_ANALYZE_SECONDS", 120)) * time.Second
	llmCtx, cancel := context.WithTimeout(r.Context(), llmBudget)
	defer cancel()
	llmStart := time.Now()
	report, llmMeta, err := EvaluateMaturity(llmCtx, doc, ev, req)
	prov, model := "", ""
	if llmMeta != nil {
		prov, model = llmMeta.Provider, llmMeta.Model
	}
	log.Printf("maturity analyze done cluster=%s in=%s llmProvider=%s llmModel=%s", cluster, time.Since(llmStart), prov, model)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	report.LLM = llmMeta

	// Return PDF if requested
	if wantPDF {
		pdfBytes, err := GenerateMaturityPDF(doc, report, req, ev)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to generate PDF: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename=maturity-report.pdf")
		w.Write(pdfBytes)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func handleMaturityQuestions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		cluster = "default"
	}

	var req MaturityQuestionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}
	if req.MaxQuestions <= 0 {
		req.MaxQuestions = 20
	}
	if req.MaxQuestions > 50 {
		req.MaxQuestions = 50
	}
	if req.MinConfidence <= 0 {
		req.MinConfidence = 0.6
	}

	doc, err := LoadMaturityCriteriaDoc("test.md")
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to load criteria: "+err.Error())
		return
	}

	conn := getClusterConn(r)
	var ev MaturityEvidence
	if conn == nil {
		ev = MaturityEvidence{
			CollectedAt:    time.Now(),
			Cluster:        cluster,
			DetectedAddons: map[string]bool{},
			Permissions:    map[string]string{"cluster": "no cluster configured (upload kubeconfig or provide notes)"},
			Kubectl:        map[string]string{},
		}
	} else {
		evStart := time.Now()
		ev, err = CollectMaturityEvidenceCached(r.Context(), cluster, conn)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to collect evidence: "+err.Error())
			return
		}
		log.Printf("maturity evidence collected cluster=%s in=%s", cluster, time.Since(evStart))
	}
	ev.InferredScores = InferScoresFromEvidence(doc, ev)

	// OpenRouter free/slow models can regularly exceed 90s; keep this generous by default.
	llmBudget := time.Duration(envInt("LLM_BUDGET_QUESTIONS_SECONDS", 300)) * time.Second
	llmCtx, cancel := context.WithTimeout(r.Context(), llmBudget)
	defer cancel()
	llmStart := time.Now()
	qs, meta, note := GeneratePrecheckQuestions(llmCtx, doc, ev, req)
	prov, model := "", ""
	if meta != nil {
		prov, model = meta.Provider, meta.Model
	}
	log.Printf("maturity questions done cluster=%s in=%s llmProvider=%s llmModel=%s", cluster, time.Since(llmStart), prov, model)
	resp := MaturityQuestionsResponse{
		GeneratedAt: time.Now(),
		Cluster:     cluster,
		Questions:   qs,
		LLM:         meta,
		Note:        note,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleMaturityReportPDF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		cluster = "default"
	}

	var req MaturityAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	doc, err := LoadMaturityCriteriaDoc("test.md")
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to load criteria: "+err.Error())
		return
	}

	conn := getClusterConn(r)
	var ev MaturityEvidence
	if conn == nil {
		ev = MaturityEvidence{
			CollectedAt:    time.Now(),
			Cluster:        cluster,
			DetectedAddons: map[string]bool{},
			Permissions:    map[string]string{"cluster": "no cluster configured (upload kubeconfig or provide notes)"},
			Kubectl:        map[string]string{},
		}
	} else {
		ev, err = CollectMaturityEvidenceCached(r.Context(), cluster, conn)
		if err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to collect evidence: "+err.Error())
			return
		}
	}
	ev.InferredScores = InferScoresFromEvidence(doc, ev)

	report, llmMeta, err := EvaluateMaturity(r.Context(), doc, ev, req)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	report.LLM = llmMeta

	pdfBytes, err := GenerateMaturityPDF(doc, report, req, ev)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to generate PDF: "+err.Error())
		return
	}

	filename := fmt.Sprintf("maturity-report-%s-%s.pdf", cluster, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfBytes)
}
