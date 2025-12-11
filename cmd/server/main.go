package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// ResourceInfo represents a generic summary of a Kubernetes resource
type ResourceInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Status    string `json:"status"`
	Age       string `json:"age"`
	Type      string `json:"type"` // e.g., "Deployment", "Service"
	Details   string `json:"details"`
}

type EventInfo struct {
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Object    string `json:"object"`
	Age       string `json:"age"`
	Timestamp int64  `json:"timestamp"`
}

type NamespaceResponse struct {
	Namespaces       []string `json:"namespaces"`
	DefaultNamespace string   `json:"defaultNamespace"`
	AllowAll         bool     `json:"allowAll"`
}

type AnalysisRow struct {
	Title         string `json:"title"`
	ProdLevel     string `json:"prodLevel"`
	StagingLevel  string `json:"stagingLevel"`
	DevLevel      string `json:"devLevel"`
	ProdTarget    string `json:"prodTarget"`
	StagingTarget string `json:"stagingTarget"`
	DevTarget     string `json:"devTarget"`
}

// Cluster analysis signals (best-effort heuristics gathered from the live cluster)
type ClusterAnalysisResponse struct {
	Cluster       string               `json:"cluster"`
	Generated     string               `json:"generatedAt"`
	Nodes         NodeSignals          `json:"nodes"`
	Network       NetworkSignals       `json:"network"`
	Security      SecuritySignals      `json:"security"`
	Observability ObservabilitySignals `json:"observability"`
	GitOps        GitOpsSignals        `json:"gitops"`
	Backup        BackupSignals        `json:"backup"`
	Workload      WorkloadSignals      `json:"workload"`
	Warnings      []string             `json:"warnings"`
}

type NodeSignals struct {
	Total         int      `json:"total"`
	ControlPlanes int      `json:"controlPlanes"`
	Zones         []string `json:"zones"`
	HasHA         bool     `json:"ha"`
	CNI           string   `json:"cni"`
}

type NetworkSignals struct {
	NetworkPolicies int      `json:"networkPolicies"`
	DefaultDenyNS   []string `json:"defaultDenyNamespaces"`
	Ingresses       []string `json:"ingressControllers"`
}

type SecuritySignals struct {
	CertManager bool     `json:"certManager"`
	PSAEnforce  []string `json:"psaEnforceNamespaces"`
}

type ObservabilitySignals struct {
	Prometheus       bool `json:"prometheus"`
	Alertmanager     bool `json:"alertmanager"`
	Grafana          bool `json:"grafana"`
	KubeStateMetrics bool `json:"kubeStateMetrics"`
	EFK              bool `json:"efk"`
}

type GitOpsSignals struct {
	ArgoCD bool `json:"argocd"`
}

type BackupSignals struct {
	Velero bool `json:"velero"`
}

type WorkloadSignals struct {
	HPAs           int      `json:"hpaCount"`
	Autoscalers    []string `json:"autoscalers"`
	ResourceQuotas int      `json:"resourceQuotaNamespaces"`
}

type ScoreResult struct {
	Category  string   `json:"category"`
	Level     string   `json:"level"`
	Rationale string   `json:"rationale"`
	Missing   []string `json:"missing,omitempty"`
}

// ClusterManager manages connections to multiple clusters
type ClusterConnection struct {
	Client            *kubernetes.Clientset
	DefaultNamespace  string
	AvailableContexts []string
}

type ClusterManager struct {
	Clusters map[string]*ClusterConnection
}

var clusterManager = &ClusterManager{
	Clusters: make(map[string]*ClusterConnection),
}

func main() {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// Initialize default cluster
	loadCluster("default", *kubeconfig)

	fmt.Println("Connected to Kubernetes cluster 'default'")
	fmt.Println("Starting web server on http://localhost:8080")

	// Serve static files
	fs := http.FileServer(http.Dir("./web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/clusters", handleClusters)
	http.HandleFunc("/api/cluster/upload", handleClusterUpload)
	http.HandleFunc("/api/namespaces", handleNamespaces)
	http.HandleFunc("/api/resources", handleResources)
	http.HandleFunc("/api/events", handleEvents)
	http.HandleFunc("/api/topology", handleTopology)
	http.HandleFunc("/api/resource/yaml", handleResourceYAML)
	http.HandleFunc("/api/resource/update", handleResourceUpdate)
	http.HandleFunc("/api/resource/create", handleResourceCreate)
	http.HandleFunc("/api/analysis", handleAnalysis)
	http.HandleFunc("/api/cluster/analysis", handleClusterAnalysis)
	http.HandleFunc("/api/cluster/score", handleClusterScore)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadCluster(name, configPath string) {
	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		log.Printf("Error building config for %s: %v", name, err)
		return
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Error creating clientset for %s: %v", name, err)
		return
	}
	clusterManager.Clusters[name] = &ClusterConnection{
		Client:           clientset,
		DefaultNamespace: "default",
	}
}

func getClusterConn(r *http.Request) *ClusterConnection {
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		cluster = "default"
	}
	if client, ok := clusterManager.Clusters[cluster]; ok {
		return client
	}
	if client, ok := clusterManager.Clusters["default"]; ok {
		return client
	}
	return nil
}

func respondJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": message,
	})
}

func (c *ClusterConnection) fallbackNamespace() string {
	if c == nil {
		return "default"
	}
	if c.DefaultNamespace != "" {
		return c.DefaultNamespace
	}
	return "default"
}

// handleClusterUpload accepts a kubeconfig via multipart form and registers a new cluster
func handleClusterUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB
		respondJSONError(w, http.StatusBadRequest, "Failed to parse form: "+err.Error())
		return
	}

	file, _, err := r.FormFile("kubeconfig")
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "Missing kubeconfig file: "+err.Error())
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "Failed to read kubeconfig: "+err.Error())
		return
	}

	name := r.FormValue("name")
	contextName := r.FormValue("context")

	// Load kubeconfig
	configObj, err := clientcmd.Load(data)
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid kubeconfig: "+err.Error())
		return
	}
	if contextName == "" {
		contextName = configObj.CurrentContext
	}
	if contextName == "" {
		// Try to pick any context
		for ctx := range configObj.Contexts {
			contextName = ctx
			break
		}
	}
	if contextName == "" {
		respondJSONError(w, http.StatusBadRequest, "No context found in kubeconfig")
		return
	}

	if name == "" {
		name = contextName
		if name == "" {
			name = fmt.Sprintf("cluster-%d", len(clusterManager.Clusters)+1)
		}
	}

	defaultNamespace := "default"
	if ctxCfg, ok := configObj.Contexts[contextName]; ok {
		if ctxCfg.Namespace != "" {
			defaultNamespace = ctxCfg.Namespace
		}
	}

	// Build client for the selected context
	var overrides clientcmd.ConfigOverrides
	overrides.CurrentContext = contextName
	clientCfg := clientcmd.NewNonInteractiveClientConfig(*configObj, contextName, &overrides, nil)
	restCfg, err := clientCfg.ClientConfig()
	if err != nil {
		respondJSONError(w, http.StatusBadRequest, "Failed to build client config: "+err.Error())
		return
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to create clientset: "+err.Error())
		return
	}

	// Ensure unique name
	original := name
	idx := 1
	for {
		if _, exists := clusterManager.Clusters[name]; !exists {
			break
		}
		idx++
		name = fmt.Sprintf("%s-%d", original, idx)
	}

	var contexts []string
	for ctx := range configObj.Contexts {
		contexts = append(contexts, ctx)
	}
	sort.Strings(contexts)

	clusterManager.Clusters[name] = &ClusterConnection{
		Client:            clientset,
		DefaultNamespace:  defaultNamespace,
		AvailableContexts: contexts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"name":    name,
		"context": contextName,
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("web/templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func handleClusters(w http.ResponseWriter, r *http.Request) {
	keys := make([]string, 0, len(clusterManager.Clusters))
	for k := range clusterManager.Clusters {
		keys = append(keys, k)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func handleNamespaces(w http.ResponseWriter, r *http.Request) {
	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	client := conn.Client
	namespaces, err := client.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) {
			ns := conn.fallbackNamespace()
			resp := NamespaceResponse{
				Namespaces:       []string{ns},
				DefaultNamespace: ns,
				AllowAll:         false,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		respondJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var nsList []string
	for _, ns := range namespaces.Items {
		nsList = append(nsList, ns.Name)
	}
	sort.Strings(nsList)

	defaultNS := conn.DefaultNamespace
	if defaultNS == "" && len(nsList) > 0 {
		defaultNS = nsList[0]
	}
	if defaultNS == "" {
		defaultNS = "default"
	}

	resp := NamespaceResponse{
		Namespaces:       nsList,
		DefaultNamespace: defaultNS,
		AllowAll:         true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleResources(w http.ResponseWriter, r *http.Request) {
	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	client := conn.Client
	namespace := r.URL.Query().Get("namespace")
	resourceType := r.URL.Query().Get("type")

	if namespace == "all" {
		namespace = ""
	}

	var resources []ResourceInfo
	var err error

	// Helper wrapper creates an age string
	calcAge := func(t metav1.Time) string {
		return t.Time.Format("2006-01-02 15:04:05")
	}

	switch resourceType {
	case "deployment":
		list, e := client.AppsV1().Deployments(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    fmt.Sprintf("%d/%d", item.Status.ReadyReplicas, item.Status.Replicas),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "Deployment",
					Details:   fmt.Sprintf("Rel: %d", item.Status.Replicas),
				})
			}
		}
	case "daemonset":
		list, e := client.AppsV1().DaemonSets(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    fmt.Sprintf("%d/%d", item.Status.NumberReady, item.Status.DesiredNumberScheduled),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "DaemonSet",
				})
			}
		}
	case "cronjob":
		list, e := client.BatchV1().CronJobs(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status: func() string {
						if item.Spec.Suspend != nil && *item.Spec.Suspend {
							return "Suspended"
						} else {
							return "Active"
						}
					}(),
					Age:     calcAge(item.CreationTimestamp),
					Type:    "CronJob",
					Details: item.Spec.Schedule,
				})
			}
		}
	case "job":
		list, e := client.BatchV1().Jobs(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status: func() string {
						if item.Status.Succeeded > 0 {
							return "Succeeded"
						} else if item.Status.Failed > 0 {
							return "Failed"
						} else {
							return "Running"
						}
					}(),
					Age:  calcAge(item.CreationTimestamp),
					Type: "Job",
				})
			}
		}
	case "statefulset":
		list, e := client.AppsV1().StatefulSets(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    fmt.Sprintf("%d/%d", item.Status.ReadyReplicas, item.Status.Replicas),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "StatefulSet",
					Details:   fmt.Sprintf("Rel: %d", item.Status.Replicas),
				})
			}
		}
	case "replicaset":
		list, e := client.AppsV1().ReplicaSets(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    fmt.Sprintf("%d/%d", item.Status.ReadyReplicas, item.Status.Replicas),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "ReplicaSet",
					Details:   fmt.Sprintf("Rel: %d", item.Status.Replicas),
				})
			}
		}
	case "pod":
		list, e := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    string(item.Status.Phase),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "Pod",
					Details:   item.Status.PodIP,
				})
			}
		}
	case "pvc":
		list, e := client.CoreV1().PersistentVolumeClaims(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    string(item.Status.Phase),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "PVC",
					Details:   string(item.Spec.AccessModes[0]),
				})
			}
		}
	case "configmap":
		list, e := client.CoreV1().ConfigMaps(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    "Active",
					Age:       calcAge(item.CreationTimestamp),
					Type:      "ConfigMap",
					Details:   fmt.Sprintf("%d keys", len(item.Data)),
				})
			}
		}
	case "secret":
		list, e := client.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    string(item.Type),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "Secret",
					Details:   fmt.Sprintf("%d keys", len(item.Data)),
				})
			}
		}
	case "service":
		list, e := client.CoreV1().Services(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				ports := make([]string, len(item.Spec.Ports))
				for i, p := range item.Spec.Ports {
					ports[i] = fmt.Sprintf("%d", p.Port)
				}
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    string(item.Spec.Type),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "Service",
					Details:   strings.Join(ports, ","),
				})
			}
		}
	case "ingress":
		list, e := client.NetworkingV1().Ingresses(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    "Active",
					Age:       calcAge(item.CreationTimestamp),
					Type:      "Ingress",
				})
			}
		}
	default:
		// Default to pods if unknown or empty
		list, e := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
		err = e
		if err == nil {
			for _, item := range list.Items {
				resources = append(resources, ResourceInfo{
					Name:      item.Name,
					Namespace: item.Namespace,
					Status:    string(item.Status.Phase),
					Age:       calcAge(item.CreationTimestamp),
					Type:      "Pod",
				})
			}
		}
	}

	if err != nil {
		status := http.StatusInternalServerError
		if apierrors.IsForbidden(err) {
			status = http.StatusForbidden
		}
		respondJSONError(w, status, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resources)
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	client := conn.Client
	namespace := r.URL.Query().Get("namespace")
	if namespace == "all" {
		namespace = ""
	}

	events, err := client.CoreV1().Events(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		status := http.StatusInternalServerError
		if apierrors.IsForbidden(err) {
			status = http.StatusForbidden
		}
		respondJSONError(w, status, err.Error())
		return
	}

	var eventList []EventInfo
	for _, e := range events.Items {
		eventList = append(eventList, EventInfo{
			Type:      e.Type,
			Reason:    e.Reason,
			Message:   e.Message,
			Object:    fmt.Sprintf("%s/%s", e.InvolvedObject.Kind, e.InvolvedObject.Name),
			Age:       e.LastTimestamp.Time.Format("2006-01-02 15:04:05"),
			Timestamp: e.LastTimestamp.Unix(),
		})
	}

	// Simple sort by timestamp desc
	sort.Slice(eventList, func(i, j int) bool {
		return eventList[i].Timestamp > eventList[j].Timestamp
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(eventList)
}

// Topology structs
type GraphNode struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Type      string `json:"type"`   // "ingress", "service", "pod", "deployment", "pvc", "configmap", "secret"
	Parent    string `json:"parent"` // ID of the parent node
	Status    string `json:"status"` // e.g. "Running", "Bound"
	Age       string `json:"age"`
	Details   string `json:"details"`   // e.g. "3/3" replicas or "80:3000" ports
	Namespace string `json:"namespace"` // usually same as query, but good to have
}

type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"` // "connects", "claims", "mounts"
}

type TopologyResponse struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

func handleTopology(w http.ResponseWriter, r *http.Request) {
	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	client := conn.Client
	namespace := r.URL.Query().Get("namespace")
	if namespace == "all" || namespace == "" {
		namespace = conn.fallbackNamespace()
	}

	resp := TopologyResponse{
		Nodes: []GraphNode{},
		Edges: []GraphEdge{},
	}

	// Helper to check if node exists
	nodeMap := make(map[string]bool)
	addNode := func(id, label, ntype, parent, status, age, details string) {
		if !nodeMap[id] {
			resp.Nodes = append(resp.Nodes, GraphNode{
				ID:        id,
				Label:     label,
				Type:      ntype,
				Parent:    parent,
				Status:    status,
				Age:       age,
				Details:   details,
				Namespace: namespace,
			})
			nodeMap[id] = true
		}
	}
	addEdge := func(src, tgt, etype string) {
		if nodeMap[src] && nodeMap[tgt] {
			resp.Edges = append(resp.Edges, GraphEdge{Source: src, Target: tgt, Type: etype})
		}
	}

	ctx := context.TODO()
	opts := metav1.ListOptions{}

	// Helper for age
	getAge := func(t metav1.Time) string {
		duration := time.Since(t.Time)
		if duration.Hours() > 24 {
			return fmt.Sprintf("%dd", int(duration.Hours()/24))
		}
		return fmt.Sprintf("%dh", int(duration.Hours()))
	}

	// 2. Fetch Services
	services, _ := client.CoreV1().Services(namespace).List(ctx, opts)
	for _, svc := range services.Items {
		id := "svc-" + svc.Name
		details := string(svc.Spec.Type)
		if len(svc.Spec.Ports) > 0 {
			details += fmt.Sprintf(" :%d", svc.Spec.Ports[0].Port)
		}
		addNode(id, svc.Name, "service", "", "Active", getAge(svc.CreationTimestamp), details)
	}

	// 3. Fetch Workloads (Parent Nodes)
	deployments, _ := client.AppsV1().Deployments(namespace).List(ctx, opts)
	for _, deploy := range deployments.Items {
		id := "deploy-" + deploy.Name
		status := fmt.Sprintf("%d/%d", deploy.Status.ReadyReplicas, deploy.Status.Replicas)
		details := "Deployment"
		addNode(id, deploy.Name, "deployment", "", status, getAge(deploy.CreationTimestamp), details)

		// Configs
		for _, vol := range deploy.Spec.Template.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil {
				name := vol.PersistentVolumeClaim.ClaimName
				addNode("pvc-"+name, name, "pvc", "", "Bound", "", "")
				addEdge(id, "pvc-"+name, "mounts")
			}
			if vol.ConfigMap != nil {
				name := vol.ConfigMap.Name
				addNode("cm-"+name, name, "configmap", "", "Active", "", "")
				addEdge(id, "cm-"+name, "mounts")
			}
			if vol.Secret != nil {
				name := vol.Secret.SecretName
				addNode("sec-"+name, name, "secret", "", "Active", "", "")
				addEdge(id, "sec-"+name, "mounts")
			}
		}
	}

	// MAP REPLICA SETS TO DEPLOYMENTS
	// This avoids string matching issues (e.g. "demo" matching "demo-complex")
	rsMap := make(map[string]string)
	replicaSets, _ := client.AppsV1().ReplicaSets(namespace).List(ctx, opts)
	for _, rs := range replicaSets.Items {
		for _, owner := range rs.OwnerReferences {
			if owner.Kind == "Deployment" {
				rsMap[rs.Name] = owner.Name
				break
			}
		}
	}

	statefulsets, _ := client.AppsV1().StatefulSets(namespace).List(ctx, opts)
	for _, ss := range statefulsets.Items {
		id := "ss-" + ss.Name
		status := fmt.Sprintf("%d/%d", ss.Status.ReadyReplicas, ss.Status.Replicas)
		details := "StatefulSet"
		addNode(id, ss.Name, "statefulset", "", status, getAge(ss.CreationTimestamp), details)

		// Configs
		for _, vol := range ss.Spec.Template.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil {
				name := vol.PersistentVolumeClaim.ClaimName
				addNode("pvc-"+name, name, "pvc", "", "Bound", "", "")
				addEdge(id, "pvc-"+name, "mounts")
			}
			if vol.ConfigMap != nil {
				name := vol.ConfigMap.Name
				addNode("cm-"+name, name, "configmap", "", "Active", "", "")
				addEdge(id, "cm-"+name, "mounts")
			}
			if vol.Secret != nil {
				name := vol.Secret.SecretName
				addNode("sec-"+name, name, "secret", "", "Active", "", "")
				addEdge(id, "sec-"+name, "mounts")
			}
		}
	}

	// 4. Fetch Pods
	pods, _ := client.CoreV1().Pods(namespace).List(ctx, opts)
	for _, pod := range pods.Items {
		podID := "pod-" + pod.Name

		parentID := ""
		for _, owner := range pod.OwnerReferences {
			if owner.Kind == "ReplicaSet" {
				// Use the map!
				if deployName, ok := rsMap[owner.Name]; ok {
					parentID = "deploy-" + deployName
				}
			} else if owner.Kind == "StatefulSet" {
				parentID = "ss-" + owner.Name
			}
		}

		status := string(pod.Status.Phase)
		details := pod.Status.PodIP
		addNode(podID, pod.Name, "pod", parentID, status, getAge(pod.CreationTimestamp), details)

		// Service -> (Parent or Pod)
		for _, svc := range services.Items {
			match := true
			if len(svc.Spec.Selector) == 0 {
				match = false
			}
			for k, v := range svc.Spec.Selector {
				if pod.Labels[k] != v {
					match = false
					break
				}
			}
			if match {
				target := podID
				if parentID != "" {
					target = parentID
				}
				addEdge("svc-"+svc.Name, target, "selects")
			}
		}
	}

	// 5. Fetch Ingresses (Moved to end to ensure Services exist for edge creation)
	ingresses, _ := client.NetworkingV1().Ingresses(namespace).List(ctx, opts)
	for _, ing := range ingresses.Items {
		id := "ing-" + ing.Name
		status := "Active"
		details := ""
		if len(ing.Status.LoadBalancer.Ingress) > 0 {
			details = ing.Status.LoadBalancer.Ingress[0].IP
		}
		addNode(id, ing.Name, "ingress", "", status, getAge(ing.CreationTimestamp), details)

		for _, rule := range ing.Spec.Rules {
			if rule.HTTP != nil {
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service != nil {
						svcName := path.Backend.Service.Name
						addEdge(id, "svc-"+svcName, "routes")
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleResourceYAML returns the full YAML configuration of a resource
func handleResourceYAML(w http.ResponseWriter, r *http.Request) {
	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	client := conn.Client
	namespace := r.URL.Query().Get("namespace")
	name := r.URL.Query().Get("name")
	resourceType := r.URL.Query().Get("type")

	if namespace == "" {
		namespace = conn.fallbackNamespace()
	}

	if namespace == "" || name == "" || resourceType == "" {
		respondJSONError(w, http.StatusBadRequest, "Missing required parameters: namespace, name, type")
		return
	}

	ctx := context.TODO()
	var yamlOutput string
	var err error

	switch resourceType {
	case "pod":
		obj, e := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	case "deployment":
		obj, e := client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	case "service":
		obj, e := client.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	case "configmap":
		obj, e := client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	case "secret":
		obj, e := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	case "pvc":
		obj, e := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	case "statefulset":
		obj, e := client.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	case "ingress":
		obj, e := client.NetworkingV1().Ingresses(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil {
			err = e
		} else {
			yamlOutput = toYAMLString(obj)
		}
	default:
		respondJSONError(w, http.StatusBadRequest, "Unsupported resource type: "+resourceType)
		return
	}

	if err != nil {
		status := http.StatusInternalServerError
		if apierrors.IsForbidden(err) {
			status = http.StatusForbidden
		}
		respondJSONError(w, status, "Error fetching resource: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(yamlOutput))
}

// toYAMLString converts a Kubernetes object to YAML string (simplified JSON for now)
func toYAMLString(obj interface{}) string {
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error marshaling: %v", err)
	}
	return string(data)
}

// handleResourceUpdate updates a resource from YAML/JSON input
func handleResourceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	client := conn.Client

	var updateRequest struct {
		Type      string `json:"type"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Content   string `json:"content"`
		Cluster   string `json:"cluster"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	ctx := context.TODO()
	var updateErr error

	switch updateRequest.Type {
	case "deployment":
		var deploy appsv1.Deployment
		if err := json.Unmarshal([]byte(updateRequest.Content), &deploy); err != nil {
			respondJSONError(w, http.StatusBadRequest, "Invalid deployment JSON: "+err.Error())
			return
		}
		ns := updateRequest.Namespace
		if ns == "" {
			ns = conn.fallbackNamespace()
		}
		_, updateErr = client.AppsV1().Deployments(ns).Update(ctx, &deploy, metav1.UpdateOptions{})
	case "service":
		var svc corev1.Service
		if err := json.Unmarshal([]byte(updateRequest.Content), &svc); err != nil {
			respondJSONError(w, http.StatusBadRequest, "Invalid service JSON: "+err.Error())
			return
		}
		ns := updateRequest.Namespace
		if ns == "" {
			ns = conn.fallbackNamespace()
		}
		_, updateErr = client.CoreV1().Services(ns).Update(ctx, &svc, metav1.UpdateOptions{})
	case "configmap":
		var cm corev1.ConfigMap
		if err := json.Unmarshal([]byte(updateRequest.Content), &cm); err != nil {
			respondJSONError(w, http.StatusBadRequest, "Invalid configmap JSON: "+err.Error())
			return
		}
		ns := updateRequest.Namespace
		if ns == "" {
			ns = conn.fallbackNamespace()
		}
		_, updateErr = client.CoreV1().ConfigMaps(ns).Update(ctx, &cm, metav1.UpdateOptions{})
	case "secret":
		var secret corev1.Secret
		if err := json.Unmarshal([]byte(updateRequest.Content), &secret); err != nil {
			respondJSONError(w, http.StatusBadRequest, "Invalid secret JSON: "+err.Error())
			return
		}
		ns := updateRequest.Namespace
		if ns == "" {
			ns = conn.fallbackNamespace()
		}
		_, updateErr = client.CoreV1().Secrets(ns).Update(ctx, &secret, metav1.UpdateOptions{})
	case "statefulset":
		var ss appsv1.StatefulSet
		if err := json.Unmarshal([]byte(updateRequest.Content), &ss); err != nil {
			respondJSONError(w, http.StatusBadRequest, "Invalid statefulset JSON: "+err.Error())
			return
		}
		ns := updateRequest.Namespace
		if ns == "" {
			ns = conn.fallbackNamespace()
		}
		_, updateErr = client.AppsV1().StatefulSets(ns).Update(ctx, &ss, metav1.UpdateOptions{})
	default:
		respondJSONError(w, http.StatusBadRequest, "Unsupported resource type for update: "+updateRequest.Type)
		return
	}

	if updateErr != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": updateErr.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Resource updated successfully",
	})
}

// handleResourceCreate creates new Kubernetes resources
func handleResourceCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	conn := getClusterConn(r)
	if conn == nil {
		respondJSONError(w, http.StatusServiceUnavailable, "No cluster configured")
		return
	}
	client := conn.Client

	var req struct {
		Type          string `json:"type"`
		Name          string `json:"name"`
		Replicas      int32  `json:"replicas"`
		ContainerName string `json:"containerName"`
		Image         string `json:"image"`
		ContainerPort int32  `json:"containerPort"`
		Namespace     string `json:"namespace"`
		Cluster       string `json:"cluster"`
		Service       *struct {
			Type string `json:"type"`
			Port int32  `json:"port"`
		} `json:"service"`
		ConfigMap *struct {
			MountPath string `json:"mountPath"`
		} `json:"configMap"`
		Secret *struct {
			MountPath string `json:"mountPath"`
		} `json:"secret"`
		PVC *struct {
			Size      string `json:"size"`
			MountPath string `json:"mountPath"`
		} `json:"pvc"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSONError(w, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	if req.Namespace == "" {
		req.Namespace = conn.fallbackNamespace()
	}

	ctx := context.TODO()
	labels := map[string]string{"app": req.Name}
	var createdResources []string

	// Create ConfigMap if requested
	if req.ConfigMap != nil {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.Name + "-config",
				Namespace: req.Namespace,
				Labels:    labels,
			},
			Data: map[string]string{
				"config.yaml": "# Your config here",
			},
		}
		if _, err := client.CoreV1().ConfigMaps(req.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to create ConfigMap: "+err.Error())
			return
		}
		createdResources = append(createdResources, "ConfigMap")
	}

	// Create Secret if requested
	if req.Secret != nil {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.Name + "-secret",
				Namespace: req.Namespace,
				Labels:    labels,
			},
			StringData: map[string]string{
				"password": "changeme",
			},
		}
		if _, err := client.CoreV1().Secrets(req.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to create Secret: "+err.Error())
			return
		}
		createdResources = append(createdResources, "Secret")
	}

	// Create PVC if requested
	if req.PVC != nil {
		storageClass := ""
		pvc := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.Name + "-pvc",
				Namespace: req.Namespace,
				Labels:    labels,
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				StorageClassName: &storageClass,
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse(req.PVC.Size),
					},
				},
			},
		}
		if _, err := client.CoreV1().PersistentVolumeClaims(req.Namespace).Create(ctx, pvc, metav1.CreateOptions{}); err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to create PVC: "+err.Error())
			return
		}
		createdResources = append(createdResources, "PVC")
	}

	// Build container spec with volume mounts
	container := corev1.Container{
		Name:  req.ContainerName,
		Image: req.Image,
		Ports: []corev1.ContainerPort{{ContainerPort: req.ContainerPort}},
	}

	var volumes []corev1.Volume
	var volumeMounts []corev1.VolumeMount

	if req.ConfigMap != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: req.Name + "-config"},
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "config",
			MountPath: req.ConfigMap.MountPath,
		})
	}

	if req.Secret != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "secret",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: req.Name + "-secret",
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secret",
			MountPath: req.Secret.MountPath,
		})
	}

	if req.PVC != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: req.Name + "-pvc",
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "data",
			MountPath: req.PVC.MountPath,
		})
	}

	container.VolumeMounts = volumeMounts

	// Create Deployment
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &req.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{container},
					Volumes:    volumes,
				},
			},
		},
	}

	if _, err := client.AppsV1().Deployments(req.Namespace).Create(ctx, deploy, metav1.CreateOptions{}); err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to create Deployment: "+err.Error())
		return
	}
	createdResources = append(createdResources, "Deployment")

	// Create Service if requested
	if req.Service != nil {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.Name + "-svc",
				Namespace: req.Namespace,
				Labels:    labels,
			},
			Spec: corev1.ServiceSpec{
				Selector: labels,
				Type:     corev1.ServiceType(req.Service.Type),
				Ports: []corev1.ServicePort{{
					Port:       req.Service.Port,
					TargetPort: intstr.FromInt(int(req.ContainerPort)),
				}},
			},
		}
		if _, err := client.CoreV1().Services(req.Namespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			respondJSONError(w, http.StatusInternalServerError, "Failed to create Service: "+err.Error())
			return
		}
		createdResources = append(createdResources, "Service")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Created: %v", createdResources),
		"created": createdResources,
	})
}

func handleAnalysis(w http.ResponseWriter, r *http.Request) {
	rows, err := parseCompositeAssessment("test.md")
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Failed to build analysis: "+err.Error())
		return
	}

	payload := map[string]interface{}{
		"rows":        rows,
		"generatedAt": time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("encode analysis response failed: %v", err)
	}
}

func parseCompositeAssessment(path string) ([]AnalysisRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	start := strings.Index(content, "## COMPOSITE ASSESSMENT MATRIX")
	if start == -1 {
		return nil, fmt.Errorf("composite assessment section not found")
	}
	section := content[start:]
	endMarker := "## 2026 Action Plan Template"
	if idx := strings.Index(section, endMarker); idx != -1 {
		section = section[:idx]
	}

	scanner := bufio.NewScanner(strings.NewReader(section))
	var rows []AnalysisRow
	lineCount := 0
	inTable := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if inTable && lineCount > 0 {
				break
			}
			continue
		}

		if strings.HasPrefix(line, "|") {
			inTable = true
			lineCount++
			if lineCount <= 2 {
				continue // skip header + alignment rows
			}

			parts := strings.Split(line, "|")
			if len(parts) < 8 {
				continue
			}

			row := AnalysisRow{
				Title:         sanitizeCell(parts[1]),
				ProdLevel:     sanitizeCell(parts[2]),
				StagingLevel:  sanitizeCell(parts[3]),
				DevLevel:      sanitizeCell(parts[4]),
				ProdTarget:    sanitizeCell(parts[5]),
				StagingTarget: sanitizeCell(parts[6]),
				DevTarget:     sanitizeCell(parts[7]),
			}
			if row.Title != "" {
				rows = append(rows, row)
			}
			continue
		}

		if inTable {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no rows parsed from assessment table")
	}
	return rows, nil
}

func sanitizeCell(val string) string {
	v := strings.TrimSpace(val)
	v = strings.Trim(v, "`")
	v = strings.ReplaceAll(v, "*", "")
	v = strings.ReplaceAll(v, "_", "")
	v = strings.ReplaceAll(v, "~", "")
	return strings.TrimSpace(v)
}

// --- Cluster analysis (best-effort heuristics) ---

func handleClusterAnalysis(w http.ResponseWriter, r *http.Request) {
	conn := getClusterConn(r)
	if conn == nil || conn.Client == nil {
		respondJSONError(w, http.StatusBadRequest, "Cluster client not available")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signals, warnings, err := collectClusterSignals(ctx, conn.Client)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Cluster analysis failed: "+err.Error())
		return
	}

	resp := ClusterAnalysisResponse{
		Cluster:       r.URL.Query().Get("cluster"),
		Generated:     time.Now().UTC().Format(time.RFC3339),
		Nodes:         signals.Nodes,
		Network:       signals.Network,
		Security:      signals.Security,
		Observability: signals.Observability,
		GitOps:        signals.GitOps,
		Backup:        signals.Backup,
		Workload:      signals.Workload,
		Warnings:      warnings,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type collectedSignals struct {
	Nodes         NodeSignals
	Network       NetworkSignals
	Security      SecuritySignals
	Observability ObservabilitySignals
	GitOps        GitOpsSignals
	Backup        BackupSignals
	Workload      WorkloadSignals
}

func collectClusterSignals(ctx context.Context, client *kubernetes.Clientset) (collectedSignals, []string, error) {
	var warns []string
	out := collectedSignals{}

	// Nodes
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, warns, err
	}
	controlPlanes := 0
	zones := map[string]struct{}{}
	for _, n := range nodes.Items {
		if isControlPlaneNode(&n) {
			controlPlanes++
		}
		if z, ok := n.Labels["topology.kubernetes.io/zone"]; ok && z != "" {
			zones[z] = struct{}{}
		}
	}
	zoneList := make([]string, 0, len(zones))
	for z := range zones {
		zoneList = append(zoneList, z)
	}
	sort.Strings(zoneList)
	out.Nodes = NodeSignals{
		Total:         len(nodes.Items),
		ControlPlanes: controlPlanes,
		Zones:         zoneList,
		HasHA:         controlPlanes >= 3 && len(zoneList) >= 2,
		CNI:           "",
	}

	// Workload resources to detect components
	deploys, err := client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, warns, err
	}
	daemonsets, err := client.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, warns, err
	}
	statefulsets, err := client.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, warns, err
	}

	// CNI detection (daemonset in kube-system is typical)
	out.Nodes.CNI = detectCNI(daemonsets.Items)

	// Network policies
	nps, err := client.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, warns, err
	}
	out.Network.NetworkPolicies = len(nps.Items)
	out.Network.DefaultDenyNS = detectDefaultDenyNamespaces(nps.Items)

	// Ingress controllers
	out.Network.Ingresses = detectIngressControllers(deploys.Items, daemonsets.Items)

	// Security signals
	out.Security.CertManager = hasDeploymentLike(deploys.Items, "cert-manager")
	out.Security.PSAEnforce = detectPSAEnforceNamespaces(ctx, client)

	// Observability
	out.Observability.Prometheus = hasDeploymentLike(deploys.Items, "prometheus")
	out.Observability.Alertmanager = hasDeploymentLike(deploys.Items, "alertmanager")
	out.Observability.Grafana = hasDeploymentLike(deploys.Items, "grafana")
	out.Observability.KubeStateMetrics = hasDeploymentLike(deploys.Items, "kube-state-metrics")
	out.Observability.EFK = hasAnyStatefulSetLike(statefulsets.Items, []string{"elasticsearch", "opensearch"}) &&
		(hasDaemonSetLike(daemonsets.Items, "fluentd") || hasDaemonSetLike(daemonsets.Items, "fluent-bit")) &&
		hasDeploymentLike(deploys.Items, "kibana")

	// GitOps
	out.GitOps.ArgoCD = hasDeploymentLike(deploys.Items, "argocd")

	// Backup
	out.Backup.Velero = hasDeploymentLike(deploys.Items, "velero")

	// Workload / autoscaling signals
	hpas, err := client.AutoscalingV2().HorizontalPodAutoscalers(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		warns = append(warns, "HPA list failed: "+err.Error())
	} else {
		out.Workload.HPAs = len(hpas.Items)
	}
	autos := detectAutoscalers(deploys.Items, daemonsets.Items)
	out.Workload.Autoscalers = autos
	out.Workload.ResourceQuotas = countNamespacesWithResourceQuotas(ctx, client)

	return out, warns, nil
}

func isControlPlaneNode(n *corev1.Node) bool {
	if n == nil {
		return false
	}
	if _, ok := n.Labels["node-role.kubernetes.io/master"]; ok {
		return true
	}
	if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok {
		return true
	}
	return false
}

func detectCNI(dss []appsv1.DaemonSet) string {
	for _, ds := range dss {
		name := strings.ToLower(ds.Name)
		switch {
		case strings.Contains(name, "calico"):
			return "Calico"
		case strings.Contains(name, "cilium"):
			return "Cilium"
		case strings.Contains(name, "flannel"):
			return "Flannel"
		case strings.Contains(name, "weave"):
			return "Weave"
		case strings.Contains(name, "ovn"):
			return "OVN"
		}
	}
	return ""
}

func detectIngressControllers(deploys []appsv1.Deployment, dss []appsv1.DaemonSet) []string {
	var out []string
	candidates := []string{"ingress-nginx", "nginx-ingress", "traefik", "contour", "haproxy", "haproxy-ingress", "istio-ingress", "kong"}
	for _, d := range deploys {
		for _, c := range candidates {
			if strings.Contains(strings.ToLower(d.Name), c) {
				out = append(out, d.Namespace+"/"+d.Name)
				break
			}
		}
	}
	for _, ds := range dss {
		for _, c := range candidates {
			if strings.Contains(strings.ToLower(ds.Name), c) {
				out = append(out, ds.Namespace+"/"+ds.Name)
				break
			}
		}
	}
	return out
}

func detectDefaultDenyNamespaces(nps []networkingv1.NetworkPolicy) []string {
	nsSet := map[string]struct{}{}
	for _, np := range nps {
		if len(np.Spec.PolicyTypes) == 0 {
			continue
		}
		if len(np.Spec.Ingress) == 0 && len(np.Spec.Egress) == 0 && len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0 {
			nsSet[np.Namespace] = struct{}{}
		}
	}
	out := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

func detectPSAEnforceNamespaces(ctx context.Context, client *kubernetes.Clientset) []string {
	list, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	var out []string
	for _, ns := range list.Items {
		if lvl, ok := ns.Labels["pod-security.kubernetes.io/enforce"]; ok && lvl != "" {
			out = append(out, ns.Name+" ("+lvl+")")
		}
	}
	sort.Strings(out)
	return out
}

func hasDeploymentLike(items []appsv1.Deployment, needle string) bool {
	needle = strings.ToLower(needle)
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Name), needle) {
			return true
		}
	}
	return false
}

func hasDaemonSetLike(items []appsv1.DaemonSet, needle string) bool {
	needle = strings.ToLower(needle)
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Name), needle) {
			return true
		}
	}
	return false
}

func hasStatefulSetLike(items []appsv1.StatefulSet, needle string) bool {
	needle = strings.ToLower(needle)
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Name), needle) {
			return true
		}
	}
	return false
}

func hasAnyStatefulSetLike(items []appsv1.StatefulSet, needles []string) bool {
	for _, n := range needles {
		if hasStatefulSetLike(items, n) {
			return true
		}
	}
	return false
}

func detectAutoscalers(deploys []appsv1.Deployment, dss []appsv1.DaemonSet) []string {
	var out []string
	for _, d := range deploys {
		name := strings.ToLower(d.Name)
		switch {
		case strings.Contains(name, "cluster-autoscaler"):
			out = append(out, d.Namespace+"/"+d.Name)
		case strings.Contains(name, "karpenter"):
			out = append(out, d.Namespace+"/"+d.Name)
		}
	}
	for _, ds := range dss {
		name := strings.ToLower(ds.Name)
		switch {
		case strings.Contains(name, "cluster-autoscaler"):
			out = append(out, ds.Namespace+"/"+ds.Name)
		case strings.Contains(name, "karpenter"):
			out = append(out, ds.Namespace+"/"+ds.Name)
		}
	}
	return out
}

func countNamespacesWithResourceQuotas(ctx context.Context, client *kubernetes.Clientset) int {
	nss, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}
	count := 0
	for _, ns := range nss.Items {
		rqs, err := client.CoreV1().ResourceQuotas(ns.Name).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			continue
		}
		if len(rqs.Items) > 0 {
			count++
		}
	}
	return count
}

// --- Cluster scoring (heuristic mapping to levels) ---

func handleClusterScore(w http.ResponseWriter, r *http.Request) {
	conn := getClusterConn(r)
	if conn == nil || conn.Client == nil {
		respondJSONError(w, http.StatusBadRequest, "Cluster client not available")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signals, warns, err := collectClusterSignals(ctx, conn.Client)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "Cluster analysis failed: "+err.Error())
		return
	}

	results := scoreCluster(signals)
	payload := map[string]interface{}{
		"generatedAt": time.Now().UTC().Format(time.RFC3339),
		"cluster":     r.URL.Query().Get("cluster"),
		"scores":      results,
		"warnings":    warns,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

func scoreCluster(sig collectedSignals) []ScoreResult {
	var out []ScoreResult

	// HA / Control Plane
	haLevel := "L1"
	var missing []string
	if sig.Nodes.ControlPlanes >= 3 && len(sig.Nodes.Zones) >= 2 {
		haLevel = "L4"
	} else if sig.Nodes.ControlPlanes >= 3 {
		haLevel = "L3"
		missing = append(missing, "Farklı AZ/zone dağılımı")
	} else if sig.Nodes.ControlPlanes == 2 {
		haLevel = "L2"
		missing = append(missing, "3+ control-plane")
	} else {
		missing = append(missing, "Multi-CP setup")
	}
	out = append(out, ScoreResult{
		Category:  "HA / Control Plane",
		Level:     haLevel,
		Rationale: fmt.Sprintf("ControlPlanes=%d Zones=%d", sig.Nodes.ControlPlanes, len(sig.Nodes.Zones)),
		Missing:   missing,
	})

	// CNI + NetworkPolicy
	npLevel := "L1"
	var npMissing []string
	if sig.Network.NetworkPolicies > 0 {
		npLevel = "L2"
		if len(sig.Network.DefaultDenyNS) > 0 {
			npLevel = "L3"
		} else {
			npMissing = append(npMissing, "Default-deny namespace")
		}
	} else {
		npMissing = append(npMissing, "NetworkPolicy yok")
	}
	if sig.Nodes.CNI == "" {
		npMissing = append(npMissing, "CNI tespiti yok")
	}
	out = append(out, ScoreResult{
		Category:  "NetworkPolicy / CNI",
		Level:     npLevel,
		Rationale: fmt.Sprintf("NP=%d DefaultDeny=%d CNI=%s", sig.Network.NetworkPolicies, len(sig.Network.DefaultDenyNS), sig.Nodes.CNI),
		Missing:   npMissing,
	})

	// Security (cert-manager + PSA)
	secLevel := "L1"
	var secMissing []string
	if sig.Security.CertManager {
		secLevel = "L2"
	} else {
		secMissing = append(secMissing, "cert-manager yok")
	}
	if len(sig.Security.PSAEnforce) > 0 {
		if secLevel == "L2" {
			secLevel = "L3"
		}
	} else {
		secMissing = append(secMissing, "PSA enforce label'lı NS yok")
	}
	out = append(out, ScoreResult{
		Category:  "Security / Certificates",
		Level:     secLevel,
		Rationale: fmt.Sprintf("cert-manager=%t PSA enforce NS=%d", sig.Security.CertManager, len(sig.Security.PSAEnforce)),
		Missing:   secMissing,
	})

	// Observability
	obsLevel := "L1"
	var obsMissing []string
	if sig.Observability.Prometheus && sig.Observability.Grafana && sig.Observability.KubeStateMetrics {
		obsLevel = "L3"
	} else {
		if !sig.Observability.Prometheus {
			obsMissing = append(obsMissing, "Prometheus yok")
		}
		if !sig.Observability.Grafana {
			obsMissing = append(obsMissing, "Grafana yok")
		}
		if !sig.Observability.KubeStateMetrics {
			obsMissing = append(obsMissing, "kube-state-metrics yok")
		}
	}
	if obsLevel == "L3" && sig.Observability.Alertmanager {
		obsLevel = "L4"
	} else if obsLevel == "L3" {
		obsMissing = append(obsMissing, "Alertmanager yok")
	}
	out = append(out, ScoreResult{
		Category:  "Observability",
		Level:     obsLevel,
		Rationale: fmt.Sprintf("Prom=%t Grafana=%t KSM=%t Alertmanager=%t EFK=%t", sig.Observability.Prometheus, sig.Observability.Grafana, sig.Observability.KubeStateMetrics, sig.Observability.Alertmanager, sig.Observability.EFK),
		Missing:   obsMissing,
	})

	// GitOps
	gitopsLevel := "L1"
	var gitopsMissing []string
	if sig.GitOps.ArgoCD {
		gitopsLevel = "L3"
	} else {
		gitopsMissing = append(gitopsMissing, "ArgoCD yok")
	}
	out = append(out, ScoreResult{
		Category:  "GitOps",
		Level:     gitopsLevel,
		Rationale: fmt.Sprintf("ArgoCD=%t", sig.GitOps.ArgoCD),
		Missing:   gitopsMissing,
	})

	// Backup
	backupLevel := "L1"
	var backupMissing []string
	if sig.Backup.Velero {
		backupLevel = "L3"
	} else {
		backupMissing = append(backupMissing, "Velero yok")
	}
	out = append(out, ScoreResult{
		Category:  "Backup",
		Level:     backupLevel,
		Rationale: fmt.Sprintf("Velero=%t", sig.Backup.Velero),
		Missing:   backupMissing,
	})

	// Autoscaling / Resource Management
	autoLevel := "L1"
	var autoMissing []string
	if sig.Workload.HPAs > 0 {
		autoLevel = "L2"
	} else {
		autoMissing = append(autoMissing, "HPA yok")
	}
	if len(sig.Workload.Autoscalers) > 0 {
		if autoLevel == "L2" {
			autoLevel = "L3"
		}
	} else {
		autoMissing = append(autoMissing, "Cluster autoscaler/Karpenter yok")
	}
	if sig.Workload.ResourceQuotas > 0 && autoLevel == "L3" {
		autoLevel = "L4"
	} else if sig.Workload.ResourceQuotas == 0 {
		autoMissing = append(autoMissing, "ResourceQuota uygulanmıyor")
	}
	out = append(out, ScoreResult{
		Category:  "Autoscaling & Quota",
		Level:     autoLevel,
		Rationale: fmt.Sprintf("HPA=%d Autoscaler=%d RQ-NS=%d", sig.Workload.HPAs, len(sig.Workload.Autoscalers), sig.Workload.ResourceQuotas),
		Missing:   autoMissing,
	})

	return out
}
