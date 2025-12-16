package main

import (
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
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

// ClusterManager manages connections to multiple clusters
type ClusterConnection struct {
	Client            *kubernetes.Clientset
	DefaultNamespace  string
	AvailableContexts []string
	Kubeconfig        []byte
	Context           string
	Insecure          bool
}

type ClusterManager struct {
	Clusters map[string]*ClusterConnection
}

var clusterManager = &ClusterManager{
	Clusters: make(map[string]*ClusterConnection),
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

var reqSeq uint64

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := atomic.AddUint64(&reqSeq, 1)
		start := time.Now()

		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[req:%d] PANIC %s %s: %v", id, r.Method, r.URL.Path, rec)
				http.Error(sw, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			d := time.Since(start)
			log.Printf("[req:%d] %s %s -> %d (%dB) in %s", id, r.Method, r.URL.Path, sw.status, sw.bytes, d.Truncate(time.Millisecond))
		}()

		next.ServeHTTP(sw, r)
	})
}

func main() {
	var kubeconfig *string
	var port *string
	defaultKubeconfig := strings.TrimSpace(os.Getenv("KUBECONFIG"))
	if defaultKubeconfig == "" {
		if home := homedir.HomeDir(); home != "" {
			defaultKubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
	kubeconfig = flag.String("kubeconfig", defaultKubeconfig, "(optional) absolute path to the kubeconfig file (defaults to $KUBECONFIG or ~/.kube/config)")
	port = flag.String("port", "8080", "HTTP listen port")
	flag.Parse()

	// Initialize default cluster
	loadCluster("default", *kubeconfig)

	fmt.Println("Connected to Kubernetes cluster 'default'")
	fmt.Printf("Starting web server on http://localhost:%s\n", *port)

	mux := http.NewServeMux()

	// Serve static files
	fs := http.FileServer(http.Dir("./web/static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/clusters", handleClusters)
	mux.HandleFunc("/api/cluster/upload", handleClusterUpload)
	mux.HandleFunc("/api/namespaces", handleNamespaces)
	mux.HandleFunc("/api/resources", handleResources)
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/topology", handleTopology)
	mux.HandleFunc("/api/resource/yaml", handleResourceYAML)
	mux.HandleFunc("/api/resource/update", handleResourceUpdate)
	mux.HandleFunc("/api/resource/create", handleResourceCreate)
	mux.HandleFunc("/api/maturity/criteria", handleMaturityCriteria)
	mux.HandleFunc("/api/maturity/evidence", handleMaturityEvidence)
	mux.HandleFunc("/api/maturity/questions", handleMaturityQuestions)
	mux.HandleFunc("/api/maturity/explain", handleMaturityExplain)
	mux.HandleFunc("/api/maturity/analyze", handleMaturityAnalyze)
	mux.HandleFunc("/api/maturity/report/pdf", handleMaturityReportPDF)

	log.Fatal(http.ListenAndServe(":"+*port, withRequestLogging(mux)))
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
	var kubeconfigBytes []byte
	if configPath != "" {
		if b, err := os.ReadFile(configPath); err == nil {
			kubeconfigBytes = b
		}
	}
	clusterManager.Clusters[name] = &ClusterConnection{
		Client:           clientset,
		DefaultNamespace: "default",
		Kubeconfig:       kubeconfigBytes,
		Insecure:         config.Insecure || config.TLSClientConfig.Insecure,
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
	insecure := strings.EqualFold(strings.TrimSpace(r.FormValue("insecure")), "true")

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
	if insecure {
		// client-go rejects mixing Insecure=true with a root CA config (CAFile/CAData).
		restCfg.Insecure = true
		restCfg.TLSClientConfig.Insecure = true
		restCfg.TLSClientConfig.CAFile = ""
		restCfg.TLSClientConfig.CAData = nil
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
		Kubeconfig:        data,
		Context:           contextName,
		Insecure:          insecure,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"name":    name,
		"context": contextName,
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" {
		respondJSONError(w, http.StatusNotFound, "API route not found")
		return
	}

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
