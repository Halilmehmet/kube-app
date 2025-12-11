package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

// ClusterManager manages connections to multiple clusters
type ClusterManager struct {
	Clusters map[string]*kubernetes.Clientset
}

var clusterManager = &ClusterManager{
	Clusters: make(map[string]*kubernetes.Clientset),
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
	http.HandleFunc("/api/namespaces", handleNamespaces)
	http.HandleFunc("/api/resources", handleResources)
	http.HandleFunc("/api/events", handleEvents)
	http.HandleFunc("/api/topology", handleTopology)
	http.HandleFunc("/api/resource/yaml", handleResourceYAML)
	http.HandleFunc("/api/resource/update", handleResourceUpdate)
	http.HandleFunc("/api/resource/create", handleResourceCreate)

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
	clusterManager.Clusters[name] = clientset
}

func getClient(r *http.Request) *kubernetes.Clientset {
	cluster := r.URL.Query().Get("cluster")
	if cluster == "" {
		cluster = "default"
	}
	if client, ok := clusterManager.Clusters[cluster]; ok {
		return client
	}
	// Fallback to default if not found
	return clusterManager.Clusters["default"]
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
	client := getClient(r)
	namespaces, err := client.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var nsList []string
	for _, ns := range namespaces.Items {
		nsList = append(nsList, ns.Name)
	}
	sort.Strings(nsList)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nsList)
}

func handleResources(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resources)
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	client := getClient(r)
	namespace := r.URL.Query().Get("namespace")
	if namespace == "all" {
		namespace = ""
	}

	events, err := client.CoreV1().Events(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	client := getClient(r)
	namespace := r.URL.Query().Get("namespace")
	if namespace == "all" || namespace == "" {
		namespace = "default"
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
	client := getClient(r)
	namespace := r.URL.Query().Get("namespace")
	name := r.URL.Query().Get("name")
	resourceType := r.URL.Query().Get("type")

	if namespace == "" || name == "" || resourceType == "" {
		http.Error(w, "Missing required parameters: namespace, name, type", http.StatusBadRequest)
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
		http.Error(w, "Unsupported resource type: "+resourceType, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Error fetching resource: "+err.Error(), http.StatusInternalServerError)
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client := getClient(r)

	var updateRequest struct {
		Type      string `json:"type"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Content   string `json:"content"`
		Cluster   string `json:"cluster"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ctx := context.TODO()
	var updateErr error

	switch updateRequest.Type {
	case "deployment":
		var deploy appsv1.Deployment
		if err := json.Unmarshal([]byte(updateRequest.Content), &deploy); err != nil {
			http.Error(w, "Invalid deployment JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, updateErr = client.AppsV1().Deployments(updateRequest.Namespace).Update(ctx, &deploy, metav1.UpdateOptions{})
	case "service":
		var svc corev1.Service
		if err := json.Unmarshal([]byte(updateRequest.Content), &svc); err != nil {
			http.Error(w, "Invalid service JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, updateErr = client.CoreV1().Services(updateRequest.Namespace).Update(ctx, &svc, metav1.UpdateOptions{})
	case "configmap":
		var cm corev1.ConfigMap
		if err := json.Unmarshal([]byte(updateRequest.Content), &cm); err != nil {
			http.Error(w, "Invalid configmap JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, updateErr = client.CoreV1().ConfigMaps(updateRequest.Namespace).Update(ctx, &cm, metav1.UpdateOptions{})
	case "secret":
		var secret corev1.Secret
		if err := json.Unmarshal([]byte(updateRequest.Content), &secret); err != nil {
			http.Error(w, "Invalid secret JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, updateErr = client.CoreV1().Secrets(updateRequest.Namespace).Update(ctx, &secret, metav1.UpdateOptions{})
	case "statefulset":
		var ss appsv1.StatefulSet
		if err := json.Unmarshal([]byte(updateRequest.Content), &ss); err != nil {
			http.Error(w, "Invalid statefulset JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, updateErr = client.AppsV1().StatefulSets(updateRequest.Namespace).Update(ctx, &ss, metav1.UpdateOptions{})
	default:
		http.Error(w, "Unsupported resource type for update: "+updateRequest.Type, http.StatusBadRequest)
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	client := getClient(r)

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
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
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
			http.Error(w, "Failed to create ConfigMap: "+err.Error(), http.StatusInternalServerError)
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
			http.Error(w, "Failed to create Secret: "+err.Error(), http.StatusInternalServerError)
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
			http.Error(w, "Failed to create PVC: "+err.Error(), http.StatusInternalServerError)
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
		http.Error(w, "Failed to create Deployment: "+err.Error(), http.StatusInternalServerError)
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
			http.Error(w, "Failed to create Service: "+err.Error(), http.StatusInternalServerError)
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
