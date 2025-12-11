Bu döküman, birden fazla Kubernetes ortamınızda her bir başlığın mevcut yetkinliğini değerlendirebilmeniz ve 2026 için CNCF/endüstri standartlarında bir production-grade cluster oluşturmanız için gerekli adımları takip etmenizi sağlamak üzere hazırlanmıştır.


***

## Maturity Levels Framework

Her görev başlığı için 5 seviye tanımlanmıştır:



| Seviye | Tanım | İş Durumu |
|:---|:---|:---|
| **Level 1 - Initial** | Manuel, tamamen ad-hoc yapılan işler; standart yok, dokümantasyon yok | Cluster var ancak risk taşıyor |
| **Level 2 - Exploratory** | Bazı araçlar deneniliyor ancak tutarlılık yok; kısmi dokümantasyon | Işlerin bir kısmı otomatize |
| **Level 3 - Fundamental** | Tutarlı prosesler, dokümantasyon, temel otomasyon; best practices uygulanıyor | Standart prosesler var, güvenilir |
| **Level 4 - Repeatable** | Tam otomasyonu, CI/CD entegrasyonu, tüm cluster'lar tutarlı; audit trail mevcut | Enterprise-ready, scalable |
| **Level 5 - Optimized** | AI-driven insights, proaktif iyileştirmeler, continuous improvement; self-service | Industry leading, future-proof |



***

## 1. Cluster Kurulumu ve Yaşam Döngüsü Yönetimi

### Alt Başlıklar & Assessment Kriterleri

#### 1.1 HA Mimarisi ve Control Plane

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Control Plane Redundancy** | Single master | 2 master, aynı AZ(Availability Zone) | 3+ master, farklı AZ'ler(Availability Zone) | 3+ master, distributed, load balanced | 5+ master, multi-region ready |
| **etcd Konfigürasyonu** | Embedded | 3-node etcd (test) | 3+ node etcd, backup automated | 5-node etcd, snapshot policy | Multi-region etcd federation |
| **API Server LB** | Direct access | Manual LB | LB with health checks | Highly available LB, auto-failover | Multi-region LB, geo-failover |
| **Backup Stratejisi** | Manual, inconsistent | Ad-hoc snapshots | Daily automated snapshot | Hourly snapshot + offsite backup | Real-time replication + DR site |
| **RTO/RPO Tanımı** | Undefined | Estimated | Documented but not tested | Tested quarterly | Tested monthly, SLA backed |

\*\*\* Availability Zone, aynı region içinde bulunan; güç, ağ ve soğutma altyapısı birbirinden izole, bir veya birden fazla veri merkezinden oluşan fiziksel bir lokasyonu ifade eder.

\*\*\* RTO (Recovery Time Objective): Bir kesinti veya felaket sonrası, sistemlerin kabul edilebilir seviyede tekrar ayağa kalkması için izin verilen maksimum kesinti süresi (örneğin 1 saat, 4 saat vb.).

\*\*\* RPO (Recovery Point Objective): Bir kesinti olduğunda kaybetmeyi göze alabileceğin maksimum veri süresi; yani backup’ların ne kadar geriye dönük olabileceği (örneğin en fazla 15 dakika, 1 saatlik veri kaybına tolerans).

**2026 Target:** Level 4 (Repeatable)

- [ ] 3+ control-plane node'u farklı AZ'lerde deployed
- [ ] External load balancer TCP health check ile configure
- [ ] etcd daily automated backup, offsite storage
- [ ] RTO/RPO dokumente ve test edilmiş


***

#### 1.2 Upgrade Stratejileri

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Upgrade Planlama** | Acil durumlarda | Biannual plans | Quarterly planning, staging test | Monthly planning, pre-prod validation | Continuous upgrade pipeline |
| **Control Plane Upgrade** | Single master yükseltme(1 Master Yapısında) | Manual master update | Rolling update, cordon strategy | Automated, blue/green ready | Canary upgrade, automated rollback |
| **Worker Node Upgrade** | Tüm nodes aynı anda | Batch update(belirli grup node ile update) , manual cordon | Scheduled rolling, drain policy | Automated, PDB enforcement | Canary + feature flags |
| **Rollback Capability** | Manual restore attempt | Documented steps | Tested rollback procedure | Automated rollback, version pinning | Instant rollback, helm hooks |
| **Version Support Policy** | Latest + 1 | Latest + 2 versions tracked | N-2 support tracked | N-1 minimum, LTS preferred | N-2 minimum with patch strategy |

\*\*\* N = En son desteklenen minor Kubernetes versiyonu (örnek: Kubernetes 1.31 ise N=1.31).

**2026 Target:** Level 4 (Repeatable)

- [ ] Quarterly upgrade plan yazılı
- [ ] Pre-prod staging ortamında full upgrade test
- [ ] Rolling update policy (maxSurge=1, maxUnavailable=0)
- [ ] Tested rollback procedure dokumente
- [ ] Upgrade automation script/tool


***

#### 1.3 Infrastructure as Code (IaC)

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| Cluster Provisioning (RKE2) | Cloud console/manuel VM + manuel rke2 install | Altyapı Ansible, rke2 install script/ansible ile manuel | Ansible ile uçtan uca rke2 provisioning (VPC, SG, LB, node, install) | Ansible + Rancher/Fleet/ArgoCD ile declarative cluster yönetimi | Full IaC + multi‑cloud, cluster API / policy‑driven otomasyon |
| Configuration Drift Detection | Manuel kontrol | Ara sıra config karşılaştırma | Drift detection aracı (örn. Ansible plan, Git diff) | Sürekli drift izleme + otomatik düzeltme (GitOps reconcile) | AI destekli drift tahmini ve proaktif önleme |
| Version Control | Lokal dosyalar, kişisel scriptler | Git repo, manuel sync (dokümansız branching) | Git tabanlı, environment bazlı branch/dir stratejisi | Tam GitOps, tüm değişiklikler MR/PR ile, audit trail mevcut | Signed commits, policy‑as‑code ile korunan audit ve compliance kayıtları |

\*\*\* Configuration Drift Detection Canlı cluster/infrastructure state’i ile Git/IaC state’ini düzenli olarak karşılaştırıp farkları tespit etmek demek.

\*\*\* Version Control Konfigürasyon dosyalarının (YAML, Helm values, Terraform, Ansible vb.) her değişikliğinin commit olarak kaydedildiği, geçmişe dönebileceğin, kim neyi ne zaman değiştirmiş görebildiğin sistem.

**2026 Hedefi (RKE2 IaC):** Level 4 (Repeatable)

- [ ] Ansible ile RKE2 cluster provisioning tamamen IaC (network, node, LB, install)
- [ ] GitOps aracı (ArgoCD/Fleet) kurulu ve production’da kullanılıyor
- [ ] Tüm cluster configuration Git’te, environment bazlı branch/klasör stratejisi tanımlı
- [ ] Haftalık configuration drift detection ve raporlama uygulanıyor


***

### Assessment Tablosu - Cluster Kurulumu (Birden Fazla Ortam)

Örnek: Prod, Staging, Dev ortamlarınız var



| Ortam | HA? | Backup Policy | Upgrade Last | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|
| **Prod** | 3 master | Daily offsite | 3 ay önce | L3 | L4 |
| **Staging** | 1 master | Weekly | 1 ay önce | L2 | L3 |
| **Dev** | 1 master | Ad-hoc | 6 ay önce | L1 | L2 |



***


***

## 2. Güvenlik Yönetimi ve Compliance

### Alt Başlıklar & Assessment Kriterleri

#### 2.1 RBAC (Role-Based Access Control)

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Service Account Policy** | Default SA kullanıyor | Per-app SA oluşturuluyor | Unique SA + proper RBAC | Automated SA provisioning | RBAC policy engine enforced |
| **User Access Model** | Root-like access | Basic user isolation | Formal RBAC rules | Regular RBAC audit tool | Continuous RBAC analysis + anomaly detection |
| **Privileged Access** | Direct cluster-admin | Documented admins | PAM system başlangıcı | PAM (Teleport/Boundary) fully deployed | Zero-trust PAM + audit trail |
| **Approval Process** | Hızlı approve | Informal approval | Formal approval workflow | Automated approval with policy | Multi-tier approval + AI review |
| **Audit & Review** | Manual, irregular | Quarterly RBAC check | Monthly audit | Automated weekly audit (Kubiscan/Krane) | Real-time RBAC drift detection |

\*\*\* Approval Process, yeni bir yetki/veri erişimi talebinin hangi adımlardan geçip onaylandığını tanımlar

\*\*\* Audit & Review, mevcut RBAC kurulumunun belirli periyotlarla taranıp kontrol edilmesini ifade eder.

**2026 Target:** Level 4 (Repeatable)

- [ ] Unique ServiceAccount her uygulama için, automated provisioning
- [ ] Formal RBAC approval process yazılı ve uygulanıyor
- [ ] Weekly automated RBAC audit tool (Kubiscan/Krane)
- [ ] Prod cluster'da PAM sistem operasyonel


***

#### 2.2 NetworkPolicy

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **NetworkPolicy Adoption** | Yok, flat network | Kısmi policies, test | Default-deny + whitelisting | All namespaces protected | Multi-cluster network policies |
| **CNI Support** | Flannel (NP desteksiz) | Calico (test) | Calico/Cilium prod | Cilium advanced features | Cilium + eBPF optimization |
| **Egress Control** | Açık (all allowed) | Kısmi engel | Pod'lar internetle kısıtlı | All external traffic restricted | Zero-egress by default |
| **Cross-Namespace Traffic** | Allowed | Kısmi kısıtlama | Kontrol altında | Strict policies | Hierarchical policies |
| **Policy Audit & Monitoring** | None | Manual review | Kyverno/OPA basic | Continuous policy check + alert | Policy violation prediction |

**2026 Target:** Level 4 (Repeatable)

- [ ] Calico veya Cilium CNI deployed
- [ ] Default-deny NetworkPolicy tüm prod namespaces
- [ ] Whitelisting policies, explicit allow rules
- [ ] Weekly NetworkPolicy audit, violation reporting


***

#### 2.3 cert-manager (Certificate Management)

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **TLS Certificate** | Manual, self-signed | Let's Encrypt manual | cert-manager + auto-renew | Multiple Issuer, policy | Certificate pinning + policy enforcement |
| **Ingress HTTPS** | No HTTPS veya self-signed | Basic HTTP/HTTPS | Full HTTPS, auto-renew | Wildcard + multi-domain | Zero-trust certificate strategy |
| **Certificate Rotation** | Manual, error-prone | Quarterly renewal | Auto-renew, no downtime | Proactive renewal + rotation | Predictive certificate lifecycle |
| **Webhook/API Certificates** | Manual | Ad-hoc generation | cert-manager managed | Automated, audit trail | Certificate pinning enforced |

**2026 Target:** Level 4 (Repeatable)

- [ ] cert-manager deployed, ClusterIssuer (Let's Encrypt prod) configured
- [ ] Tüm Ingress'ler automatic TLS, auto-renew
- [ ] Certificate renewal 30 gün öncesinden başlıyor
- [ ] Webhook certificates cert-manager tarafından yönetiliyor


***

#### 2.4 CIS Benchmark Compliance

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Initial Audit** | None | Manual checklist | kube-bench report | Quarterly kube-bench + SIEM | Continuous compliance monitoring |
| **API Server Config** | Default flags | Some security flags | CIS recommended flags | Full CIS compliance, audit log | Audit log + real-time analysis |
| **etcd Encryption** | No | Encrypted, manual key | Encryption at rest | Key rotation policy | Transparent encryption + key federation |
| **Kubelet Hardening** | Default kubelet | Basic restriction | CIS flags applied | Audited kubelet, no exec | Kubelet lock-down mode |
| **Pod Security Standards** | None | PSP (deprecated) | Pod Security Standards enforce | Restricted mode default | Custom security policies |
| **Remediation & Tracking** | Manual ad-hoc | Basic tracking | Remediation plan | Automated remediation | Self-healing security drift |

**2026 Target:** Level 4 (Repeatable)

- [ ] Monthly automated kube-bench scan
- [ ] API server CIS flags fully implemented
- [ ] etcd encryption at rest, key rotation policy
- [ ] Pod Security Standards "restricted" mode prod namespace'lerde
- [ ] CIS violations tracking, remediation SLA


***

#### 2.5 Additional Security (Image Scanning, Secrets Management)

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Container Image Scanning** | Manual scan, irregular | Trivy sporadic use | Registry scanning enabled | CI/CD pipeline scanning | Real-time vulnerability scanning + policy |
| **Secrets Management** | etcd'de plaintext | Basic encryption | External secrets (Vault) | Sealed Secrets + rotation | Zero-knowledge secrets management |
| **Image Pull Policy** | imagePullPolicy: Always | Always enforced (test) | Private registry, signed images | Image signature verification | Content-based image verification |

**2026 Target:** Level 4 (Repeatable)

- [ ] Trivy integration CI/CD pipeline, block on CRITICAL CVE
- [ ] HashiCorp Vault veya Sealed Secrets deployed
- [ ] Private registry, image signature verification
- [ ] Quarterly vulnerability re-scan


***

### Assessment Tablosu - Güvenlik (Birden Fazla Ortam)

| Ortam | RBAC Level | NetworkPolicy | cert-manager | CIS Audit | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|:---|
| **Prod** | L3 (formal RBAC) | Default-deny | Active | L3 (monthly) | L3 | L4 |
| **Staging** | L2 (basic) | Partial | Testing | L2 (manual) | L2 | L3 |
| **Dev** | L1 (default) | None | None | L1 (never) | L1 | L2 |



***


***

## 3. Monitoring ve Observability

### Alt Başlıklar & Assessment Kriterleri

#### 3.1 Prometheus & Grafana

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Prometheus Deploy** | None | Manual Prometheus | Helm chart deploy | Highly available (2+ replicas) | Multi-cluster Prometheus federation |
| **Metrics Collection** | None | Basic metrics | Full kube-state-metrics | Custom metrics + service-level metrics | AI-driven metric prediction |
| **Scrape Config** | None | Default | Documented scrape targets | Dynamic service discovery | Automated scrape discovery |
| **Grafana Dashboards** | None | Basic system dashboard | 5+ operational dashboards | 15+ dashboards + alerting | Self-generating dashboards + anomaly detection |
| **Data Retention** | N/A | 7 days | 30 days | 90+ days | Tiered storage (hot/warm/cold) |
| **Alert Rules** | None | Basic alerts | 10+ alert rules | 30+ rules, silencing policy | Predictive alerting |

**2026 Target:** Level 4 (Repeatable)

- [ ] Prometheus HA (2+ replicas), 90 day retention
- [ ] kube-state-metrics deployed
- [ ] 15+ operational Grafana dashboards
- [ ] 30+ alert rules, silencing policy


***

#### 3.2 Log Aggregation (EFK / PLG Stack)

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Log Collection Tool** | None | Manual log access | Fluentd/Logstash basic | Full EFK/PLG stack | Distributed tracing + logs |
| **Centralized Storage** | None | Local files | Elasticsearch (test) | HA Elasticsearch (3+ nodes) | Multi-tier Elasticsearch |
| **Log Query & Search** | None | Manual grep | Kibana search | Advanced queries + dashboards | AI-driven log analysis |
| **Log Retention Policy** | N/A | Undefined | 7 days | 30-90 days by severity | Tiered retention + archive |
| **Audit Log Centralization** | None | Local files | Partial centralization | Full audit log in ELK | Real-time audit analysis |

**2026 Target:** Level 4 (Repeatable)

- [ ] EFK stack (Elasticsearch, Fluentd, Kibana) fully deployed
- [ ] 30-90 day retention policy
- [ ] Audit logs centralized in EFK
- [ ] Weekly log analysis review


***

### Assessment Tablosu - Observability

| Ortam | Prometheus | Grafana Dashboard | EFK Stack | Log Retention | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|:---|
| **Prod** | HA (2+) | 12 dash | EFK deploy | 90 days | L4 | L4 ✓ |
| **Staging** | Single | 5 dash | Partial | 30 days | L3 | L3 ✓ |
| **Dev** | None | Ad-hoc | None | 7 days | L1 | L2 |



***


***

## 4. Resource Management & Optimization

### Alt Başlıklar & Assessment Kriterleri

#### 4.1 Resource Requests & Limits

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Request Definition** | None | Estimated values | Load testing based | Data-driven sizing | ML-predicted optimal |
| **Limit Configuration** | None | Loose limits | Appropriate limits | Tight limits, enforced | Dynamic limits |
| **Enforcement** | None | Recommendation | Policy agent (basic) | OPA/Kyverno enforced | Automatic policy violation prevention |
| **Over-provisioning** | 200%+ waste | 150% waste | 80% utilization | 70% utilization | 85-90% utilization |

**2026 Target:** Level 4 (Repeatable)

- [ ] Tüm prod pod'lar CPU/memory request + limit
- [ ] Policy agent (OPA/Kyverno) enforce etme
- [ ] Monthly capacity reporting, 80% utilization target


***

#### 4.2 HPA / VPA / Cluster Autoscaler

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **HPA (Horizontal Pod Autoscaler)** | Manual scaling | HPA basic (CPU only) | HPA multiple metrics | Advanced HPA + custom metrics | Predictive HPA |
| **VPA (Vertical Pod Autoscaler)** | None | VPA test mode | VPA recommendations | VPA auto-apply (off-peak) | Full VPA automation |
| **Cluster Autoscaler** | Manual node addition | Cluster Autoscaler (1 pool) | Multi-pool autoscaling | Advanced CA (spot instances) | Predictive node provisioning |
| **Scaling Policies** | Undefined | Basic policy | Documented policy | Formalized, tested policy | Self-optimizing policy |

**2026 Target:** Level 4 (Repeatable)

- [ ] HPA prod deployments'e aktif (CPU + memory metrics)
- [ ] Cluster Autoscaler yapılandırılmış, multi-pool
- [ ] VPA recommendation mode, monthly review
- [ ] Scaling policy documented, tested


***

#### 4.3 ResourceQuota & Namespace Isolation

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Namespace Strategy** | Single ns or random | Per-team ns | Prod/staging/dev separation | Hierarchical ns + multi-tenant | Advanced multi-tenancy isolation |
| **ResourceQuota** | None | Per-team quota (loose) | Tight quota per ns | Quota enforcement | Dynamic quota adjustment |
| **LimitRange** | None | Default limits | Per-ns limits | Enforced limits | Predictive limits |
| **Quota Violation Monitoring** | None | Manual check | Monthly report | Weekly monitoring + alert | Real-time quota dashboard |

**2026 Target:** Level 4 (Repeatable)

- [ ] Hierarchical namespace strategy (prod/staging/dev)
- [ ] ResourceQuota tüm prod namespaces
- [ ] LimitRange enforcement
- [ ] Weekly quota monitoring, 80% threshold alert


***

### Assessment Tablosu - Resource Management

| Ortam | Requests/Limits | HPA Active | CA Config | Quota | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|:---|
| **Prod** | 80% | Yes (CPU) | Multi-pool | Yes | L3 | L4 |
| **Staging** | 40% | Partial | Single-pool | No | L2 | L3 |
| **Dev** | None | No | Manual | No | L1 | L2 |



***


***

## 5. Storage Management

### Alt Başlıklar & Assessment Kriterleri

#### 5.1 PV / PVC & StorageClass

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **StorageClass** | Manual PV | Basic StorageClass | Multiple SC (SSD/HDD) | Advanced SC (topology aware) | Multi-cloud SC |
| **Dynamic Provisioning** | Manual provision | Partial automation | Full dynamic provisioning | Provisioning policy | Intelligent provisioning |
| **PVC Management** | None | Ad-hoc | Documented standard | Automated enforcement | Self-service PVC template |
| **Access Modes** | Undefined | RWO only | RWO + RWM mix | Proper access mode strategy | Optimized access patterns |

**2026 Target:** Level 4 (Repeatable)

- [ ] Multiple StorageClass (fast/standard/archive)
- [ ] Dynamic provisioning fully operational
- [ ] Backup policy per PVC


***

#### 5.2 Storage Performance & Backup

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Performance Tier** | Single storage class | Basic differentiation | SSD + HDD | Multi-tier with policy | AI-driven tier selection |
| **Backup Strategy** | Manual backups | Weekly backup | Daily snapshot | Continuous replication | Zero-RPO replication |
| **Disaster Recovery** | None | Manual restore (untested) | Tested restore procedure | Automated DR failover | Multi-region DR |
| **Data Retention** | Undefined | 7 days | 30 days | 90 days | Tiered retention |

**2026 Target:** Level 4 (Repeatable)

- [ ] Storage performance tiering (hot/warm/cold)
- [ ] Daily automated snapshot, 90 day retention
- [ ] Tested restore procedure quarterly
- [ ] Data encryption at rest


***

### Assessment Tablosu - Storage

| Ortam | StorageClass | Backup | Retention | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|
| **Prod** | Multi-tier | Daily | 90 days | L3 | L4 |
| **Staging** | Basic | Weekly | 30 days | L2 | L3 |
| **Dev** | Single | Manual | 7 days | L1 | L2 |



***


***

## 6. Networking & Service Management

### Alt Başlıklar & Assessment Kriterleri

### 6.1 Ingress Controller & TLS (HAProxy + nginx + K8s Ingress)


**Mimari varsayım:**WAN → HAProxy (L4/L7) → nginx (edge, SSL termination) → Kubernetes Ingress Controller (cluster içi, HTTP/HTTPS)

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 (Hedef) | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Ingress Katmanları** | Tek katman, doğrudan NodePort/Ingress | HAProxy **veya** nginx tek başına edge | HAProxy + nginx edge, K8s Ingress basic | HAProxy + nginx edge (prod), K8s Ingress Controller prod‑ready, çoklu ingress class (internal/external) | Global traffic manager + çok bölgeli edge, geo‑routing |
| **Ingress Controller (K8s içi)** | Yok | Tek nginx Ingress, basic config | nginx Ingress prod‑like ama tek entrypoint | nginx Ingress (ve gerekirse ek internal controller) prod‑ready, HPA, PodDisruptionBudget, config as code | Gelişmiş Envoy/Cilium/Ingress mesh, dynamic routing |
| **TLS Terminasyonu** | Hiç TLS yok | Self‑signed TLS, manuel sertifika | TLS termination sadece nginx’te, manuel veya kısmi otomasyon | TLS termination nginx’te, cert-manager ile otomatik yenileme; gerekirse Ingress level TLS (mTLS/internal) için ek cert-manager entegrasyonu | Uçtan uca zero‑trust TLS, hem edge hem mesh tarafında otomatik mTLS |
| **cert-manager Kullanımı** | Yok | Sadece test domain için, kısmen manuel | Public domain’ler için cert-manager, bazı servisler hariç | Tüm public hostname’ler için cert-manager + ACME (Let’s Encrypt vb.), wildcard/subject‑alt‑name kullanım standart; internal CA için ayrı Issuer/ClusterIssuer | Birden fazla CA (public + enterprise), policy‑driven issuer seçimi, otomatik rotation & revocation |
| **Load Balancer (Edge)** | LB yok, direkt node IP | Tek HAProxy, manuel config | HAProxy HA ama health check/auto failover sınırlı | HAProxy HA (en az 2 node), health check + failover senaryosu dokümante, arkasında autoscaled nginx/Ingress | Multi‑region LB + anycast/DNS‑based global traffic management |
| **Routing Policy (Edge + Ingress)** | Sadece static IP ve host | Host bazlı temel routing | Host + path bazlı routing, bazı sticky session/headers | Host + path bazlı advanced routing (blue/green, canary), header‑based routing; WAN tarafında HAProxy’de SNI/host‑based dağıtım; Ingress tarafında path/host ayrımı standardize | Dinamik routing, latency‑aware, user segment‑aware intelligent routing |

**2026 Target (senin mimarine göre):** Level 4

- [ ] HAProxy önünde en az 2 instance (HA), health check ve failover senaryosu tanımlı ve test edilmiş.
- [ ] nginx edge config’i (virtual host, TLS ayarları) tamamen Git’te, Terraform/Ansible/Helm ile yönetiliyor; manuel config yok.
- [ ] Kubernetes tarafında nginx Ingress Controller prod‑ready:
  * HPA ile scale, PodDisruptionBudget ile upgrade sırasında kesinti önleme.
  * IngressClass kullanımı (örn. `external-nginx`, gerekirse `internal-nginx`).
- [ ] cert-manager ile edge için gerekli tüm public domain sertifikaları otomatik alınıyor ve yenileniyor (ACME, örn. Let’s Encrypt); wildcard veya SAN stratejisi net.
- [ ] Internal servisler için (cluster‑içi mTLS ya da internal domains) ayrı bir Issuer/ClusterIssuer (örneğin internal CA veya Vault) tanımlı.
- [ ] HAProxy + nginx + Ingress routing kuralları dokümante:
  * WAN → HAProxy: SNI/hostname bazlı backend seçimi.
  * HAProxy → nginx: HTTP/HTTPS, health check.
  * nginx → K8s Ingress Controller: host/path bazlı mapping standardı (örn. `*.corp.domain` → internal, `*.public.domain` → external).



***

### 6.2 Service Mesh (Optional Advanced, HAProxy + nginx ile birlikte)

Service mesh kullanmak zorunlu olmadığı için “edge pattern”ini bozmadan şöyle çerçevelenebilir:

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 (Hedef, opsiyonel) | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Service Mesh Deploy** | Yok | Istio/Linkerd POC, edge entegrasyonu yok | Istio/Linkerd POC + Ingress Gateway testleri | Production Istio/Linkerd; HAProxy/nginx sadece dış edge, mesh iç trafik yönetiyor | Cilium/Envoy tabanlı full mesh, mesh‑aware global routing |
| **mTLS Enforcement (Mesh içi)** | Yok | POC ortamında namespace bazlı mTLS | Bazı prod namespace’lerinde mTLS | Prod’ta kritik namespace’ler için zorunlu mTLS; edge (nginx) ile mesh ingress gateway entegrasyonu dokümante | Mesh içinde zero‑trust mTLS, istisnasız enforcement |
| **Traffic Management** | Yok | Basit canary/traffic shifting POC | Canary deployment bazı servislerde | Canlıda rollout’lar mesh ile yönetiliyor (canary, blue/green, header/beta flag based routing), edge config ile uyumlu | Mesh + global traffic manager ile intelligent, latency‑aware steering |
| **Observability** | Yok | Mesh metrics (Grafana) temel | Kiali dashboard + mesh metrics | Kiali + distributed tracing (Jaeger/Tempo) + edge (HAProxy/nginx logları) ile full request path görünürlüğü | Mesh telemetry + AI‑driven anomaly detection |

**2026 için öneri (opsiyonel):**

- [ ] Mevcut HAProxy + nginx edge’ini bozmadan, bir sandbox/staging cluster’da Istio veya Linkerd POC’i çalıştır.
- [ ] Eğer mesh’e geçeceksen:
  * Edge’de SSL termination nginx’te kalabilir; mesh ingress gateway’e forward edersin.
  * İç trafikte mTLS, canary rollout ve observability kazanırsın; edge yapınla entegrasyon pattern’ini (HAProxy/nginx → mesh ingress gateway → servis) dokümante et.


***

### Assessment Tablosu - Networking

| Ortam | Ingress | HTTPS | Service Mesh | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|
| **Prod** | nginx | cert-manager | None | L3 | L4 |
| **Staging** | nginx | cert-manager | Evaluation | L2 | L3 |
| **Dev** | Manual | Self-signed | None | L1 | L2 |



***


***

## 7. CI/CD & GitOps

### Alt Başlıklar & Assessment Kriterleri

#### 7.1 GitOps & ArgoCD

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **GitOps Tool** | None | Manual kubectl | ArgoCD basic | ArgoCD full + sealed-secrets | ArgoCD + AI automation |
| **Deployment Method** | Manual kubectl | Shell scripts | Helm + manual apply | Full GitOps + auto-sync | Pull-based GitOps + policy |
| **Git Repo Structure** | Undefined | Ad-hoc | Organized structure | Monorepo / multi-repo strategy | Mono + policy as code |
| **Rollback Capability** | Manual git revert | Documented steps | Automated rollback | One-click rollback | Predictive rollback |
| **Audit Trail** | None | Partial | Full Git audit | Real-time audit dashboard | Immutable audit log |

**2026 Target:** Level 4 (Repeatable)

- [ ] ArgoCD production deployment
- [ ] Git'te tüm configuration (declarative)
- [ ] Auto-sync enabled, manual sync option
- [ ] Sealed Secrets entegrasyon


***

#### 7.2 Helm Chart Management

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Helm Usage** | None | Ad-hoc Helm charts | Helm standard | Helm Hub + private repo | Helm + policy gates |
| **Values Management** | Hardcoded | Separate values | Environment-specific values | Sealed values | Dynamic values generation |
| **Chart Testing** | None | Manual test | helm lint | Helm chart testing in CI | Automated helm validation |
| **Release Management** | Manual | Documented steps | Helm release automation | Automated helm upgrades | Predictive helm releases |

**2026 Target:** Level 4 (Repeatable)

- [ ] Helm 3 standard, private Helm repository
- [ ] Values separation per environment
- [ ] helm lint + testing in CI pipeline
- [ ] Automated Helm upgrades via GitOps


***

### Assessment Tablosu - CI/CD

| Ortam | GitOps | ArgoCD | Helm | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|
| **Prod** | Full | Active | 3 charts | L3 | L4 |
| **Staging** | Partial | Testing | 2 charts | L2 | L3 |
| **Dev** | None | None | 0 charts | L1 | L2 |



***


***

## 8. Backup & Disaster Recovery

### Alt Başlıklar & Assessment Kriterleri

#### 8.1 etcd Backup & State

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Backup Frequency** | None | Manual, irregular | Daily | Hourly automated | Continuous replication |
| **Backup Location** | Local | Same node | Different AZ | Off-site (cloud) | Multi-region |
| **Restore Testing** | None | Never tested | Annual test | Quarterly test | Monthly test |
| **Backup Encryption** | None | Unencrypted | Encrypted transit | Encrypted at rest | Key management federation |
| **RTO Target** | Undefined | 24 hours | 4 hours | 1 hour | 15 minutes |
| **RPO Target** | Undefined | 24 hours | 4 hours | 30 minutes | 5 minutes |

\*\*\* RTO (Recovery Time Objective): Bir kesinti veya felaket olduktan sonra, sistemlerin kabul edilebilir seviyede tekrar çalışır hale gelmesi için izin verilen maksimum süre.

\*\*\* (Recovery Point Objective): Bir kesintide kaybetmeyi göze alabileceğin maksimum veri miktarı, zaman cinsinden.

**2026 Target:** Level 4 (Repeatable)

- [ ] etcdctl hourly snapshot, automated
- [ ] Off-site backup (cloud storage)
- [ ] Quarterly restore test, documented
- [ ] RTO 1 hour / RPO 30 min target
- [ ] Encrypted backup at rest + transit


***

#### 8.2 Application Backup (Velero)

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Backup Tool** | None | Manual export | Velero basic | Velero + policy | Velero + hooks |
| **Backup Scope** | N/A | Manual selection | Per-namespace | Selective + full backup | Policy-based backup |
| **Backup Schedule** | None | Manual | Daily | Hourly | Continuous |
| **Restore Procedure** | N/A | Untested | Documented | Tested quarterly | Tested monthly |
| **Incremental Backup** | None | Manual | Basic | Advanced diff-based | Continuous incremental |

**2026 Target:** Level 4 (Repeatable)

- [ ] Velero deployed, configured
- [ ] Daily namespace backup
- [ ] Quarterly full restore test
- [ ] Hook'lar (pre/post backup)


***

#### 8.3 Disaster Recovery Planning

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **DR Plan** | None | Informal | Documented | Tested (annual) | Tested (quarterly) |
| **DR Site** | None | Manual setup | Semi-automated | Fully automated failover | Multi-region active-active |
| **Data Replication** | None | Manual | Asynchronous | Near-synchronous | Synchronous |
| **Failover Time** | N/A | Hours | 30 minutes | 5 minutes | Automatic |
| **Communication Plan** | None | Undefined | Documented | Integrated with ITSM | Automated alerting |

\*\*\* Disaster Recovery Planning’i sadece tek bir cluster için değil, risk/kritiklik seviyesine göre her cluster için ayrı ayrı tanımlaman gerekir.

\*\*\* Disaster Recovery hedefleri her cluster (hatta kritikse her uygulama) için ayrı ayrı tanımlanmalıdır.

**2026 Target:** Level 4 (Repeatable)

- [ ] DR plan yazılı, versiyonlu
- [ ] Semi-automated DR site
- [ ] Failover test quarterly
- [ ] RTO 1 hour / RPO 30 min defined


***

### Assessment Tablosu - Backup & DR

| Ortam | etcd Backup | Velero | DR Test | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|
| **Prod** | Hourly | Daily | Quarterly | L4 | L4 ✓ |
| **Staging** | Daily | Manual | Annual | L2 | L3 |
| **Dev** | Weekly | None | Never | L1 | L2 |



***


***

## 9. Troubleshooting & Debugging

### Alt Başlıklar & Assessment Kriterleri

#### 9.1 kubectl Debugging Tools

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **kubectl Commands** | Limited knowledge | Basic commands | Advanced kubectl | All kubectl debugging commands | kubectl plugin ecosystem |
| **Pod Debugging** | Manual pod access | Limited exec usage | Full exec + port-forward | Ephemeral containers | Interactive debugging |
| **Event Analysis** | None | Manual check | kubectl describe usage | Event aggregation + filtering | Predictive event analysis |
| **Logs Analysis** | Manual logs | grep usage | Log streaming | Advanced queries | AI-driven log analysis |

**2026 Target:** Level 4 (Repeatable)

- [ ] Team trained on advanced kubectl
- [ ] Ephemeral container debugging enabled
- [ ] Troubleshooting runbook documented


***

#### 9.2 Monitoring & Alerting Integration

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Alert System** | None | Basic email alerts | Slack/PagerDuty alerts | Escalation policy | AI-driven alert correlation |
| **Alert Fatigue** | High (many false positives) | Moderate | Well-tuned | Minimal | Predictive alert suppression |
| **On-Call Runbook** | None | Manual docs | Automated runbook | Integration with tools | AI-assisted runbook |
| **MTTR (Mean Time To Resolve)** | Undefined | Hours | 30 minutes | 10 minutes | <5 minutes (AI-assisted) |

**2026 Target:** Level 4 (Repeatable)

- [ ] PagerDuty or Opsgenie integration
- [ ] Alert tuning, <10% false positive rate
- [ ] Runbook automation
- [ ] MTTR < 15 minutes target


***

### Assessment Tablosu - Troubleshooting

| Ortam | kubectl Level | Debugging Tools | Alert System | Runbook | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|:---|
| **Prod** | Advanced | Partial | PagerDuty | Basic docs | L3 | L4 |
| **Staging** | Basic | Manual | Email | Informal | L2 | L3 |
| **Dev** | Limited | None | None | None | L1 | L2 |



***


***

## 10. Cost Optimization & FinOps

### Alt Başlıklar & Assessment Kriterleri

#### 10.1 Resource Rightsizing

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Utilization Analysis** | Never analyzed | Annual review | Quarterly analysis | Monthly trend analysis | Continuous ML analysis |
| **Over-provisioning** | 200%+ waste | 150% waste | 100% (balanced) | 80% efficient | 90%+ efficient |
| **Automated Rightsizing** | Manual tuning | VPA recommendations | VPA auto-apply (off-peak) | Full automation | Predictive rightsizing |
| **Cost Reporting** | No visibility | Annual report | Monthly report | Weekly report | Real-time dashboard |

**2026 Target:** Level 4 (Repeatable)

- [ ] Monthly utilization analysis
- [ ] VPA recommendation review + auto-apply
- [ ] Weekly cost reporting
- [ ] 80%+ utilization target


***

#### 10.2 Spot/Reserved Instances & Instance Types

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Instance Strategy** | On-demand only | Mix on-demand + reserved | Reserved + spot (non-critical) | Advanced spot (80%+) | Dynamic instance selection |
| **Spot Usage** | None | Experimental | Non-prod workloads | Prod batch workloads | All interruptible workloads |
| **Node Pool Strategy** | Single pool | 2 pools (manual) | 3+ pools auto-scaled | Cost-optimized pools | ML-driven pool selection |
| **Cost Savings** | 0% | 10-20% | 30-40% | 50%+ | 60%+ |

**2026 Target:** Level 4 (Repeatable)

- [ ] Spot instances 50%+ of workloads
- [ ] 3+ node pools (on-demand/reserved/spot)
- [ ] Karpenter or Kubecost for optimization
- [ ] Cost savings 40%+ vs all on-demand


***

#### 10.3 Cost Allocation & FinOps

| Kriter | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|:---|:---|:---|:---|:---|:---|
| **Cost Allocation** | None | Manual tracking | Namespace-level cost | Department/project allocation | Real-time allocation + showback |
| **Budget Control** | None | Informal limit | Defined budget | Automated budget alerts | Auto-enforcement + chargeback |
| **FinOps Culture** | No awareness | Emerging awareness | Cost-conscious team | Full FinOps practice | Continuous optimization culture |
| **Savings Tracking** | None | Manual | Quarterly report | Monthly dashboard | Predictive savings |

**2026 Target:** Level 4 (Repeatable)

- [ ] Kubecost deployed, real-time allocation
- [ ] Namespace-level cost tracking
- [ ] Monthly cost review with teams
- [ ] Budget alert at 80% threshold


***

### Assessment Tablosu - Cost Optimization

| Ortam | Utilization | Spot Usage | Cost Allocation | Level | 2026 Target |
|:---|:---|:---|:---|:---|:---|
| **Prod** | 75% | 30% | Basic | L2 | L4 |
| **Staging** | 60% | 50% | None | L2 | L3 |
| **Dev** | 40% | 0% | None | L1 | L2 |



***


***

## COMPOSITE ASSESSMENT MATRIX (Tüm Ortamlar)

### Özet Tablo

| Başlık | Prod Level | Staging Level | Dev Level | Prod Target | Staging Target | Dev Target |
|:---|:---|:---|:---|:---|:---|:---|
| **1. Cluster & Lifecycle** | L3 | L2 | L1 | **L4** | **L3** | **L2** |
| **2. Security & Compliance** | L3 | L2 | L1 | **L4** | **L3** | **L2** |
| **3. Monitoring** | L4 | L3 | L1 | **L4** ✓ | **L3** ✓ | **L2** |
| **4. Resource Mgmt** | L3 | L2 | L1 | **L4** | **L3** | **L2** |
| **5. Storage** | L3 | L2 | L1 | **L4** | **L3** | **L2** |
| **6. Networking** | L3 | L2 | L1 | **L4** | **L3** | **L2** |
| **7. CI/CD & GitOps** | L3 | L2 | L1 | **L4** | **L3** | **L2** |
| **8. Backup & DR** | L4 | L2 | L1 | **L4** ✓ | **L3** | **L2** |
| **9. Troubleshooting** | L3 | L2 | L1 | **L4** | **L3** | **L2** |
| **10. Cost Optimization** | L2 | L2 | L1 | **L4** | **L3** | **L2** |
| **Average Level** | **L3** | **L2** | **L1** | **L4** | **L3** | **L2** |



***

## 2026 Action Plan Template

Örnek: **PROD Cluster Roadmap**



| Q | Initiative | Owner | Target Level | Dependency | Status |
|:---|:---|:---|:---|:---|:---|
| **Q1 2026** | Helm 3 + ArgoCD setup | DevOps | L4 | Git repo cleanup | \[ \] |
| **Q1 2026** | Multi-cluster Prometheus federation | Platform | L4 | Infra planning | \[ \] |
| **Q2 2026** | cert-manager webhook certs | Security | L4 | cert-manager upgrade | \[ \] |
| **Q2 2026** | Kubecost deployment + showback | FinOps | L4 | Metrics API | \[ \] |
| **Q3 2026** | Disaster recovery drill | DevOps | L4 | DR plan finalize | \[ \] |
| **Q3 2026** | Pod Security Standards enforcement | Security | L4 | Policy agent setup | \[ \] |
| **Q4 2026** | Multi-cluster management (if needed) | Platform | L4 | Central control plane | \[ \] |



***

## Quarterly Review Checklist

Her Quarter'da bu kontrolleri yapın:

- [ ] Her cluster için current level assessment
- [ ] Tamamlanan initiatives tracking
- [ ] Blocker'ları belirleme ve escalation
- [ ] Next quarter'ın prioritization'ı
- [ ] Team skill gaps analysis
- [ ] Tool upgrade planning


***

## Conclusion

Bu döküman sayesinde:

✅ **Mevcut durumu** (current state) net şekilde görebilirsiniz ✅ **Hedefler** (2026 target = Level 4) açıkça tanımlanmıştır ✅ **Adımlar** (quarterly initiatives) yapılandırılmıştır ✅ **Bazı başlıklar zaten target'ta** (Monitoring L4, Backup L4 Prod'da)


