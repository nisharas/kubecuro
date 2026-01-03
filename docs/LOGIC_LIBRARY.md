# 📚 KubeCuro Logic Library (v1.0.0)

This library catalogs the specific logical validations performed by the **Synapse** and **Shield** engines. 

## 🧠 Synapse: Connectivity Logic Checks

| ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **SYN-001** | **Ghost Service** | 🔴 HIGH | Service `spec.selector` matches zero Pods in the current manifest suite. |
| **SYN-002** | **Port Mismatch** | 🔴 HIGH | Service `targetPort` does not exist as a `containerPort` in the targeted Pods. |
| **SYN-003** | **Namespace Isolation** | 🟠 MED | Service and Pod have matching labels but reside in different namespaces. |
| **SYN-004** | **HPA Orphan** | 🔴 HIGH | HorizontalPodAutoscaler targets a `scaleTargetRef` that cannot be found. |
| **SYN-005** | **HPA Resource Gap** | 🟠 MED | HPA targets a Deployment that lacks `resources.requests`. |
| **SYN-006** | **Ingress Backend Gap** | 🔴 HIGH | Ingress refers to a `serviceName` that does not exist in the scanned directory. |

## 🛡️ Shield: Governance & API Checks

| ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **SHLD-101** | **API Deprecation** | 🟠 MED | Resource uses a deprecated API version (e.g., `v1beta1`) that will fail soon. |
| **SHLD-102** | **API Retirement** | 🔴 HIGH | Resource uses an API version that has been fully removed from the target K8s release. |

## 🏗️ Upcoming Logic (Roadmap v1.1.0+)

These checks are currently in development and represent the first "Security Tier" of the KubeCuro roadmap.

| ID | Category | Target | Logic Goal |
| :--- | :--- | :--- | :--- |
| **SEC-201** | Security | Pods | Flag containers missing `securityContext.runAsNonRoot: true`. |
| **SEC-202** | Security | RBAC | Flag `ClusterRole` with `*` (wildcard) permissions on critical resources. |
| **DEP-301** | Dependency | ConfigMap | Verify `envFrom.configMapRef` points to a ConfigMap defined in the bundle. |
| **DEP-302** | Dependency | Secrets | Detect Pods mounting Secrets that are missing from the scanned manifests. |
