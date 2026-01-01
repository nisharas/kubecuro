# 🩺 Kubecuro Current Capabilities & Strategic 2026 Roadmap

Kubecuro is not just a linter; it is a **Cross-Manifest Logic Engine**. It bridges the gap between syntactically correct YAML and a functionally working Kubernetes cluster.

---

## 🚀 Current Intelligence (Available Now)

### 🩹 1. The Healer Engine (Structural)

* **Problem:** Malformed YAML prevents `kubectl` from even reading the file.
* **Solution:** Automatically repairs structural issues.
* **Auto-Indentation:** Fixes nested structures to match Kubernetes standards.
* **Syntax Remediation:** Corrects missing colons and malformed key-pair structures.
* **File Standardization:** Re-writes all manifests to a clean, 2-space indentation format.

### 🧠 2. The Synapse Engine (Connectivity)

* **Problem:** Manifests deploy successfully but fail at runtime due to mismatched selectors or ports.
* **Solution:** Performs a "Deep Tissue Scan" across the entire directory to verify relationships.
* **Ghost Service Detection:** Identifies Services targeting labels that do not exist on any Pod.
* **Port-Mapping Audit:** Detects mismatches between Service `targetPort` and Pod `containerPort`.
* **Namespace Validation:** Flags cross-namespace communication attempts that will be blocked by K8s isolation.

### 🛡️ 3. The Shield Engine (Governance)

* **Problem:** API deprecations lead to failed cluster upgrades and deployment rejections.
* **Solution:** Validates API versions against modern cluster requirements.
* **Deprecation Scanner:** Identifies retired APIs (e.g., `extensions/v1beta1`).
* **Migration Advisor:** Suggests the exact modern API version to use.

---

## 🛠 Strategic Roadmap (Upcoming Features)

### 🔒 Phase 1: Security Hardening (Q1 2026)

* **Privileged Guard:** Flag containers running with `privileged: true`.
* **Rootless Audit:** Identify Pods missing the `runAsNonRoot` security context.
* **HostPath Tracker:** Detect dangerous host-level mounts.

### 📦 Phase 2: Dependency Validation (Q2 2026)

* **Orphaned Secret Check:** Ensure `envFrom` and `SecretMounts` have a corresponding Secret file in the directory.
* **ConfigMap Parity:** Verify that keys requested by a Pod actually exist in the ConfigMap.
* **Resource Limit Audit:** Identify containers missing CPU/Memory limits to prevent OOMKills.

### 🌐 Phase 3: Advanced Networking (Q3 2026)

* **NetworkPolicy Logic:** Verify if traffic is actually allowed to reach the defined Service ports.
* **HPA-Deployment Sync:** Ensure Autoscalers are correctly targeting existing Deployments.
* **Topology Export:** Generate a visual dependency graph of all manifests.

---

## 📊 Feature Comparison

| Feature | Standard Linters (IDE) | Kubecuro |
| --- | --- | --- |
| Single-file Syntax Check | ✅ | ✅ |
| **Cross-file Selector Mapping** | ❌ | ✅ |
| **Port-to-Port Logic Validation** | ❌ | ✅ |
| **Automatic YAML Healing** | ❌ | ✅ |
| **Severity-based Prioritization** | ❌ | ✅ |
| **Zero-Network/Air-Gapped Ops** | ⚠️ | ✅ |

---

## 💬 Contributing to Logic

If you have encountered a production issue caused by a "Logic Gap" that Kubecuro didn't catch, please [Open an Issue](https://github.com/nisharas/kubecuro/issues) with the tag `[Logic Gap]`.

---
