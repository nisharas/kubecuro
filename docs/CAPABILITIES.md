# 🩺 Kubecuro Current Capabilities & Strategic 2026 Roadmap

Kubecuro is not just a linter; it is a **Cross-Manifest Logic Engine**. It bridges the gap between syntactically correct YAML and a functionally working Kubernetes cluster.

---

## 🚀 Current Intelligence (v1.0.0)

### 🩹 1. The Healer Engine (Structural)

* **Problem:** Malformed YAML or deprecated APIs prevent kubectl from applying changes.
* **Solution:** Active remediation of structural and versioning issues.
* **Auto-Healing:** Corrects indentation, missing colons, and malformed key-pairs.
* **API Shield:** Automatically migrates retired APIs (e.g., `networking.k8s.io/v1beta1` → `v1`).

Dry-Run Mode: Preview exactly what the Healer will change before writing to disk.

### 🧠 2. The Synapse Engine (Connectivity)

* **Problem:** "Silent Killers"—manifests deploy without errors but fail to route traffic.
* **Solution:** A "Deep Tissue Scan" across the entire manifest suite.
* **Ghost Detection:** Identifies Services targeting labels that match zero Pods.
* **Port Alignment:** Detects mismatches between Service `targetPort` and Pod `containerPort`.
* **HPA Logic:** Warns if an HPA targets a deployment where containers lack `resources.requests`.

### 🛡️ 3. The Shield Engine (Governance)

* **Smart Autocomplete:** Native Bash/Zsh completion for commands and resource types.
* **Explain Engine:** Built-in documentation for every logic check. Use `kubecuro explain <resource>` to see the "Why" behind the "How."

---

## 🛠 Strategic Roadmap (Upcoming Features)

### 🔒 Phase 1: Security Hardening (Q1 2026)

* **Hardening Audit:** Flag `privileged: true`, missing `runAsNonRoot`, and dangerous `hostPath` mounts.
* **RBAC Integrity:** Verify that `RoleBindings` refer to existing `Roles` and valid `ServiceAccounts`.
* **Secret Safety:** Detect hardcoded secrets and verify `envFrom` references exist.

### 📦 Phase 2: Dependency Validation (Q2 2026)

* **ConfigMap/Secret Sync:** Ensure every `valueFrom` key actually exists in the referenced ConfigMap/Secret.
* **OOMKill Prevention:** Audit containers missing CPU/Memory limits.
* **Storage Logic:** Validate PVC-to-PV binding requirements and StorageClass alignment.
* 
### 🌐 Phase 3: Advanced Networking (Q3 2026)

* **NetworkPolicy Logic:** Verify if traffic is actually allowed to reach the defined Service ports.
* **Visual Topology:** Generate a `mermaid.js` or `SVG` dependency graph of your manifests.
* **JSON/JUnit Output:** Enable CI/CD integration for automated "Logic Gates."

---

## 📊 Feature Comparison

| Feature | Standard Linters (IDE) | Kubecuro |
| --- | --- | --- |
| **Single-file Syntax Check** | ✅ | ✅ |
| **Cross-file Selector Mapping** | ❌ | ✅ |
| **Port-to-Port Logic Validation** | ❌ | ✅ |
| **Automatic YAML Healing** | ❌ | ✅ |
| **Interactive "Explain" Engine** | ❌ | ✅ |
| **Zero-Network/Air-Gapped Ops** | ⚠️ | ✅ |

---

## 💬 Contributing to Logic

If you have encountered a production issue caused by a "Logic Gap" that Kubecuro didn't catch, please [Open an Issue](https://github.com/nisharas/kubecuro/issues) with the tag `[Logic Gap]`.

---
*Built with ❤️ by Nishar A Sunkesala and the Kubecuro Community | Powered by FixMyK8s*
