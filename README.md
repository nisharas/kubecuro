---

```markdown
# 💓 KubePulse

[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=flat&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**KubePulse** is a high-performance, production-grade CLI tool designed to eliminate the "silent killers" of Kubernetes deployments. While standard linters merely validate YAML syntax, KubePulse performs a deep-tissue scan to ensure your infrastructure is **Syntactically Healthy**, **Logically Connected**, and **API Future-Proof**.

---

## 📄 Project Metadata

* **Author:** Nishar A Sunkesala / [FixMyK8s](https://github.com/FixMyK8s)
* **Version:** 1.0.0
* **Created:** December 2025
* **Last Modified:** December 31, 2025
* **Status:** Stable / Production Ready

---

## 🎯 The Gap & The Solution

**The Gap:** Current CI/CD pipelines use "Validators" that only check if a YAML file is technically valid. They fail to detect if a Service will actually reach its Pod (due to label/namespace mismatches) or if an API version is deprecated until the deployment hits the cluster and fails.

**The Solution:** KubePulse closes this feedback loop. It analyzes the **relationships** between files, detecting logical orphans and connection gaps *before* they reach your control plane.



---

## 🚀 The Triple-Engine Defense

1. **🩹 The Healer (Syntax Engine):** Uses a **Split-Stream** architecture to safely process multi-document YAMLs. It auto-remediates missing colons, fixes indentation, and quotes complex image tags without corrupting your file structure.
2. **🧠 The Synapse (Logic Engine):** A deep-link analyzer that validates **Selectors vs. Labels**, **Namespace isolation**, and **Port mapping** (including named ports) across your entire directory.
3. **🛡️ The Shield (API Shield Engine):** A context-aware deprecation guard. It doesn't just flag old APIs; it identifies the resource type (Ingress, Deployment, etc.) and suggests the specific modern API path.


---

## 🛡️ Security & Privacy Audit

KubePulse is designed with a "Security-First" architecture. It operates as a localized static analysis tool with a zero-trust approach to network and cluster access.

* **Zero Data Leakage:** KubePulse runs entirely on your local machine. It does not contain `requests`, `urllib`, or any networking sockets. Your manifest data never leaves your environment.
* **Air-Gapped by Design:** The tool does not communicate with the Kubernetes API Server (Control Plane) and does not require `kubeconfig` access. It is as safe to run as a standard text editor.
* **No Privilege Escalation:** KubePulse operates with the same permissions as the user executing it. It cannot modify system-level settings or "hack" worker nodes.
* **Safe Parsing:** By utilizing `ruamel.yaml` (an industry-standard, safe YAML parser) and avoiding risky functions like `eval()`, KubePulse is protected against malicious code injection within YAML manifests.

---

## 💻 Usage

KubePulse is designed for simplicity. Point it at a file or a directory, and let it perform the heartbeat check.

### Scan a Single File
```bash
kubepulse pod.yaml

Scan an Entire Directory (Folder Scan)
Cross-references all manifests within the folder to find logical gaps.
```bash
kubepulse ./k8s-manifests/

Get Help
```bash
kubepulse --help



---

## 🛠️ Installation

### Option A: Standalone Binary (Recommended)
Zero dependencies. Best for CI/CD runners or quick local use.
```bash
# Download the binary from the releases page
chmod +x kubepulse
sudo mv kubepulse /usr/local/bin/


### Option B: From Source (Developers)

```bash
git clone [https://github.com/FixMyK8s/kubepulse.git](https://github.com/FixMyK8s/kubepulse.git)
cd kubepulse
pip install -e .

```

---

## 📊 Performance & Resource Footprint

KubePulse is engineered to be lightweight, ensuring it adds zero friction to your development workflow.

| Metric | Standing | Notes |
| --- | --- | --- |
| **Binary Size** | ~12MB | Self-contained with all logic engines. |
| **RAM Usage** | < 25MB | Optimized for large-scale manifest folders. |
| **Execution Time** | < 1s | Instant feedback for local Git hooks. |

---

## ⚖️ Advantages & Considerations

### ✅ Advantages

* **Isolation Mapping:** Detects if a Service and Pod match labels but exist in different namespaces.
* **Named Port Support:** Recognizes connections between `targetPort: http` and `name: http`.
* **Zero-Config Healing:** Automatically fixes common "copy-paste" YAML errors.

### ⚠️ Considerations

* **Static Analysis:** Analyzes local files only; does not query the live cluster state for external dependencies.
* **Declarative Focus:** Best used during the "Pre-Commit" or "CI-Lint" phase of a GitOps workflow.

---

## 🩺 Diagnostic Intelligence

| Signal | Category | Resolution Strategy |
| --- | --- | --- |
| **🩺 DIAGNOSTIC** | Structure | Auto-heals syntax and indentation. |
| **🌐 NAMESPACE** | Connectivity | Ensure the `namespace` field is identical for Service & Pod. |
| **👻 GHOST** | Orphanage | Match Service `selectors` to Deployment `template` labels. |
| **🔌 PORT** | Networking | Align `targetPort` in Service with `containerPort` in Pod. |
| **🛡️ API SHIELD** | Compliance | Migrate to the recommended stable API version. |

---

## 💬 Feedback & Contribution

KubePulse is built for the community.

* **Found a bug?** Open an Issue.
* **Have a feature idea?** Email me at fixmyk8s@protonmail.com

**Built with ❤️  by Nishar A Sunkesala / FixMyK8s.**

```

---


