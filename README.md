## 💓 KubeCuro

[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=flat&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

**KubeCuro** is a high-performance, production-grade CLI tool designed to eliminate the "silent killers" of Kubernetes deployments. While standard linters merely validate YAML syntax, KubeCuro performs a deep-tissue scan to ensure your infrastructure is **Syntactically Healthy**, **Logically Connected**, and **API Future-Proof**.

---

## 📄 Project Metadata

* **Author:** Nishar A Sunkesala / [FixMyK8s](https://github.com/nisharas)
* **Version:** 1.0.0
* **Status:** Stable / Production Ready
* **Repository:** [https://github.com/nisharas/kubecuro](https://github.com/nisharas/kubecuro)

---

## 🎯 The Gap & The Solution

**The Gap:** Current CI/CD pipelines use "Validators" that only check if a YAML file is technically valid. They fail to detect if a Service will actually reach its Pod (due to label/namespace mismatches) or if an API version is deprecated.

**The Solution:** KubeCuro closes this feedback loop. It analyzes the **relationships** between files, detecting logical orphans and connection gaps *before* they reach your control plane.

---

## 🚀 The Triple-Engine Defense

1. **🩹 The Healer (Syntax Engine):** Uses a **Split-Stream** architecture to safely process multi-document YAMLs. It auto-remediates missing colons and standardizes indentation.
2. **🧠 The Synapse (Logic Engine):** A deep-link analyzer that validates **Selectors vs. Labels**, **Namespace isolation**, and **Port mapping** (including named ports).
3. **🛡️ The Shield (API Shield Engine):** A context-aware deprecation guard that identifies resource types and suggests specific modern API paths.

---

## 🛡️ Security & Privacy Audit

KubeCuro is designed with a "Security-First" architecture, operating as a localized static analysis tool.

* **Zero Data Leakage:** Runs entirely on your local machine. No external network requests or data collection.
* **Air-Gapped by Design:** Does not communicate with the Kubernetes API Server. No `kubeconfig` or credentials required.
* **No Privilege Escalation:** Operates with the same permissions as the local user.
* **Safe Parsing:** Uses `ruamel.yaml` to prevent malicious code injection within YAML manifests.

---

## 💻 Usage

**Scan a Single File**
```bash
kubecuro pod.yaml

```

**Scan an Entire Directory**
Cross-references all manifests within the folder to find logical gaps.

```bash
kubecuro ./k8s-manifests/

```

**Get Help**

```bash
kubecuro --help

```

---

## 🛠️ Installation

### Option A: Standalone Binary (Recommended)

Zero dependencies. Download and install directly via terminal:

```bash
# Download the latest binary
curl -L -O https://github.com/nisharas/kubecuro/releases/download/v1.0.0/kubecuro

# Set execution permissions
chmod +x kubecuro

# Move to your local bin path
sudo mv kubecuro /usr/local/bin/

```

### Option B: From Source (Developers)

```bash
git clone https://github.com/nisharas/kubecuro.git
cd kubecuro
pip install -e .

```

---

## 🩺 Diagnostic Intelligence

| Signal | Category | Resolution Strategy |
| --- | --- | --- |
| **🩺 DIAGNOSTIC** | Structure | Auto-heals syntax and indentation. |
| **🌐 NAMESPACE** | Connectivity | Align the `namespace` field between Service & Pod. |
| **👻 GHOST** | Orphanage | Match Service `selectors` to Deployment `template` labels. |
| **🔌 PORT** | Networking | Align `targetPort` in Service with `containerPort` in Pod. |
| **🛡️ API SHIELD** | Compliance | Migrate to the recommended stable API version. |

---

## 📊 Sample Report

KubeCuro provides a clear, severity-ranked breakdown of your infrastructure's health:

FINAL PULSE SUMMARY
| File Name | Severity   | Engine   | Issues Found   | Status       |
| --- | --- | --- | --- | --- |
| web.yaml  | 🔴 HIGH    | Synapse  | GHOST          | ❌ Logic Gap |
| ing.yaml  | 🟠 MED     | Shield   | DEPRECATED API | ⚠️ Warning   |

```text
💡 SUGGESTED REMEDIATIONS:
======================================================================
👉 [GHOST]: Update Service 'selector' to match Pod 'labels'.
👉 [PORT]: Align Service 'targetPort' with Pod 'containerPort'.
👉 [API]: Update 'apiVersion' to 'networking.k8s.io/v1' for Ingress.
======================================================================
```

---

## 💬 Feedback & Contribution

KubeCuro is built for the community.

* **Found a bug?** Open an [Issue](https://github.com/nisharas/kubecuro/issues).

## 💖 Support the Project

KubeCuro is an open-source project built with the goal of making Kubernetes infrastructure safer and more reliable for everyone. If KubeCuro has saved you hours of debugging or prevented a production outage, consider supporting its continued development!

### ☕ Buy Me a Coffee
If you find this tool helpful, you can support my work by buying me a coffee. Every bit of support helps keep the "Heartbeat" of this project going.

| Scan to Support | Link |
| :---: | :--- |
| <img src="https://github.com/nisharas/kubecuro/blob/main/assets/bmc_qr.png?raw=true" width="150"> | [Buy Me a Coffee](https://www.buymeacoffee.com/fixmyk8s) |

### 🚀 Corporate Sponsorship
Is your company using KubeCuro to secure its delivery pipeline? Please consider a corporate sponsorship to help fund:
* Advanced diagnostic engines.
* Faster release cycles.
* Dedicated community support.

Reach out to me at **fixmyk8s@protonmail.com** for formal sponsorship inquiries.
* **Have a feature idea?** Email me at **fixmyk8s@protonmail.com**

**Built with ❤️ by Nishar A Sunkesala / [FixMyK8s](https://github.com/nisharas).**


