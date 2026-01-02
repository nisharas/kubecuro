## KubeCuro

[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=flat&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

<img src="https://github.com/nisharas/kubecuro/blob/main/assets/KubeCuro%20Logo%20.png?raw=true" width="300">

**KubeCuro** is a high-performance, production-grade CLI tool designed to eliminate the "silent killers" of Kubernetes deployments. While standard linters merely validate YAML syntax, KubeCuro performs a deep-tissue scan to ensure your infrastructure is **Syntactically Healthy**, **Logically Connected**, and **API Future-Proof**.

**KubeCuro** isn't just another linter; it's a "Kubernetes Sanitizer." While most tools focus on schema validation, KubeCuro focuses on the functional integrity of your entire manifest suite. It bridges the gap between writing YAML and successfully running it.

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

## 🛠️ The Three Pillars of KubeCuro
| Engine | Purpose | Real-World Value |
| --- | --- | --- |
| 🩺 Healer | Auto-Fixing | Stops "Death by Indentation." Automatically repairs syntax and formatting issues, showing a clear diff of changes. |
| 🧠 Synapse | Logic Audit | Detects "Ghost Services." Ensures that Selectors, Labels, and Ports actually align across different files. |
| 🛡️ Shield | Security & Versioning | Prevents "API Rot." Flags deprecated API versions and insecure configurations before they hit your cluster. |

---

## 🚀 Why use KubeCuro?
1. Reduce "Developer Friction"
Instead of a CI/CD pipeline failing with a cryptic "Invalid YAML" error, KubeCuro tells the developer exactly what happened and, in many cases, fixes it for them. This reduces the back-and-forth between Dev and Ops.

2. Prevent Silent Failures
A Service with a typo in its selector won't throw a Kubernetes error—it just won't send traffic to your Pods. These "silent failures" are the hardest to debug. Synapse catches these instantly.

3. Zero-Dependency Portability
Thanks to the static build process, KubeCuro is a single, 10MB binary.

    * No Python required.
    * No pip install.
    * Just chmod +x and run. This makes it perfect for Scratch-based Docker images or restricted CI runners.

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

FINAL SUMMARY
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

## 📈 Roadmap to v1.1.0
To further increase the value, we are looking at:
   
  * --json output: For easy integration with monitoring dashboards.
  * Helm Support: Directly scanning Helm templates before rendering.
  * GitHub Action: A first-party action to "Cure" your PRs automatically.

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

**Built with ❤️ by Nishar A Sunkesala and the Kubecuro Community | Powered by FixMyK8s**


