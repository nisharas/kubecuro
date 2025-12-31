# 💓 KubePulse

[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=flat&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**KubePulse** is a high-performance, production-grade CLI tool designed to eliminate the "silent killers" of Kubernetes deployments. While standard linters merely validate YAML syntax, KubePulse performs a deep-tissue scan to ensure your infrastructure is **Syntactically Healthy**, **Logically Connected**, and **API Future-Proof**.

---

## 📄 Project Metadata

* **Author:** Nishar A Sunkesala / [FixMyK8s](https://github.com/nisharas)
* **Version:** 1.0.0
* **Status:** Stable / Production Ready
* **Repository:** [https://github.com/nisharas/kubepulse](https://github.com/nisharas/kubepulse)

---

## 🎯 The Gap & The Solution

**The Gap:** Current CI/CD pipelines use "Validators" that only check if a YAML file is technically valid. They fail to detect if a Service will actually reach its Pod (due to label/namespace mismatches) or if an API version is deprecated.

**The Solution:** KubePulse closes this feedback loop. It analyzes the **relationships** between files, detecting logical orphans and connection gaps *before* they reach your control plane.

---

## 🚀 The Triple-Engine Defense

1. **🩹 The Healer (Syntax Engine):** Uses a **Split-Stream** architecture to safely process multi-document YAMLs. It auto-remediates missing colons and standardizes indentation.
2. **🧠 The Synapse (Logic Engine):** A deep-link analyzer that validates **Selectors vs. Labels**, **Namespace isolation**, and **Port mapping** (including named ports).
3. **🛡️ The Shield (API Shield Engine):** A context-aware deprecation guard that identifies resource types and suggests specific modern API paths.

---

## 🛡️ Security & Privacy Audit

KubePulse is designed with a "Security-First" architecture, operating as a localized static analysis tool.

* **Zero Data Leakage:** Runs entirely on your local machine. No external network requests or data collection.
* **Air-Gapped by Design:** Does not communicate with the Kubernetes API Server. No `kubeconfig` or credentials required.
* **No Privilege Escalation:** Operates with the same permissions as the local user.
* **Safe Parsing:** Uses `ruamel.yaml` to prevent malicious code injection within YAML manifests.

---

## 💻 Usage

**Scan a Single File**
```bash
kubepulse pod.yaml
Scan an Entire DirectoryCross-references all manifests within the folder to find logical gaps.Bashkubepulse ./k8s-manifests/
Get HelpBashkubepulse --help
🛠️ InstallationOption A: Standalone Binary (Recommended)Zero dependencies. Download and install directly via terminal:Bash# Download the latest binary
curl -L -O [https://github.com/nisharas/kubepulse/releases/download/v1.0.0/kubepulse](https://github.com/nisharas/kubepulse/releases/download/v1.0.0/kubepulse)

# Set execution permissions
chmod +x kubepulse

# Move to your local bin path
sudo mv kubepulse /usr/local/bin/
Option B: From Source (Developers)Bashgit clone [https://github.com/nisharas/kubepulse.git](https://github.com/nisharas/kubepulse.git)
cd kubepulse
pip install -e .
🩺 Diagnostic IntelligenceSignalCategoryResolution Strategy🩺 DIAGNOSTICStructureAuto-heals syntax and indentation.🌐 NAMESPACEConnectivityAlign the namespace field between Service & Pod.👻 GHOSTOrphanageMatch Service selectors to Deployment template labels.🔌 PORTNetworkingAlign targetPort in Service with containerPort in Pod.🛡️ API SHIELDComplianceMigrate to the recommended stable API version.💬 Feedback & ContributionKubePulse is built for the community.Found a bug? Open an Issue.Have a feature idea? Email me at fixmyk8s@protonmail.comBuilt with ❤️ by Nishar A Sunkesala / FixMyK8s.
