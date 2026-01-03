## ❤️ KubeCuro

[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=flat&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

<img src="src/kubecuro/assets/KubeCuro-Logo.png" width="300">

**KubeCuro** is a high-performance, production-grade CLI tool designed to eliminate the "silent killers" of Kubernetes deployments.

## 🎯 Our Mission
**To ensure that every Kubernetes manifest is not just syntactically correct, but logically sound and production-ready.** We believe that YAML validation should go beyond "Is it valid?" and answer "Will it work?"

## 📄 Project Metadata
**Author:** Nishar A Sunkesala / FixMyK8s  
**Version:** 1.0.0  
**Status:** Stable / Production Ready  

---

## 🔍 The Gap & The Solution

**The Gap:** Current CI/CD pipelines use "Validators" that only check if a YAML file is technically valid. They fail to detect if a Service will actually reach its Pod (due to label mismatches) or if an API version is deprecated.

**The Solution:** KubeCuro closes this feedback loop. It analyzes the **relationships** between files, detecting logical orphans and connection gaps before they reach your control plane.

---
## ⚖️ Why KubeCuro? (The Logic Gap)

Most tools only check if the "grammar" of your YAML is correct. KubeCuro checks if the "story" makes sense.

| Feature | Standard Linters | KubeCuro |
| --- | --- | --- |
| YAML Syntax Check | ✅ | ✅ | 
| Schema Validation | ✅ | ✅ |
| Auto-Heal Formatting | ❌ | ✅ | 
| Cross-File Logic (Synapse) | ❌ | ✅ |
| Service-to-Pod Mapping | ❌ | ✅ | 
| Port Alignment Audit | ❌ | ✅ |

## 🚀 Why use KubeCuro?
1. Reduce "Developer Friction" - 
Instead of a CI/CD pipeline failing with a cryptic "Invalid YAML" error, KubeCuro tells the developer exactly what happened and, in many cases, fixes it for them. This reduces the back-and-forth between Dev and Ops.

2. Prevent Silent Failures -
A Service with a typo in its selector won't throw a Kubernetes error—it just won't send traffic to your Pods. These "silent failures" are the hardest to debug. Synapse catches these instantly.

3. Healer - Enhanced auto-repair for mixed indentation and deprecated API versions.

4. Zero-Dependency Portability
Thanks to the static build process, KubeCuro is a single, 15MB binary.

    * No Python required.
    * No pip install.
    * Just chmod +x and run. This makes it perfect for Scratch-based Docker images or restricted CI runners.
      
5. Smart Tab-Completion: Full support for Bash and Zsh with an automated installer.

6. Explain Engine: Direct access to K8s logic best practices via kubecuro explain.
## 🛠️ The Three Pillars of KubeCuro
| Engine | Purpose | Real-World Value |
| --- | --- | --- |
| 🩺 Healer | Auto-Fixing | Stops "Death by Indentation." Automatically repairs syntax and formatting issues, showing a clear diff of changes. |
| 🧠 Synapse | Logic Audit | Detects "Ghost Services." Ensures that Selectors, Labels, and Ports actually align across different files. |
| 🛡️ Shield | Security & Versioning | Prevents "API Rot." Flags deprecated API versions and insecure configurations before they hit your cluster. |

---
## 🧠 Diagnostic Intelligence

KubeCuro categorizes issues based on their impact on cluster stability:

- 🔴 GHOST (Critical): Service exists, but its selector matches zero Pods. Traffic will be dropped.
- 🔴 PORT (Critical): Service targetPort does not match any containerPort in the targeted Pods.
- 🟠 NAMESPACE (Warning): Matches found, but resources are isolated in different namespaces.
- 🟡 API (Warning): Using deprecated API versions (e.g., extensions/v1beta1) that will fail on upgrade.
  
## 🛡️ Security & Privacy Audit

KubeCuro is designed with a "Security-First" architecture, operating as a localized static analysis tool.

* **Zero Data Leakage:** Runs entirely locally. No external network requests.
* **Air-Gapped by Design:** Does not need a connection to the K8s API server.
* **Read-Only by Default:** The scan command never modifies your files.
---
## ⚖️ Design Philosophy: The "Safe" CNCF Approach
KubeCuro is built on the principle of Predictable Automation. We distinguish between structural repair and logical intent to ensure your manifests remain under your total control.

🩺 The Healer (Active): Auto-fixes Syntax. It handles the "busy work" by repairing indentation, fixing tab/space conflicts, and ensuring YAML standards (via ruamel.yaml).

🧠 Synapse & Shield (Passive): Provides Intelligence. These engines detect logical gaps (like GHOST services) and security risks. Instead of making dangerous assumptions, they provide a Remediation Guide so a human engineer can make the final, informed decision.

Why? In production Kubernetes environments, auto-fixing a label could accidentally route traffic to the wrong database. KubeCuro fixes the format but respects your intent.

---
## 🖥️ Compatibility & Requirements

KubeCuro is distributed as a **fully static Linux binary**. 

* **OS:** Linux (Any distribution: Ubuntu, CentOS, Alpine, RHEL, etc.)
* **Architecture:** x86_64 (64-bit Intel/AMD processors only)
* **Dependencies:** None. (Self-contained static binary)

> **Note:** This binary will not run on ARM64 architectures (e.g., Apple M-series chips, Raspberry Pi, or AWS Graviton) or non-Linux operating systems (Windows/macOS) natively.
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

### Enable Smart Autocomplete (Zsh/Bash)
To make your workflow faster with tab-completions, you need to download and run the automated installer script.

```bash
# 1. Download the installer script from the repository
curl -L -O https://raw.githubusercontent.com/nisharas/kubecuro/main/install-completions.sh

# 2. Run the automated installer
chmod +x install-completions.sh
./install-completions.sh

# 3. Apply changes to your current session
source ~/.bashrc  # if using Bash
source ~/.zshrc   # if using Zsh
```

---
## 💻 Usage

**1. Smart Scan**
Scan a file or a whole directory. KubeCuro automatically detects if you want a scan.
```bash
kubecuro ./manifests/

```

**2. Auto-Heal (Fix)**
Repair syntax errors and migrate old API versions instantly.

```bash
kubecuro fix deployment.yaml --dry-run  # Preview changes
kubecuro fix deployment.yaml            # Apply changes
```

**3. Logic Encyclopedia**
Don't just fix it—understand why. Use `explain` to see the logic KubeCuro uses.
*Tip: Hit [TAB] after typing 'explain' to see all available resources!*
```bash
kubecuro explain hpa
kubecuro explain rbac
```
**4. Get Help**

```bash
kubecuro --help
```
---
## 📊 Sample Output

**1. Running a Smart Scan**

When you run `kubecuro ./k8s-manifests/` the tool performs a multi-stage audit:
```text
❤️  KUBECURO SCAN
Target: ./k8s-manifests/ (4 files)

📊 Diagnostic Report
Severity   File             Message
🟢 FIXED    web-svc.yaml     Repaired YAML syntax and migrated API versions.
🔴 HIGH     web-svc.yaml     Service 'web-frontend' targets labels {'app': 'nginx'} but matches 0 Pods.
🟠 MED      ingress.yaml     🛡️ [API_DEPRECATED] Ingress uses 'extensions/v1beta1'. Retired in 1.22+.
🔴 HIGH     backend-hpa.yaml 📈 [Synapse] HPA targets 'api-server' but containers lack resources.requests.

📈 Audit Summary
* Ghost Services: 1 (Services with no pods)
* HPA Logic Gaps: 1 (Missing requests)
* API Warnings:   1 (Outdated versions)
* Auto-Repairs:   1 (Files syntax-healed)

Summary & Impact (CRITICAL)
Your manifests are technically valid but LOGICALLY BROKEN. 
Traffic will not reach the web-frontend due to a label mismatch.
```
**2. Using the Explain Engine**

If a user is confused by the HPA Logic Gap, they can ask KubeCuro for the underlying logic:

`kubecuro explain hpa`
```text
Logic: hpa
────────────────────────────────────────────────────────────────────────────────
# 📈 HPA Audit
KubeCuro audits Scaling Logic:
1. Target Ref: Validates that the target Deployment/StatefulSet exists.
2. Resources: Warns if scaling on CPU/Mem but containers lack resources.requests.
   Reason: HPA cannot calculate percentage-based scaling without a baseline request.
────────────────────────────────────────────────────────────────────────────────
```
**3. The "Healer" in Action (Dry Run)**

If you want to see exactly how KubeCuro would fix a broken file:

`kubecuro fix web-svc.yaml --dry-run`
```text
❤️  KUBECURO FIX (DRY-RUN)

--- web-svc.yaml (Original)
+++ web-svc.yaml (Healed)
@@ -1,6 +1,6 @@
-apiVersion: v1beta1
-kind: Service
+apiVersion: v1
+kind: Service
 metadata:
   name: web-frontend
 spec:
-  selector: 
-      app: nginx    <-- [Fixed Indentation]
+  selector:
+    app: nginx

🟢 WOULD FIX: Repaired YAML Syntax and migrated API versions.
Run without --dry-run to apply these changes.
```
## 📈 Roadmap to v1.1.0
To further increase the value, we are looking at:
   
  * --json output: For easy integration with monitoring dashboards.
  * Helm Support: Directly scanning Helm templates before rendering.
  * GitHub Action: Official KubeCuro action for PR "Logic Gates."

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
| <img src="src/kubecuro/assets/bmc-qr.png" width="150"> | [Buy Me a Coffee](https://www.buymeacoffee.com/fixmyk8s) |

* Governance: See [MAINTAINERS.md](https://github.com/nisharas/kubecuro/blob/main/MAINTAINERS.md) and [ADOPTERS.md](https://github.com/nisharas/kubecuro/blob/main/ADOPTERS.md).
* **Have a feature idea?** Email me at **fixmyk8s@protonmail.com**

### 🚀 Corporate Sponsorship
Is your company using KubeCuro to secure its delivery pipeline? Please consider a corporate sponsorship to help fund:
* Advanced diagnostic engines.
* Faster release cycles.
* Dedicated community support.

Reach out to me at **fixmyk8s@protonmail.com** for formal sponsorship inquiries.



**Built with ❤️ by Nishar A Sunkesala and the Kubecuro Community | Powered by FixMyK8s**


