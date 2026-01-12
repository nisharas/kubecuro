## ❤️ 
KubeCuro - Kubernetes Surgeon
**Diagnose. Explain. Auto-Fix. Zero Downtime.**

[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=flat&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
![Build Status](https://github.com/nisharas/kubecuro/actions/workflows/test.yml/badge.svg?branch=main)
[![Status](https://img.shields.io/badge/status-stable-green)]()
[![Release](https://img.shields.io/github/v/release/nisharas/kubecuro?color=orange)]()

<p align="center">
<img src="src/kubecuro/assets/KubeCuro-Logo.png" width="200"/>
</p>

**KubeCuro** is a high-performance, production-grade CLI tool designed to eliminate the "silent killers" of Kubernetes deployments.

> [!TIP]
> **Get started in seconds:**
> ```bash
> # 1. Install (Linux x86_64)
> curl -L -O https://github.com/nisharas/kubecuro/releases/download/v1.0.0/kubecuro && chmod +x kubecuro && sudo mv kubecuro /usr/local/bin/
> 
> # 2. Scan your manifests (Ensure the folder contains .yaml or .yml files)
> kubecuro scan .
> ```
---

### 🎯 Our Mission
**To ensure that every Kubernetes manifest is not just syntactically correct, but logically sound and production-ready.** We believe that YAML validation should go beyond "Is it valid?" and answer "Will it work?"

### 📄 Project Metadata
**Author:** Nishar A Sunkesala / FixMyK8s  
**Version:** 1.0.0  
**Status:** Stable / Production Ready  

---

### 🔍 The Gap & The Solution

**The Gap:** Current CI/CD pipelines use "Validators" that only check if a YAML file is technically valid. They fail to detect if a Service will actually reach its Pod (due to label mismatches) or if an API version is deprecated.

**The Solution:** KubeCuro closes this feedback loop. It analyzes the **relationships** between files, detecting logical orphans and connection gaps before they reach your control plane.

---

### ⚖️ Why KubeCuro? (The Logic Gap)

Most tools only check if the "grammar" of your YAML is correct. KubeCuro checks if the "story" makes sense.

| Feature | Standard Linters | KubeCuro |
| --- | --- | --- |
| YAML Syntax Check | ✅ | ✅ | 
| Schema Validation | ✅ | ✅ |
| Auto-Heal Formatting | ❌ | ✅ | 
| Cross-File Logic (Synapse) | ❌ | ✅ |
| Service-to-Pod Mapping | ❌ | ✅ | 
| Port Alignment Audit | ❌ | ✅ |

### 🚀 Why use KubeCuro?
1. Reduce "Developer Friction" - 
Instead of a CI/CD pipeline failing with a cryptic "Invalid YAML" error, KubeCuro tells the developer exactly what happened and, in many cases, fixes it for them. This reduces the back-and-forth between Dev and Ops.

2. Prevent Silent Failures -
A Service with a typo in its selector won't throw a Kubernetes error—it just won't send traffic to your Pods. These "silent failures" are the hardest to debug. Synapse catches these instantly.

3. Zero-Dependency Portability
Thanks to the static build process, KubeCuro is a single, 15MB binary.

    * No Python required.
    * No pip install.
    * Just chmod +x and run. This makes it perfect for Scratch-based Docker images or restricted CI runners.
      
4. Smart Tab-Completion: Full support for Bash and Zsh with an automated installer.

5. Explain Engine: Direct access to K8s logic best practices via `kubecuro explain`.
### 🛠️ The Three Pillars of KubeCuro
| Engine | Purpose | Real-World Value |
| --- | --- | --- |
| 🩺 Healer | Auto-Fixing | Stops "Death by Indentation." Automatically repairs syntax and formatting issues, showing a clear diff of changes. |
| 🧠 Synapse | Logic Audit | Detects "Ghost Services." Ensures that Selectors, Labels, and Ports actually align across different files. |
| 🛡️ Shield | Security & Versioning | Prevents "API Rot." Flags deprecated API versions and insecure configurations before they hit your cluster. |

### 🚀 Intelligent Logic Checks (Verified)

KubeCuro goes beyond standard linters by auditing the **relationships** between your resources.

#### 🧠 Synapse: Networking & Scaling Logic
* **Ghost Service Detection:** Identifies `Services` that target labels matching zero `Pods`. (Verified in tests)
* **HPA Resource Gap:** Flags `HorizontalPodAutoscalers` that scale based on CPU/Memory when those resources aren't defined in the deployment. (Verified in tests)

#### 🛡️ Shield: Versioning & Security
* **API Rot Protection:** Automatically detects deprecated API versions (like `extensions/v1beta1`) before they break your cluster upgrade. (Verified in tests)
* **Severity Scoring:** Issues are categorized into `GHOST`, `PORT`, and `API` for easy prioritization.

#### 🩺 Healer: Structural Repair
* **Auto-Repair:** The `fix` command automatically heals YAML indentation and upgrades deprecated APIs while maintaining a dry-run preview. (Verified in tests)

### 📦 Supported Kubernetes Resources

KubeCuro currently provides deep-logic analysis for the following core resources:

| Resource Type | Synapse (Logic) | Shield (Security) | Healer (Auto-Fix) |
| :--- | :---: | :---: | :---: |
| **Deployments** | ✅ | ✅ | ✅ |
| **Services** | ✅ | ✅ | ✅ |
| **HPAs** | ✅ | ❌ | ✅ |
| **Ingress** | ❌ | ✅ | ✅ |
| **StatefulSets** | ✅ | ✅ | ❌ |

> **Note:** We are constantly adding new resource definitions. If you need support for a specific CRD, please open an issue!

---

### 🧠 Diagnostic Intelligence

KubeCuro categorizes issues based on their impact on cluster stability:

- 🔴 GHOST (Critical): Service exists, but its selector matches zero Pods. Traffic will be dropped.
- 🔴 PORT (Critical): Service targetPort does not match any containerPort in the targeted Pods.
- 🟠 NAMESPACE (Warning): Matches found, but resources are isolated in different namespaces.
- 🟡 API (Warning): Using deprecated API versions (e.g., extensions/v1beta1) that will fail on upgrade.
  
### 🛡️ Security & Privacy Audit

KubeCuro is designed with a "Security-First" architecture, operating as a localized static analysis tool.

* **Zero Data Leakage:** Runs entirely locally. No external network requests.
* **Air-Gapped by Design:** Does not need a connection to the K8s API server.
* **Read-Only by Default:** The scan command never modifies your files.

### ⚖️ Design Philosophy: The "Safe" CNCF Approach
KubeCuro is built on the principle of Predictable Automation. We distinguish between structural repair and logical intent to ensure your manifests remain under your total control.

🩺 The Healer (Active): Auto-fixes Syntax. It handles the "busy work" by repairing indentation, fixing tab/space conflicts, and ensuring YAML standards (via ruamel.yaml).

🧠 Synapse & Shield (Passive): Provides Intelligence. These engines detect logical gaps (like GHOST services) and security risks. Instead of making dangerous assumptions, they provide a Remediation Guide so a human engineer can make the final, informed decision.

Why? In production Kubernetes environments, auto-fixing a label could accidentally route traffic to the wrong database. KubeCuro fixes the format but respects your intent.

---

**🆓 FREE vs 💎 PRO**  
| Tier | Detects | Behavior |
|------|---------|----------|
| **🆓 FREE** | OOM_RISK, SEC_TOKEN_AUDIT, API_DEPRECATED + 12 others | ✅ Full diagnostics |
| **💎 PRO** | `KUBECURO_PRO=1` unlocks GHOST_SERVICE, VPA_CONFLICT + 5 more | ✅ Full diagnostics |
| **🔒 Locked** | PRO rules for free users | Shows `"🔒 PRO RULE: fixmyk8s.com/pro"` |

**ALL rules = diagnostics only. `kubecuro fix` auto-heals syntax regardless of tier.**

---

### 🖥️ Compatibility & Requirements

KubeCuro is distributed as a **fully static Linux binary**. 

* **OS:** Linux (Any distribution: Ubuntu, CentOS, Alpine, RHEL, etc.)
* **Architecture:** x86_64 (64-bit Intel/AMD processors only)
* **Dependencies:** None. (Self-contained static binary)

> **Note:** This binary will not run on ARM64 architectures (e.g., Apple M-series chips, Raspberry Pi, or AWS Graviton) or non-Linux operating systems (Windows/macOS) natively.

---

### 🛠️ Installation

#### Option A: Standalone Binary (Recommended)

Zero dependencies. Download and install directly via terminal:

```bash
# Download the latest binary
curl -L -O https://github.com/nisharas/kubecuro/releases/download/v1.0.0/kubecuro

# Set execution permissions
chmod +x kubecuro

# Move to your local bin path
sudo mv kubecuro /usr/local/bin/

```

#### Option B: From Source (Developers)

```bash
git clone https://github.com/nisharas/kubecuro.git
cd kubecuro
pip install -e .

```

#### Enable Smart Autocomplete (Zsh/Bash)
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

### 💻 Usage

**1. Smart Scan**
Scan a file or a whole directory. KubeCuro automatically detects if you want a scan.
```bash
kubecuro ./manifests-folder/

```

**2. Auto-Heal (Fix)**
Repair syntax errors and migrate old API versions instantly.

```bash
kubecuro fix deployment.yaml --dry-run  # Preview changes
kubecuro fix deployment.yaml            # Apply changes
```

**3. Get Help**

```bash
kubecuro --help
```

---

### 📊 Sample Output

**1. Running a Smart Scan**

When you run `kubecuro ./k8s-manifests-folder/` the tool performs a multi-stage audit:
🔍 KubeCuro v1.0.0 SCAN
```text
┌─────────────────┐ ┌────────────┐ ┌──────────┐
│ 🔴 CRITICAL     │ │ 🟡 WARNING │ │ 🟢 INFO  │
│ 0               │ │ 2         │ │ 0        │
└─────────────────┘ └────────────┘ └──────────┘

📂 name-port-ghost.yaml
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity           ┃     Line ┃ Code                 ┃ Issue                                                         ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 🟡 MEDIUM          │        8 │ SEC_TOKEN_AUDIT      │ Healer Recommendation: SEC_TOKEN_AUDIT                        │
│ 🟡 MEDIUM          │        9 │ OOM_RISK             │ Container missing resource limits (Risk of OOMKill)           │
├────────────────────┼──────────┼──────────────────────┼───────────────────────────────────────────────────────────────┤
│ Σ 2 Issues         │          │ CLEAN                │ File Health Analysis Complete                                 │
└────────────────────┴──────────┴──────────────────────┴───────────────────────────────────────────────────────────────┘

────────────────────────────────────────────  🧬 KUBECURO SYSTEM REPORT  ───────────────────────────────────────────── 
                                                                                                                        
   STATUS                                        CLUSTER INTEGRITY: 90%                               VULNERABILITIES   
   CRITICAL                     ━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                           2 total   
   ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────   
   🔴 0 Critical 🟡 2 Warning 🟢 0 Info                                                                                
                                                                                                                        
                                                                                                                        
                                                                                                                        
      💡 PERFORMANCE ADVISORY                                                                                           
     Resource limits are missing. Execute kubecuro fix --apply-defaults to inject conservative CPU/Memory bounds.       
                                                                                                                        
                                                                                                                        
 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 
```
**2. The "Healer" in Action (Dry Run)**

If you want to see exactly how KubeCuro would fix a broken file:

`kubecuro fix service.yaml --dry-run`
```text
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                ❤️  KubeCuro v1.0.0 FIX                                                │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
🔍 Analyzing 1 manifests...
  [ 1/1] service.yaml                        ✓

                                         ✅ Nothing to fix - All files healthy! 
```
---

#### 💎 **Upgrade to KubeCuro PRO** 
**[fixmyk8s.com/pro](https://fixmyk8s.com/pro)** - **$9/month per developer**

## 🆓 FREE vs 💎 PRO

| Feature | 🆓 **FREE** | 💎 **PRO** (`KUBECURO_PRO=1`) |
|---------|-------------|-------------------------------|
| **CORE SAFETY** | ✅ OOM_RISK<br>✅ SEC_TOKEN_AUDIT<br>✅ API_DEPRECATED<br>✅ SYNTAX_ERROR<br>✅ **15+ rules** | ✅ **ALL 25+ rules**<br>🔓 **GHOST_SERVICE**<br>🔓 **VPA_CONFLICT**<br>🔓 **SHADOW_DEPLOYMENT**<br>🔓 **NODE_PRESSURE** |
| **DIAGNOSTICS** | 🔍 **ALL rules**<br>📊 Spectacular tables<br>🎯 Health scores | 🔍 **ALL rules**<br>📊 Spectacular tables<br>🎯 Health scores<br>📈 **Trend analysis** |
| **AUTO-FIX** | 🛠️ **SYNTAX_ERROR**<br>🔧 **OOM_RISK** (basic)<br>⚡ Zero-downtime | 🛠️ **ALL 25+ rules**<br>🔧 **Advanced OOM**<br>🔧 **Ghost cleanup**<br>🔧 **Shadow deployments**<br>⚡ **Zero-downtime**<br>🚀 **100% fix coverage** |
| **VISIBILITY** | 👻 PRO rules show:<br>`🔒 PRO RULE: fixmyk8s.com/pro` | ✅ **Full visibility**<br>🚀 No restrictions |
| **SUPPORT** | 📚 Docs + Community | 👨‍💻 **Priority support**<br>🎥 Custom demos |
| **ENTERPRISE** | - | 🏢 GitHub Copilot integration<br>🔄 CI/CD automation<br>📊 Team dashboards |

> **🆓 FREE** = Firefighter (85% coverage).  
> **💎 PRO** = Fire Prevention Engineer (100% coverage + exclusive rules).  
> 
> ```bash
> export KUBECURO_PRO=1
> # PRO users run:
> KUBECURO_PRO=your-license-key ./kubecuro scan .
> ```

⚡ Instant upgrade → No re-install → PRO rules immediately active

Get PRO License → [fixmyk8s.com/pro](https://fixmyk8s.com/pro)

---

### 💬 Feedback & Contribution

KubeCuro is built for the community.

* **Found a bug?** Open an [Issue](https://github.com/nisharas/kubecuro/issues).

### 💖 Support the Project

KubeCuro is an open-source project built with the goal of making Kubernetes infrastructure safer and more reliable for everyone. If KubeCuro has saved you hours of debugging or prevented a production outage, consider supporting its continued development!

#### ☕ Buy Me a Coffee
If you find this tool helpful, you can support my work by buying me a coffee. Every bit of support helps keep the "Heartbeat" of this project going.

| Scan to Support | Link |
| :---: | :--- |
| <img src="src/kubecuro/assets/bmc-qr.png" width="150"> | [Buy Me a Coffee](https://www.buymeacoffee.com/fixmyk8s) |


* **Have a feature idea?** Email me at **fixmyk8s@protonmail.com**

Reach out to me at **fixmyk8s@protonmail.com** for formal sponsorship inquiries.



**Built with ❤️ by Nishar A Sunkesala and the Kubecuro Community | Powered by FixMyK8s**


