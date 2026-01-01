# Contributing to Kubecuro 💓

Welcome! We are excited that you want to help make Kubernetes deployments more reliable. As a project aiming for the CNCF Sandbox, we value transparency, inclusion, and high-quality "Logic Checks."

## 📜 Code of Conduct
By participating in this project, you agree to abide by the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

## ⚖️ License & CLA
By contributing to Kubecuro, you agree that your contributions will be licensed under the **Apache License 2.0**. 

Before we can merge your pull requests, we ask that you sign-off your commits to certify the **Developer Certificate of Origin (DCO)**. You can do this by adding `-s` to your git commit command:
`git commit -s -m "Add new synapse check for NetworkPolicy"`

## 🛠️ How Can I Contribute?

### 1. Reporting "Logic Gaps"
The most valuable contribution is a report of a real-world Kubernetes failure that Kubecuro didn't catch. 
* Open an issue with the tag `[Logic Gap]`.
* Provide a sample of the broken YAML (anonymized).

### 2. Improving the Engines
* **Healer:** Add new regex or logic to fix more YAML syntax errors.
* **Synapse:** Add new cross-resource relationship checks (e.g., ConfigMap to Deployment).
* **Shield:** Update the list of deprecated APIs for the latest K8s versions.

### 3. Documentation & Examples
* Help us improve the `README.md` or `CAPABILITIES.md`.
* Add sample "Broken vs. Fixed" manifests to the `examples/` folder.

## 🚀 Pull Request Process
1. **Fork** the repository and create your branch from `main`.
2. **Test** your changes locally using our test suite.
3. **Document** any new logic checks in the PR description.
4. **Sign-off** your commits (`git commit -s`).
5. Open the PR and wait for a maintainer to review.

## 💬 Communication
If you have questions, please use **GitHub Discussions** or join our community Discord/Slack (Coming Soon!).

---
*Built with ❤️ by Nishar A Sunkesala and the Kubecuro Community | Powered by FixMyK8s.*
