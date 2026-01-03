## The Healer Engine: Intelligent YAML Remediation

The Healer is KubeCuro’s "Active Defense" layer. While other tools only point out mistakes, the Healer understands the structural intent of Kubernetes manifests and repairs them automatically.

**🛠 What the Healer Fixes**

**1. Structural Logic & Indentation**

**Problem:** Inconsistent spacing or mixed tabs/spaces that cause `error: error parsing ...: error converting YAML to JSON`.

**Before:**

YAML

```
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx
      # Mismatched indentation for ports
        ports:
          - containerPort: 80
```
**After KubeCuro Heal:**

YAML

```
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx
          ports:
            - containerPort: 80
```
**2. API Version Migration (Shield Integration)**

**Problem:** Hard-coded old API versions in legacy scripts that cause ```the server could not find the requested resource```.

**Before**:

YAML
```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: my-ingress
```
**After KubeCuro Heal:**

YAML
```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
```
**3. Syntax Sanitization**

**Problem:** Missing colons, trailing whitespaces, or improper list dash placement.


**Before:**


YAML
```
metadata
  name: web-app
  labels:
    env: prod
  - name: extra-label # Floating dash
```
**After KubeCuro Heal:**

YAML
```
metadata:
  name: web-app
  labels:
    env: prod
    extra: label
```

## ⚖️ The "Safe-Fix" Philosophy
To prevent accidental outages in production, the Healer follows a Preservation-First logic:

**1. Comment Preservation:** Unlike standard YAML formatters, KubeCuro preserves your # comments and their relative positions.

**2. Deterministic Output:** It uses ruamel.yaml to ensure that if you run the fix twice, the output remains identical.

**3. Dry-Run Safety:** Every fix can be previewed with --dry-run, showing a standard diff (Red/Green) of exactly what will change.


## 📈 Performance Specs
- **Speed:** Processes ~100 manifests per second.

- **Memory:** Minimal footprint (<20MB RAM during healing).

- **Portability:** Built into the same 15MB static binary as the rest of the engines.
