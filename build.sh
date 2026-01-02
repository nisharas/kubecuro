#!/bin/bash
set -e

echo "📦 1. Deep cleaning workspace..."
rm -rf build/ dist/ *.spec
# Clear the PyInstaller cache to ensure it doesn't remember the C-lib
pyinstaller --clean -y /dev/null &>/dev/null || true 

echo "🐍 2. Building Dynamic Binary (Force Exclude CLIB)..."
pyinstaller --onefile \
            --clean \
            --name kubecuro_dynamic \
            --paths src \
            --collect-all rich \
            --hidden-import ruamel.yaml \
            --exclude-module _ruamel_yaml_clib \
            --exclude-module ruamel.yaml.clib \
            src/kubecuro/main.py

echo "🛡️ 3. Converting to Static Binary..."
# Check if the dynamic file actually exists first
if [ -f "dist/kubecuro_dynamic" ]; then
    staticx dist/kubecuro_dynamic dist/kubecuro
else
    echo "❌ Error: dist/kubecuro_dynamic was not created!"
    exit 1
fi

echo "✅ 4. Build Complete!"
echo "------------------------------------------------"
echo "Binary location: $(pwd)/dist/kubecuro"
echo "Test it now: ./dist/kubecuro --help"
