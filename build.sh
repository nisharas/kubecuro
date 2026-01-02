#!/bin/bash
set -e

echo "🧹 1. Deep cleaning workspace..."
rm -rf build/ dist/ *.spec *.egg-info
# Clear PyInstaller's internal cache
pyinstaller --clean -y /dev/null &>/dev/null || true 

echo "🐍 2. Building Dynamic Binary..."
# Note: We still keep the exclusion flags as a double-safety measure
pyinstaller --onefile \
            --clean \
            --name kubecuro_dynamic \
            --paths src \
            --add-data "assets/*.png:assets" \
            --collect-all rich \
            --hidden-import ruamel.yaml \
            --exclude-module _ruamel_yaml_clib \
            --exclude-module ruamel.yaml.clib \
            src/kubecuro/main.py

echo "🛡️ 3. Converting to Static Binary with StaticX..."
if [ -f "dist/kubecuro_dynamic" ]; then
    # StaticX will now succeed because the .so file is physically missing from the bundle
    staticx dist/kubecuro_dynamic dist/kubecuro
else
    echo "❌ Error: dist/kubecuro_dynamic was not created!"
    exit 1
fi

echo "✅ 4. Build Complete!"
echo "--------------------------------------"
echo "Binary location: $(pwd)/dist/kubecuro"
echo "Test it now: ./dist/kubecuro --help"
