#!/usr/bin/env python3
import sys
import re
import difflib
from io import StringIO
try:
    from ruamel.yaml import YAML
except ImportError:
    import ruamel.yaml
    YAML = ruamel.yaml.YAML

def linter_engine(file_path):
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    
    try:
        with open(file_path, 'r') as f:
            original_content = f.read()

        raw_docs = re.split(r'^---', original_content, flags=re.MULTILINE)
        healed_parts = []

        for doc in raw_docs:
            if not doc.strip():
                continue

            d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+)(?=[ \t]*$)', r'\1:', doc, flags=re.MULTILINE)
            d = re.sub(r'(^[ \t]*[\w.-]+):(?!\s| )', r'\1: ', d, flags=re.MULTILINE)
            d = re.sub(r'([\w.-]+:[ \t]+)([^"\s\n][^#\n]*:[^#\n]*)', r'\1"\2"', d)
            d = d.replace('\t', '    ')

            try:
                parsed = yaml.load(d)
                if parsed:
                    buf = StringIO()
                    yaml.dump(parsed, buf)
                    healed_parts.append(buf.getvalue().strip())
            except Exception:
                healed_parts.append(d.strip())

        healed_final = "---\n" + "\n---\n".join(healed_parts) + "\n"

        diff = list(difflib.unified_diff(
            original_content.splitlines(),
            healed_final.splitlines(),
            fromfile='Current',
            tofile='Healed',
            lineterm=''
        ))

        print(f"\n🩺 [DIAGNOSTIC REPORT] File: {file_path}")
        print("=" * 60)
        
        if not diff:
            print("✔ Manifest is already healthy. No changes required.")
            return False
        else:
            for line in diff:
                if line.startswith('+') and not line.startswith('+++'):
                    print(f"\033[92m{line}\033[0m")
                elif line.startswith('-') and not line.startswith('---'):
                    print(f"\033[91m{line}\033[0m")
            
            with open(file_path, 'w') as f:
                f.write(healed_final)
            
            print("=" * 60)
            print(f"SUCCESS: Configuration file '{file_path}' has been healed.")
            return True

    except Exception as e:
        print(f"\n[CRITICAL ERROR] Auto-heal failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print("Usage: healer.py <filename.yaml>")
    else:
        linter_engine(sys.argv[1])
