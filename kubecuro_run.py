import sys
import os

# 1. Get the directory where this script is located
base_path = os.path.dirname(os.path.abspath(__file__))

# 2. Add the 'src/kubecuro' path so Python can find main.py, healer.py, etc.
sys.path.insert(0, os.path.join(base_path, 'src', 'kubecuro'))

# 3. PyInstaller support: look inside the internal bundle if running as a binary
if getattr(sys, 'frozen', False):
    sys.path.insert(0, sys._MEIPASS)

from main import run

if __name__ == "__main__":
    run()
