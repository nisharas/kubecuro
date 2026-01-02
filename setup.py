import os
from setuptools import setup, find_packages

setup(
    name="kubecuro",
    version="1.0.0",
    author="Nishar A Sunkesala",
    author_email="fixmyk8s@protonmail.com", 
    description="The logic-based diagnostic engine for Kubernetes manifests.",
    long_description=open("README.md").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    package_dir={"": "src"}, 
    # find_packages will now pick up both 'kubecuro' and 'utils'
    packages=find_packages(where="src"),
    install_requires=[
        "ruamel.yaml>=0.17.0",
        "rich>=12.0.0",
        "tabulate>=0.8.1",
    ],
    entry_points={
        "console_scripts": [
            # This matches your src/kubecuro/main.py:run() function
            "kubecuro=kubecuro.main:run", 
        ],
    },
    include_package_data=True,
    python_requires=">=3.7",
)
