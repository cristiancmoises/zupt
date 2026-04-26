#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="zupt-gui",
    version="1.0.0",
    description="Zupt GUI — Cross-Platform Post-Quantum Backup Utility",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Cristian Cezar Moisés",
    url="https://github.com/cristiancmoises/zupt",
    license="AGPL-3.0-or-later",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    py_modules=["zupt_gui"],
    python_requires=">=3.9",
    install_requires=["PySide6>=6.5"],
    entry_points={
        "console_scripts": ["zupt-gui=zupt_gui:main"],
        "gui_scripts": ["zupt-gui=zupt_gui:main"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: X11 Applications :: Qt",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Archiving :: Compression",
    ],
)
