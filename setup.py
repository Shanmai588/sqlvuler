#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="sqlvuler",
    version="1.0.0",
    author="AduDev",
    author_email="educational@todo.com",
    description="SQL Injection Vulnerability Scanner for Educational Purposes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/todo",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sqlvuler=sqlvuler.sqlvuler:main",
        ],
    },
)
