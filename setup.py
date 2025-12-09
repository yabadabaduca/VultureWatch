"""Setup do VultureWatch"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vulturewatch",
    version="1.0.0",
    author="VultureWatch Team",
    description="Monitoramento de CVEs críticas com exploits públicos",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "pyyaml>=6.0.1",
        "python-dotenv>=1.0.0",
        "slack-sdk>=3.27.0",
        "python-telegram-bot>=20.7",
        "sqlalchemy>=2.0.23",
        "schedule>=1.2.0",
        "beautifulsoup4>=4.12.2",
        "lxml>=4.9.3",
    ],
    entry_points={
        "console_scripts": [
            "vulturewatch=vulturewatch.main:main",
        ],
    },
)

