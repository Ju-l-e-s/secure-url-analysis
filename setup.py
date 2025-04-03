from setuptools import setup, find_packages

setup(
    name="secure-url-analysis",
    version="1.0.0",
    description="Tool for secure analysis of potentially malicious URLs",
    author="Jules",
    author_email="myemail@example.com",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "selenium>=4.0.0",
        "mitmproxy>=8.0.0",
        "tldextract>=3.1.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "secure-url-analyze=run_secure_container:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
)
