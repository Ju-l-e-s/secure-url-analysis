# Secure URL Analysis Tool

A containerized solution for safely analyzing potentially malicious URLs without risking your host system integrity.

## Overview

This tool provides a secure sandbox environment based on Docker to analyze suspicious URLs. It lets you inspect websites for malicious behavior while protecting your system through multiple layers of isolation and security controls.

## ⚠️ Security Recommendation

**Always use a VPN or proxy when analyzing suspicious URLs.** Even though this tool runs analysis inside an isolated container, your IP address will still be exposed to the target website. Use a VPN or proxy service to protect your identity and location when investigating potentially malicious sites.

## Features

- **Isolated Analysis**: Runs all tests within a locked-down Docker container
- **ARM Architecture Compatible**: Optimized for Apple Silicon (M-series) Macs
- **Multiple Security Layers**: Read-only filesystem, non-privileged user, resource limits, etc.
- **Advanced Detection**: Identifies cross-domain redirections, automatic downloads, phishing forms, and more
- **SSL Certificate Verification**: Checks certificate validity and trustworthiness
- **Detailed Reporting**: Generates clear, actionable reports with threat severity classification
- **Modular Architecture**: Makes it easy to extend with new analyzers

## Project Structure

```
secure-url-analysis/
├── docker/
│   ├── Dockerfile
│   └── entrypoint.sh
├── src/
│   ├── analyzers/
│   │   ├── ssl_analyzer.py
│   │   ├── dom_analyzer.py
│   │   └── script_analyzer.py
│   ├── utils/
│   │   ├── browser_manager.py
│   │   ├── url_validator.py
│   │   └── report_generator.py
│   └── main.py
├── tests/
│   └── test_isolation.py
├── requirements.txt
├── setup.py
├── run_secure_container.py
└── README.md
```

## Requirements

- Docker Desktop for Mac (compatible with Apple Silicon)
- Python 3.8+
- Internet connection for container building and URL analysis
- VPN or proxy service (recommended for anonymous analysis)

## Installation and Usage

### First-time Setup

1. Clone this repository:
```bash
git clone https://github.com/Ju-l-e-s/secure-url-analysis.git
cd secure-url-analysis
```

2. Create a virtual environment (recommended):
```bash
# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Build the Docker image:
```bash
# Build Docker image (first-time use)
python3 run_secure_container.py --build-image
```

### Analyzing URLs

Once the setup is complete, you can analyze URLs:

```bash
# Basic URL analysis
python3 run_secure_container.py https://example.com

# Analysis with custom timeout (in seconds)
python3 run_secure_container.py https://suspicious-site.com --timeout 90

# Analysis with custom output directory
python3 run_secure_container.py https://example.com --output-dir my-reports
```

### Rebuilding the Docker Image

If you need to rebuild the Docker image (after Dockerfile changes):

```bash
python3 run_secure_container.py --rebuild-image
```

## Understanding Results

Reports classify threats with these levels:
- **[CRITICAL]** - High-risk threats requiring immediate attention
- **[WARNING]** - Suspicious behavior that might indicate malicious activity
- **[INFO]** - Contextual information about the site

Critical alerts include:
- Cross-domain redirections
- Executable download attempts
- Hidden iframes to external domains
- Phishing forms submitting to external domains

## Security Testing

To verify the isolation of your analysis environment:

```bash
# Run the isolation test
docker run --rm --entrypoint python3 -v $(pwd)/tests:/home/sandboxuser/tests sandbox-mitm /home/sandboxuser/tests/test_isolation.py

```

This script will check several aspects of container isolation:
- Filesystem write protection
- Process execution restrictions
- Network access controls
- Privilege escalation protections
- Linux capabilities restrictions

## Customization

To modify detection patterns or add new checks:

1. Create a new analyzer in the `src/analyzers/` directory
2. Implement the `analyze()` method that returns a list of results
3. Integrate your analyzer in the `src/main.py` file

Example of a new analyzer:

```python
class CustomAnalyzer:
    def __init__(self, driver):
        self.driver = driver
        self.results = []
    
    def analyze(self):
        # Your custom analysis logic here
        return self.results
```