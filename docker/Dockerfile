# Use Python 3.9 slim as base image for smaller footprint
FROM python:3.9-slim

# Install minimal system dependencies
# Chromium and chromedriver are required for headless browser automation
# ca-certificates is needed for secure connections
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    ca-certificates \
    unzip \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install required Python libraries
# selenium: browser automation
# mitmproxy: HTTPS interception and analysis
# tldextract: domain name extraction and classification
RUN pip install --no-cache-dir selenium mitmproxy tldextract

# Create non-root user with high UID to limit privileges
# This is a security best practice for containerized applications
RUN useradd -u 10000 -m sandboxuser
WORKDIR /home/sandboxuser

# Create directories for temporary data and logs
# Set appropriate ownership to sandboxuser
RUN mkdir -p /home/sandboxuser/tmp /home/sandboxuser/logs /home/sandboxuser/workdir \
    && chown -R sandboxuser:sandboxuser /home/sandboxuser

# Copy minimal entrypoint script with restricted permissions
# The entrypoint is set to be executable only (500)
COPY docker/entrypoint.sh .
RUN chmod +x entrypoint.sh


# Switch to non-privileged user
USER sandboxuser

# Set the entrypoint script
ENTRYPOINT ["./entrypoint.sh"]