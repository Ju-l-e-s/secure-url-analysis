#!/bin/bash
# This entrypoint script manages the analysis environment inside the container

cleanup() {
    echo "[INFO] Cleaning up logs and workdir..."
    rm -rf /home/sandboxuser/workdir/*
    rm -rf /home/sandboxuser/logs/*
    echo "[INFO] Logs and workdir cleaned up"
}
trap cleanup EXIT INT TERM

echo "[INFO] Starting mitmproxy proxy server..."
mitmproxy --mode regular --listen-port 8080 --set console_eventlog_verbosity=debug --set console_output_verbosity=error >/dev/null 2>&1 &

# Wait for mitmproxy to be fully operational
sleep 5

echo "[INFO] Starting URL analysis..."
if [ -z "$TARGET_URL" ]; then
    if [ "$#" -gt 0 ]; then
        URL="$1"
    else
        echo "[ERROR] No URL provided. Please set TARGET_URL environment variable or provide URL as argument"
        exit 1
    fi
else
    URL="$TARGET_URL"
fi

echo "[INFO] Using modular analysis structure"
python3 -m src.main "$URL"
ANALYSIS_STATUS=$?

if [ $ANALYSIS_STATUS -eq 0 ]; then
    echo "[INFO] Analysis completed successfully"
else
    echo "[ERROR] Analysis completed with errors (status code: $ANALYSIS_STATUS)"
fi

exit $ANALYSIS_STATUS
