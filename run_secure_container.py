#!/usr/bin/env python3
import subprocess
import argparse
import os
import sys
import signal
import time
from src.utils.url_validator import URLValidator


class DockerManager:
    """
    Docker container manager for secure analysis
    """

    def __init__(self, image_name="sandbox-mitm"):
        """
        Initializes the Docker container manager.

        :param image_name: Name of the Docker image to use
        :type image_name: str
        """
        self.image_name = image_name
        self.container_id = None

    def build_docker_image(self, dockerfile_path="docker/Dockerfile", force_rebuild=False):
        """
        Builds or updates the Docker image.

        :param dockerfile_path: Path to the Dockerfile
        :type dockerfile_path: str
        :param force_rebuild: Force rebuild even if image exists
        :type force_rebuild: bool
        :return: True if build succeeds, False otherwise
        :rtype: bool
        """
        try:
            # Check if image already exists
            check_cmd = ["docker", "images", "-q", self.image_name]
            image_check = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if not force_rebuild and image_check.stdout.strip():
                print(f"[INFO] Docker image {self.image_name} already exists")
                return True

            # Build the image
            print(f"[INFO] Building Docker image: {self.image_name}")
            build_cmd = ["docker", "build", "-t", self.image_name, "-f", dockerfile_path, "."]
            result = subprocess.run(build_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode != 0:
                print(f"[ERROR] Docker image build failed: {result.stderr}")
                return False

            print(f"[INFO] Docker image {self.image_name} built successfully")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to build Docker image: {e}")
            return False

    def run_secure_container(self, url, timeout=60):
        """
        Launches a secure Docker container with multiple restrictions.

        :param url: URL to analyze
        :type url: str
        :param timeout: Timeout in seconds
        :type timeout: int
        :return: Container's stdout and stderr
        :rtype: tuple(str, str)
        """
        # Unique identifier for this container
        self.container_id = f"url-analysis-{os.getpid()}-{int(time.time())}"

        # Get the path to the src directory
        src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")

        print(f"[INFO] Preparing analysis of: {url}")

        # Secure Docker command
        command = [
            "docker", "run", "--rm",

            # Read-only filesystem
            "--read-only",

            # Temporary filesystems with limited permissions (RAM)
            "--tmpfs", "/tmp:rw,noexec,nosuid,uid=10000,gid=10000,size=50m",
            "--tmpfs", "/home/sandboxuser/tmp:rw,noexec,nosuid,uid=10000,gid=10000,size=256m",
            "--tmpfs", "/home/sandboxuser/logs:rw,noexec,nosuid,uid=10000,gid=10000,size=50m",
            "--tmpfs", "/home/sandboxuser/workdir:rw,noexec,nosuid,uid=10000,gid=10000,size=10m",

            # Capability and security restrictions
            "--cap-drop=ALL",  # No system capabilities
            "--security-opt", "no-new-privileges",  # No privilege escalation
            # "--security-opt", "seccomp=unconfined",  # Required for Chrome/Chromium

            # Resource limits
            "--pids-limit=100",  # Process limit
            "--memory=1g",  # Memory limited to 1GB
            "--memory-swap=1g",  # No swap
            "--cpus=1.5",  # Limited CPU

            # Ulimits: restrict number of open files and processes
            "--ulimit", "nofile=1024:1024",  # Max 1024 open files
            "--ulimit", "nproc=100:100",  # Max 100 processes/threads

            # Network configuration
            "--network=bridge",  # Isolated Docker network
            "--publish", "127.0.0.1:8080:8080",  # Expose only mitmproxy on localhost

            # Container naming
            "--name", self.container_id,

            # Chrome configuration
            "--shm-size=256m",  # Shared memory for Chrome

            # Mount src directory in read-only mode
            "-v", f"{src_path}:/home/sandboxuser/src:ro",

            # Pass URL as environment variable
            "-e", f"TARGET_URL={url}",

            # Image to use
            self.image_name
        ]

        try:
            # Execute command and capture stdout and stderr
            print(f"[INFO] Launching analysis in isolated container...")
            print(f"[INFO] Container ID: {self.container_id}")

            # Configure interrupt signal handler
            original_sigint = signal.getsignal(signal.SIGINT)

            def sigint_handler(sig, frame):
                print("\n[INFO] Received interrupt signal, stopping container...")
                self.kill_container()
                signal.signal(signal.SIGINT, original_sigint)
                sys.exit(1)

            signal.signal(signal.SIGINT, sigint_handler)

            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    timeout=timeout)

            # Restore signal handler
            signal.signal(signal.SIGINT, original_sigint)

            return result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            print(f"[ERROR] Analysis timed out after {timeout} seconds")
            self.kill_container()
            return "", f"Analysis timed out after {timeout} seconds"
        except Exception as e:
            print(f"[ERROR] Error during container execution: {e}")
            self.kill_container()
            return "", str(e)

    def kill_container(self):
        """
        Forcefully stops and removes the container.

        :return: True if stop succeeds, False otherwise
        :rtype: bool
        """
        if not self.container_id:
            return True

        try:
            # Check if container exists
            check_cmd = ["docker", "ps", "-a", "--filter", f"name={self.container_id}", "--format", "{{.ID}}"]
            container_check = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if container_check.stdout.strip():
                print(f"[INFO] Cleaning up container {self.container_id}")
                kill_cmd = ["docker", "rm", "-f", self.container_id]
                subprocess.run(kill_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True

            return True
        except Exception as e:
            print(f"[ERROR] Failed to kill container: {e}")
            return False


def parse_and_format_output(stdout, stderr):
    """
    Parses and formats container output.

    :param stdout: Container's stdout
    :type stdout: str
    :param stderr: Container's stderr
    :type stderr: str
    :return: List of formatted results
    :rtype: list
    """
    # Tags to filter in logs
    tags = ["[INFO]", "[URL]", "[TITLE]", "[WARNING]", "[SSL]", "[ERROR]", "[CRITICAL]", "[DEBUG]"]

    # Filter relevant lines
    output_lines = []
    for line in stdout.splitlines():
        if any(tag in line for tag in tags):
            print(line)
            output_lines.append(line)

    # Display Docker errors if any
    # if stderr and "ImportError: cannot import name 'url_quote'" not in stderr:
    #     print("\n[DOCKER ERROR]")
    #     print(stderr)

    return output_lines


def save_report(url, output_lines, output_dir="."):
    """
    Saves the analysis report.

    :param url: URL analyzed
    :type url: str
    :param output_lines: Output lines
    :type output_lines: list
    :param output_dir: Output directory
    :type output_dir: str
    :return: Report path
    :rtype: str
    """
    # Create output directory if needed
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Clean URL for filename
    clean_url = url.replace('://', '_').replace('/', '_').replace('?', '_').replace('&', '_')
    report_path = os.path.join(output_dir, f"report_{clean_url}.txt")

    # Write report
    with open(report_path, 'w') as f:
        f.write(f"Analysis Report for {url}\n")
        f.write("=" * 50 + "\n")
        f.write("\n".join(output_lines))

    return report_path


def main():
    """
    Main function to run the URL security analysis.

    :return: Exit code
    :rtype: int
    """
    parser = argparse.ArgumentParser(description='Secure analysis of potentially malicious URLs')

    # Optional URL parameter (required only for analysis, not for build)
    parser.add_argument('url', nargs='?', help='URL to analyze (example: https://example.com)')

    # Build options
    build_group = parser.add_mutually_exclusive_group()
    build_group.add_argument('--build-image', action='store_true', help='Build Docker image for first use')
    build_group.add_argument('--rebuild-image', action='store_true', help='Force rebuild of existing Docker image')

    # Other options
    parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds for analysis (default: 60)')
    parser.add_argument('--output-dir', default="reports", help='Output directory for reports (default: reports)')

    args = parser.parse_args()

    # Check if we're building/rebuilding or analyzing
    is_building = args.build_image or args.rebuild_image

    # URL is required for analysis but not for build
    if not is_building and not args.url:
        parser.error("URL is required unless --build-image or --rebuild-image is specified")
        return 1

    # Initialize Docker manager
    docker_manager = DockerManager()

    try:
        # If we're just building the image
        if is_building:
            force_rebuild = args.rebuild_image
            print(f"[INFO] {'Rebuilding' if force_rebuild else 'Building'} Docker environment...")

            if docker_manager.build_docker_image(force_rebuild=force_rebuild):
                print("[INFO] Docker image ready for use!")
                return 0
            else:
                print("[ERROR] Failed to prepare Docker environment")
                return 1

        # For analysis, validate the URL
        validator = URLValidator()
        if not validator.is_valid_basic(args.url):
            print(f"[ERROR] Invalid URL format: {args.url}")
            print("[INFO] URL must start with http:// or https:// and contain a valid domain")
            return 1

        # Check if Docker image exists, build if needed
        if not docker_manager.build_docker_image(force_rebuild=False):
            print("[ERROR] Failed to prepare Docker environment")
            return 1

        # Run analysis in secure container
        stdout, stderr = docker_manager.run_secure_container(args.url, args.timeout)

        # Parse and format output
        output_lines = parse_and_format_output(stdout, stderr)

        # Save report
        report_path = save_report(args.url, output_lines, args.output_dir)
        print(f"[INFO] Report saved to {report_path}")

        return 0

    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return 1
    finally:
        # Cleanup
        if 'docker_manager' in locals() and hasattr(docker_manager, 'kill_container'):
            docker_manager.kill_container()


if __name__ == "__main__":
    sys.exit(main())