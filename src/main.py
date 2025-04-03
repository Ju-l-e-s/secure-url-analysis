import os
import sys
import time
import argparse
from typing import List, Dict, Any, Optional

try:
    from .analyzers.ssl_analyzer import SSLAnalyzer
    from .analyzers.dom_analyzer import DomAnalyzer
    from .analyzers.script_analyzer import ScriptAnalyzer
    from .utils.browser_manager import BrowserManager
    from .utils.report_generator import ReportGenerator
except ImportError:
    # For when run as a standalone script
    from analyzers.ssl_analyzer import SSLAnalyzer
    from analyzers.dom_analyzer import DomAnalyzer
    from analyzers.script_analyzer import ScriptAnalyzer
    from utils.browser_manager import BrowserManager
    from utils.report_generator import ReportGenerator


class URLAnalyzer:
    """
    Main class that coordinates the different analyses of a URL
    """

    def __init__(self, url: str, timeout: int = 60, output_dir: str = "."):
        """
        Initializes the URL analyzer.

        :param url: URL to analyze
        :type url: str
        :param timeout: Timeout in seconds for analysis
        :type timeout: int
        :param output_dir: Output directory for reports
        :type output_dir: str
        """
        self.url = url
        self.timeout = timeout
        self.output_dir = output_dir
        self.results: List[Dict[str, Any]] = []
        self.browser = BrowserManager(timeout=timeout)
        self.report_generator = ReportGenerator(url)

    def run_analysis(self) -> bool:
        """
        Runs the complete analysis of the URL.

        :return: True if analysis succeeded, False otherwise
        :rtype: bool
        """
        print(f"[INFO] Starting analysis of {self.url}")
        start_time = time.time()

        try:
            # 1. Analyze SSL/TLS certificate
            print("[INFO] Analyzing SSL/TLS certificate...")
            ssl_analyzer = SSLAnalyzer(self.url)
            ssl_results = ssl_analyzer.analyze()
            self.results.extend(ssl_results)

            # 2. Initialize browser
            print("[INFO] Initializing browser...")
            if not self.browser.initialize_browser():
                self.results.append({
                    "level": "ERROR",
                    "message": "Failed to initialize browser. Check Docker configuration."
                })
                return False

            # 3. Load URL
            print(f"[INFO] Loading URL: {self.url}")
            if not self.browser.load_url(self.url):
                self.results.append({
                    "level": "ERROR",
                    "message": f"Failed to load URL: {self.url}"
                })
                # Continue anyway with certificate analysis

            # 5. DOM analyzer
            print("[INFO] Analyzing DOM elements...")
            dom_analyzer = DomAnalyzer(self.browser.driver, self.url)
            dom_results = dom_analyzer.analyze()
            self.results.extend(dom_results)

            # 6. Script analyzer
            print("[INFO] Analyzing scripts...")
            script_analyzer = ScriptAnalyzer(self.browser.driver)
            script_results = script_analyzer.analyze()
            self.results.extend(script_results)

            # 7. Generate report directly to console
            self.report_generator.add_results(self.results)
            report_text = self.report_generator.format_text_report()
            print(report_text)

            # 8. Add timing information
            elapsed_time = time.time() - start_time
            self.results.append({
                "level": "INFO",
                "message": f"Analysis completed in {elapsed_time:.2f} seconds"
            })

            # Add test completion message
            print("[INFO] Test completed. The site has been analyzed for critical security threats.")

            return True

        except Exception as e:
            self.results.append({
                "level": "ERROR",
                "message": f"Analysis failed with exception: {e}"
            })
            return False

        finally:
            # Always clean up resources
            if hasattr(self, 'browser') and self.browser:
                self.browser.cleanup()

            print("[INFO] Analysis completed")

    def get_results(self) -> List[Dict[str, Any]]:
        """
        Gets the analysis results.

        :return: List of analysis results
        :rtype: List[Dict[str, Any]]
        """
        return self.results

    def print_results_summary(self) -> None:
        """
        Prints a summary of the results.

        :return: None
        :rtype: None
        """
        # Organize by severity level
        summary = {
            "CRITICAL": 0,
            "ERROR": 0,
            "WARNING": 0,
            "INFO": 0,
            "SSL": 0
        }

        for result in self.results:
            level = result.get("level", "INFO")
            if level in summary:
                summary[level] += 1

        print("\n=== ANALYSIS SUMMARY ===")
        for level, count in summary.items():
            if count > 0:
                print(f"{level}: {count}")

        # Determine overall risk level
        if summary["CRITICAL"] > 0:
            risk_level = "HIGH"
        elif summary["ERROR"] > 0 or summary["WARNING"] > 3:
            risk_level = "MEDIUM"
        elif summary["WARNING"] > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        print(f"\nOverall risk level: {risk_level}")


def main():
    """
    Main function for direct script execution
    """
    parser = argparse.ArgumentParser(description='URL Security Analyzer')
    parser.add_argument('url', help='URL to analyze (e.g., https://example.com)')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds (default: 60)')
    parser.add_argument('--output-dir', default="/home/sandboxuser/workdir",
                        help='Output directory (default: /home/sandboxuser/workdir)')

    args = parser.parse_args()

    print(f"[INFO] Starting analysis of {args.url}")
    start_time = time.time()

    try:
        # Create analyzer instance
        analyzer = URLAnalyzer(url=args.url, timeout=args.timeout, output_dir=args.output_dir)

        # Run the analysis
        success = analyzer.run_analysis()

        # Print summary
        analyzer.print_results_summary()

        elapsed_time = time.time() - start_time
        print(f"[INFO] Total analysis completed in {elapsed_time:.2f} seconds")

        # Exit with appropriate status code
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[CRITICAL] Main analysis script error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()