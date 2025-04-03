import re
from selenium.webdriver.common.by import By

class ScriptAnalyzer:
    """
    JavaScript analyzer to detect malicious behaviors
    such as obfuscation, forced redirects, and automatic downloads.
    """
    
    def __init__(self, driver):
        """
        Initializes the analyzer with the Selenium driver.
        
        :param driver: Initialized Selenium WebDriver
        :type driver: WebDriver
        """
        self.driver = driver
        self.results = []

    def analyze(self):
        """
        Executes all script analyses.

        :return: List of analysis results
        :rtype: list
        """
        try:
            self.detect_auto_downloads()
            self.analyze_inline_scripts()
        except Exception as e:
            result = {
                "level": "ERROR",
                "message": f"Error during script analysis: {e}"
            }
            self.results.append(result)
            print(f"[{result['level']}] {result['message']}")

        return self.results

    def detect_auto_downloads(self):
        """
        Detects scripts that attempt to trigger automatic downloads.

        :return: None (results are stored in self.results)
        :rtype: None
        """
        page_source = self.driver.page_source

        # Patterns for automatic downloads and forced redirects
        auto_download_patterns = [
            r'window\.location\s*=\s*([\'"]).*\.exe[\'"1]',
            r'document\.location\s*=\s*([\'"]).*\.(exe|zip|msi|bat|ps1|dat)[\'"1]',
            r'\.download\s*\(',
            r'\.saveAs\s*\(',
            r'navigator\.msSaveBlob',
            r'<meta\s+http-equiv=[\'"]refresh[\'"].*url=.*\.(exe|zip|msi|bat|dat)',
            r'location\.replace\([\'"].*\.(exe|zip|msi|bat|dat)[\'"]'
        ]

        for pattern in auto_download_patterns:
            matches = re.findall(pattern, page_source)
            if matches:
                result = {
                    "level": "CRITICAL",
                    "message": f"Automatic download attempt detected! Pattern: {pattern}"
                }
                self.results.append(result)
                print(f"[{result['level']}] {result['message']}")

    def analyze_inline_scripts(self):
        """
        Analyzes inline scripts to detect obfuscation behaviors.

        :return: None (results are stored in self.results)
        :rtype: None
        """
        scripts = self.driver.find_elements(By.XPATH, "//script[not(@src)]")
        for script in scripts:
            try:
                script_content = script.get_attribute("innerHTML")
                script_length = len(script_content)

                # Only analyze larger scripts
                if script_length > 1000:
                    # Calculate entropy to detect obfuscation (simplified approach)
                    char_count = {}
                    for char in script_content:
                        if char in char_count:
                            char_count[char] += 1
                        else:
                            char_count[char] = 1

                    # If the script contains many unusual characters, it's suspicious
                    unusual_chars = sum(1 for char, count in char_count.items()
                                        if
                                        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_. (){}[]:;,\"'=-+*/\\")

                    if unusual_chars > 100:
                        result = {
                            "level": "CRITICAL",
                            "message": f"Highly obfuscated script detected with {unusual_chars} unusual characters"
                        }
                        self.results.append(result)
                        print(f"[{result['level']}] {result['message']}")

                    # Detection of nested evals (highly suspicious)
                    if re.search(r'eval\s*\(\s*eval', script_content) or re.search(r'eval\s*\(\s*atob', script_content):
                        result = {
                            "level": "CRITICAL",
                            "message": f"Nested eval detected - strong indicator of malicious code"
                        }
                        self.results.append(result)
                        print(f"[{result['level']}] {result['message']}")
            except Exception:
                continue
