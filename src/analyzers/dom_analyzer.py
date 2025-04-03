import tldextract
from selenium.webdriver.common.by import By

# Configure tldextract to use a writable directory or disable caching
tldextract_cache_dir = '/home/sandboxuser/tmp/tldextract_cache'


class DomAnalyzer:
    """
    DOM analyzer to detect malicious behaviors in a web page
    (hidden iframes, phishing forms, etc.)
    """

    def __init__(self, driver, original_url):
        """
        Initializes the analyzer with Selenium driver and the original URL.

        :param driver: Initialized Selenium WebDriver
        :type driver: WebDriver
        :param original_url: Original URL being analyzed
        :type original_url: str
        """
        self.driver = driver
        self.original_url = original_url
        self.results = []

        # Extract base domain for comparisons
        # Use cache_dir=tldextract_cache_dir to avoid permission errors
        original_domain_info = tldextract.extract(original_url)
        self.original_base_domain = f"{original_domain_info.domain}.{original_domain_info.suffix}"

    def analyze(self):
        """
        Executes all DOM analyses.

        :return: List of analysis results
        :rtype: list
        """
        try:
            self.analyze_redirections()
            self.analyze_iframes()
            self.analyze_forms()
            self.analyze_download_links()
            self.analyze_external_scripts()
        except Exception as e:
            result = {
                "level": "ERROR",
                "message": f"Error during DOM analysis: {e}"
            }
            self.results.append(result)
            print(f"[{result['level']}] {result['message']}")

        return self.results

    def analyze_redirections(self):
        """
        Checks if the URL has been redirected to another domain.

        :return: None (results are stored in self.results)
        :rtype: None
        """
        final_url = self.driver.current_url

        # Configurer tldextract pour éviter l'erreur de cache
        final_domain_info = tldextract.extract(final_url)
        final_base_domain = f"{final_domain_info.domain}.{final_domain_info.suffix}"

        if final_base_domain != self.original_base_domain:
            result = {
                "level": "CRITICAL",
                "message": f"Cross-domain redirection detected: {self.original_base_domain} -> {final_base_domain}"
            }
            self.results.append(result)
            print(f"[{result['level']}] {result['message']}")
        elif final_url != self.original_url:
            result = {
                "level": "INFO",
                "message": f"Same-domain redirection: {self.original_url} -> {final_url}"
            }
            self.results.append(result)
            print(f"[{result['level']}] {result['message']}")

        # Add basic page information
        result = {
            "level": "INFO",
            "message": f"Final URL: {final_url}"
        }
        self.results.append(result)
        print(f"[{result['level']}] {result['message']}")

        result = {
            "level": "INFO",
            "message": f"Page title: {self.driver.title}"
        }
        self.results.append(result)
        print(f"[{result['level']}] {result['message']}")

    def analyze_iframes(self):
        """
        Detects potentially malicious iframes.

        :return: None (results are stored in self.results)
        :rtype: None
        """
        iframes = self.driver.find_elements(By.TAG_NAME, "iframe")
        for iframe in iframes:
            try:
                iframe_src = iframe.get_attribute("src")
                if not iframe_src:
                    continue

                iframe_style = iframe.get_attribute("style") or ""
                iframe_hidden = (
                        "display: none" in iframe_style or
                        "visibility: hidden" in iframe_style or
                        "opacity: 0" in iframe_style or
                        iframe.get_attribute("hidden") is not None
                )

                # Use cache_dir=tldextract_cache_dir to avoid permission errors
                iframe_domain_info = tldextract.extract(iframe_src)
                iframe_base_domain = f"{iframe_domain_info.domain}.{iframe_domain_info.suffix}"

                if iframe_base_domain != self.original_base_domain:
                    if iframe_hidden:
                        result = {
                            "level": "CRITICAL",
                            "message": f"Hidden iframe to external domain detected: {iframe_src}"
                        }
                        self.results.append(result)
                        print(f"[{result['level']}] {result['message']}")
                    else:
                        result = {
                            "level": "WARNING",
                            "message": f"Iframe to external domain: {iframe_src}"
                        }
                        self.results.append(result)
                        print(f"[{result['level']}] {result['message']}")
            except Exception:
                continue

    def analyze_forms(self):
        """
        Detects potential phishing forms.

        :return: None (results are stored in self.results)
        :rtype: None
        """
        forms = self.driver.find_elements(By.TAG_NAME, "form")
        for form in forms:
            try:
                # Check if form contains sensitive fields
                password_field = len(form.find_elements(By.XPATH, ".//input[@type='password']")) > 0
                credit_card_field = len(form.find_elements(By.XPATH,
                                                           ".//input[contains(@name, 'card') or contains(@id, 'card') or contains(@placeholder, 'card')]")) > 0

                if password_field or credit_card_field:
                    # Check form destination
                    action = form.get_attribute("action") or ""

                    if action.startswith("http"):
                        # Use cache_dir=tldextract_cache_dir to avoid permission errors
                        form_domain_info = tldextract.extract(action)
                        form_base_domain = f"{form_domain_info.domain}.{form_domain_info.suffix}"

                        if form_base_domain != self.original_base_domain:
                            form_type = "password" if password_field else "credit card"
                            result = {
                                "level": "CRITICAL",
                                "message": f"Possible phishing: {form_type} form submits to external domain: {action}"
                            }
                            self.results.append(result)
                            print(f"[{result['level']}] {result['message']}")
                    elif password_field:
                        result = {
                            "level": "INFO",
                            "message": f"Password form detected with action: {action}"
                        }
                        self.results.append(result)
                        print(f"[{result['level']}] {result['message']}")
            except Exception:
                continue

    def analyze_download_links(self):
        """
        Detects suspicious download links.

        :return: None (results are stored in self.results)
        :rtype: None
        """
        links = self.driver.find_elements(By.TAG_NAME, "a")
        high_risk_extensions = [".exe", ".msi", ".bat", ".ps1", ".scr", ".vbs", ".pif", ".hta",".dat"]

        # Debug: ajouter le nombre de liens trouvés
        print(f"[DEBUG] Found {len(links)} links on page")

        for link in links:
            try:
                href = link.get_attribute("href")
                if not href:
                    continue

                if any(href.lower().endswith(ext) for ext in high_risk_extensions):
                    result = {
                        "level": "CRITICAL",
                        "message": f"Executable download link detected: {href}"
                    }
                    self.results.append(result)
                    print(f"[{result['level']}] {result['message']}")
                elif ".zip" in href.lower() or ".rar" in href.lower():
                    result = {
                        "level": "WARNING",
                        "message": f"Archive download link: {href}"
                    }
                    self.results.append(result)
                    print(f"[{result['level']}] {result['message']}")
            except Exception as e:
                # Debug: signaler les erreurs lors de l'analyse des liens
                print(f"[DEBUG] Error analyzing link: {e}")

    def analyze_external_scripts(self):
        """
        Analyzes external scripts to detect suspicious domains.

        :return: None (results are stored in self.results)
        :rtype: None
        """
        external_scripts = self.driver.find_elements(By.XPATH, "//script[@src]")
        for script in external_scripts:
            try:
                script_src = script.get_attribute("src")
                if not script_src:
                    continue

                # Use cache_dir=tldextract_cache_dir to avoid permission errors
                script_domain_info = tldextract.extract(script_src)
                script_base_domain = f"{script_domain_info.domain}.{script_domain_info.suffix}"

                if script_base_domain != self.original_base_domain:
                    result = {
                        "level": "INFO",
                        "message": f"External script from domain: {script_base_domain}"
                    }
                    self.results.append(result)
                    print(f"[{result['level']}] {result['message']}")

                    # Additional check for highly suspicious domains
                    suspicious_domains = ['clickjacking', 'malware', 'exploit', 'phish', 'hack']
                    if any(s in script_base_domain for s in suspicious_domains):
                        result = {
                            "level": "CRITICAL",
                            "message": f"Highly suspicious external script domain: {script_src}"
                        }
                        self.results.append(result)
                        print(f"[{result['level']}] {result['message']}")
            except Exception:
                continue