import os
import time
import shutil
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class BrowserManager:
    """
    Selenium browser manager for secure URL analysis
    """

    def __init__(self, timeout=30):
        """
        Initializes the browser manager with security options.

        :param timeout: Timeout in seconds for page loading
        :type timeout: int
        """
        self.timeout = timeout
        self.driver = None
        self.user_data_dir = None

    def setup_chrome_options(self):
        """
        Configures Chrome options for secure analysis.

        :return: Configured Chrome options
        :rtype: Options
        """
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-popup-blocking")
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--window-size=1366,768")
        chrome_options.add_argument("--disable-setuid-sandbox")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--disable-dev-tools")
        chrome_options.add_argument("--single-process")
        chrome_options.add_argument("--disable-application-cache")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_argument(
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

        # Set Chrome/Chromium binary location
        chrome_options.binary_location = "/usr/bin/chromium"

        # Create and configure a specific temporary directory for user data
        self.user_data_dir = os.path.expanduser("~/tmp/chrome_data_" + str(int(time.time())))
        if not os.path.exists(self.user_data_dir):
            os.makedirs(self.user_data_dir)
        chrome_options.add_argument(f"--user-data-dir={self.user_data_dir}")

        return chrome_options

    def initialize_browser(self):
        """
        Initializes the browser with security options.

        :return: True if initialization succeeds, False otherwise
        :rtype: bool
        """
        try:
            chrome_options = self.setup_chrome_options()
            service = Service(executable_path="/usr/bin/chromedriver")
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
            return True
        except Exception as e:
            print(f"[ERROR] Browser initialization failed: {e}")
            return False

    def load_url(self, url):
        """
        Loads the specified URL in the browser with error handling.

        :param url: URL to load
        :type url: str
        :return: True if loading succeeds (at least partially), False otherwise
        :rtype: bool
        """
        if not self.driver:
            return False

        try:
            print(f"[INFO] Starting browser for {url}")
            print(f"[INFO] Accessing: {url}")
            start_time = time.time()

            # Load the page with error handling
            self.driver.get(url)

            try:
                # Wait for body to load, but continue even if timeout
                WebDriverWait(self.driver, 15).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except Exception as e:
                print(f"[WARNING] Page load warning (will continue analysis): {e}")

            # Wait a bit more for scripts to load
            time.sleep(3)

            return True
        except Exception as e:
            print(f"[ERROR] Failed to load URL: {e}")
            return False

    def get_page_source(self):
        """
        Gets the source code of the current page.

        :return: Page source code or None on error
        :rtype: str or None
        """
        if not self.driver:
            return None

        try:
            return self.driver.page_source
        except Exception:
            return None

    def get_current_url(self):
        """
        Gets the current URL after possible redirections.

        :return: Current URL or None on error
        :rtype: str or None
        """
        if not self.driver:
            return None

        try:
            return self.driver.current_url
        except Exception:
            return None

    def cleanup(self):
        """
        Cleans up resources (browser, temporary directories).

        :return: True if cleanup succeeds, False otherwise
        :rtype: bool
        """
        success = True

        # Close the browser
        try:
            if self.driver:
                self.driver.quit()
                print("[INFO] Browser closed successfully")
        except Exception as e:
            print(f"[ERROR] Failed to close browser: {e}")
            success = False

        # Delete the temporary directory
        try:
            if self.user_data_dir and os.path.exists(self.user_data_dir):
                shutil.rmtree(self.user_data_dir)
                print(f"[INFO] Cleaned up temporary directory")
        except Exception as e:
            print(f"[ERROR] Failed to clean up temporary directory: {e}")
            success = False

        return success