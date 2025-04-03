import re

class URLValidator:
    """
    URL validator with different levels of verification
    """
    
    @staticmethod
    def is_valid_basic(url):
        """
        Basic URL validation to prevent command injections.
        
        :param url: URL to validate
        :type url: str
        :return: True if the URL is valid, False otherwise
        :rtype: bool
        """
        url_pattern = re.compile(
            r'^https?://[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](:[0-9]+)?(/[-a-zA-Z0-9_.~:/?#[\]@!$&\'()*+,;=]*)?$')
        return bool(url_pattern.match(url))
    
    @staticmethod
    def is_valid_advanced(url):
        """
        More permissive URL validation, accepting international characters
        and more complex but still valid formats.
        
        :param url: URL to validate
        :type url: str
        :return: True if the URL is valid, False otherwise
        :rtype: bool
        """
        try:
            # More permissive version, compatible with IDN and special characters
            from urllib.parse import urlparse
            
            # Basic checks
            if not url.startswith(('http://', 'https://')):
                return False
            
            # Use urlparse to check the structure
            parsed = urlparse(url)
            
            # Check that we have at least a hostname
            if not parsed.netloc:
                return False
                
            return True
        except:
            return False
    
    @staticmethod
    def clean_url_for_filename(url):
        """
        Cleans a URL to be used as a filename.
        
        :param url: URL to clean
        :type url: str
        :return: URL cleaned for use in a filename
        :rtype: str
        """
        return url.replace('://', '_').replace('/', '_').replace('?', '_').replace('&', '_')
