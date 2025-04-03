import ssl
import socket
from datetime import datetime


class SSLAnalyzer:
    """
    Analyzer for SSL/TLS certificates of websites.
    Checks validity, issuer, and expiration of certificates.
    """

    # List of well-known and trusted certificate authorities
    TRUSTED_CAS = [
        "Let's Encrypt", "DigiCert", "GeoTrust", "Comodo", "GlobalSign",
        "Thawte", "RapidSSL", "Sectigo", "Google Trust Services", "Amazon",
        "Microsoft", "Apple", "Symantec", "GoDaddy", "Entrust", "IdenTrust",
        "Network Solutions", "VISA", "Verizon", "Trustwave"
    ]

    def __init__(self, url):
        """
        Initializes the analyzer with the URL to check.

        :param url: The complete URL to analyze
        :type url: str
        """
        self.url = url
        self.hostname = url.split("//")[-1].split("/")[0]
        self.results = []

    def analyze(self):
        """
        Performs the SSL/TLS certificate analysis.

        :return: List of analysis results
        :rtype: list
        """
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
                s.settimeout(5)
                s.connect((self.hostname, 443))
                cert = s.getpeercert()

            # Check expiration date
            expire_date = cert['notAfter']
            expire_date_obj = datetime.strptime(expire_date, "%b %d %H:%M:%S %Y GMT")
            current_time = datetime.utcnow()
            days_until_expiry = (expire_date_obj - current_time).days

            if days_until_expiry < 30:
                result = {
                    "level": "WARNING",
                    "message": f"Certificate expires soon: {expire_date} (in {days_until_expiry} days)"
                }
                self.results.append(result)
                print(f"[{result['level']}] {result['message']}")
            else:
                result = {
                    "level": "SSL",
                    "message": f"Valid certificate for {self.hostname}, expires: {expire_date}"
                }
                self.results.append(result)
                print(f"[{result['level']}] {result['message']}")

            # Check certificate authority
            issuer = dict(x[0] for x in cert['issuer'])
            org_name = issuer.get('organizationName', 'Unknown')

            if org_name not in self.TRUSTED_CAS:
                result = {
                    "level": "WARNING",
                    "message": f"Certificate issued by less common authority: {org_name}"
                }
                self.results.append(result)
                print(f"[{result['level']}] {result['message']}")
            else:
                result = {
                    "level": "SSL",
                    "message": f"Certificate issued by trusted authority: {org_name}"
                }
                self.results.append(result)
                print(f"[{result['level']}] {result['message']}")

        except Exception as e:
            result = {
                "level": "WARNING",
                "message": f"SSL/TLS certificate issue: {e}"
            }
            self.results.append(result)
            print(f"[{result['level']}] {result['message']}")

        return self.results