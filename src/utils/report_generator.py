from datetime import datetime


class ReportGenerator:
    """
    Report generator for URL security analyses
    """

    def __init__(self, url, results=None):
        """
        Initializes the report generator.

        :param url: URL that was analyzed
        :type url: str
        :param results: List of analysis results (optional)
        :type results: list or None
        """
        self.url = url
        self.results = results or []
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def add_results(self, results):
        """
        Adds analysis results to the report.

        :param results: List of results to add
        :type results: list
        :return: None
        :rtype: None
        """
        self.results.extend(results)

    def format_text_report(self):
        """
        Generates a text format report.

        :return: The report in text format
        :rtype: str
        """
        report_lines = [
            f"Security Analysis Report for {self.url}",
            "=" * 70,
            f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-" * 70,
            "Analysis Results:",
            ""
        ]

        # Sort results by severity level (CRITICAL, WARNING, INFO)
        severity_order = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3, "SSL": 4}
        sorted_results = sorted(
            self.results,
            key=lambda x: severity_order.get(x.get("level", "INFO"), 999)
        )

        # Organize by section
        sections = {}
        for result in sorted_results:
            level = result.get("level", "INFO")
            message = result.get("message", "")

            if level not in sections:
                sections[level] = []

            sections[level].append(message)

        # Add each section to the report
        for level in ["CRITICAL", "ERROR", "WARNING", "INFO", "SSL"]:
            if level in sections and sections[level]:
                report_lines.append(f"{level} Findings:")
                report_lines.append("-" * 50)
                for message in sections[level]:
                    report_lines.append(f"[{level}] {message}")
                report_lines.append("")

        # Add a summary at the end
        report_lines.append("-" * 70)
        report_lines.append("Summary:")
        for level in ["CRITICAL", "ERROR", "WARNING", "INFO", "SSL"]:
            if level in sections:
                report_lines.append(f"{level}: {len(sections[level])} found")

        return "\n".join(report_lines)