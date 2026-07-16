import json
from datetime import datetime


class ReportGenerator:
    """Exports scan results to a JSON report."""

    def export(self, scan_results):

        filename = f"netsentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, "w") as file:
            json.dump(scan_results, file, indent=4)

        return filename