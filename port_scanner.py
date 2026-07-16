import nmap


class PortScanner:
    """Scan a host for open TCP ports."""

    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan_ports(self, host):
        """
        Scan the top 1000 TCP ports on a host.

        Args:
            host (str): IP address of the target.

        Returns:
            dict: Dictionary containing open ports and services.
        """

        print(f"\n[*] Scanning ports on {host}...\n")

        self.scanner.scan(hosts=host, arguments="-sV")

        results = {}

        for protocol in self.scanner[host].all_protocols():

            ports = self.scanner[host][protocol].keys()

            for port in sorted(ports):

                service = self.scanner[host][protocol][port]["name"]

                version = self.scanner[host][protocol][port]["product"]

                results[port] = {
                    "service": service,
                    "version": version
                }

        return results