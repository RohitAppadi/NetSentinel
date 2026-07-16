import nmap


class HostDiscovery:
    """
    Discovers live hosts on a given network using Nmap ping scan.
    """

    def __init__(self):
        self.scanner = nmap.PortScanner()

    def discover_hosts(self, target):
        """
        Performs a ping scan (-sn) on the target network.

        Args:
            target (str): IP address or CIDR range
                          Example: 192.168.1.0/24

        Returns:
            list: List of live host IP addresses
        """

        print(f"\n[*] Discovering live hosts on {target}...\n")

        self.scanner.scan(hosts=target, arguments="-sn")

        live_hosts = []

        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                live_hosts.append(host)

        return live_hosts