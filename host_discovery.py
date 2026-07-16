import nmap


class HostDiscovery:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def discover_hosts(self, target):
        print(f"\n[*] Scanning {target} for live hosts...\n")

        self.scanner.scan(hosts=target, arguments='-sn')

        live_hosts = []

        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                live_hosts.append(host)

        return live_hosts