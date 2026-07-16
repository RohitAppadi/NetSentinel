from datetime import datetime

from host_discovery import HostDiscovery
from port_scanner import PortScanner
from vulnerability_checker import VulnerabilityChecker
from report_generator import ReportGenerator


def banner():
    print("=" * 50)
    print("          NetSentinel v1.0")
    print("     Network Vulnerability Scanner")
    print("=" * 50)


def main():
    banner()

    target = input("\nEnter Target (Example: 192.168.1.0/24): ").strip()

    # Initialize modules
    discovery = HostDiscovery()
    port_scanner = PortScanner()
    vulnerability_checker = VulnerabilityChecker()
    report_generator = ReportGenerator()

    # Discover live hosts
    hosts = discovery.discover_hosts(target)

    if not hosts:
        print("\n[-] No live hosts found.")
        return

    print(f"\n[+] Found {len(hosts)} live host(s).\n")

    # Dictionary to store the complete scan
    scan_results = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "hosts": []
    }

    # Scan each host
    for host in hosts:

        print("=" * 50)
        print(f"Host: {host}")
        print("=" * 50)

        # Scan ports
        ports = port_scanner.scan_ports(host)

        if not ports:
            print("No open ports found.\n")

            scan_results["hosts"].append({
                "host": host,
                "ports": {},
                "findings": []
            })

            continue

        # Display open ports
        print("\nOpen Ports")
        print("-" * 60)
        print(f"{'Port':<8}{'Protocol':<10}{'Service':<15}Version")
        print("-" * 60)

        for port, info in ports.items():
            protocol = info.get("protocol", "Unknown")
            service = info.get("service", "Unknown")
            version = info.get("version", "Unknown")

            print(f"{port:<8}{protocol:<10}{service:<15}{version}")

        # Analyze vulnerabilities
        findings = vulnerability_checker.analyze(ports)

        print("\nPotential Security Findings")
        print("-" * 60)

        if findings:
            for finding in findings:
                print(f"[{finding['severity'].upper()}]")
                print(f"Port           : {finding['port']}")
                print(f"Protocol       : {finding['protocol']}")
                print(f"Service        : {finding['service']}")
                print(f"Reason         : {finding['reason']}")
                print(f"Recommendation : {finding['recommendation']}")
                print("-" * 60)
        else:
            print("No common security findings detected.")

        # Save results for report generation
        scan_results["hosts"].append({
            "host": host,
            "ports": ports,
            "findings": findings
        })

        print()

    # Export JSON report
    filename = report_generator.export(scan_results)

    print("=" * 50)
    print(f"[+] Scan complete!")
    print(f"[+] Report saved as: {filename}")
    print("=" * 50)


if __name__ == "__main__":
    main()