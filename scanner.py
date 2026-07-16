from host_discovery import HostDiscovery


def banner():
    print("=" * 50)
    print("          NetSentinel v1.0")
    print("     Network Vulnerability Scanner")
    print("=" * 50)


def main():
    banner()

    target = input("\nEnter Target (Example: 192.168.1.0/24): ")

    discovery = HostDiscovery()

    hosts = discovery.discover_hosts(target)

    print("\nDiscovered Hosts")
    print("-" * 30)

    if not hosts:
        print("No live hosts found.")
        return

    for host in hosts:
        print(f"[+] {host}")


if __name__ == "__main__":
    main()