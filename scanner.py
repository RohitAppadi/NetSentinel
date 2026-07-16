from host_discovery import HostDiscovery


def main():
    target = input("Enter target (Example: 192.168.1.0/24): ")

    scanner = HostDiscovery()

    hosts = scanner.discover_hosts(target)

    print("\nLive Hosts:")
    for host in hosts:
        print(f" - {host}")


if __name__ == "__main__":
    main()