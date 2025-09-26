#!/usr/bin/env python3
"""
Improved Network Reconnaissance Tool
- Fixed bugs (missing imports, timeouts per-socket)
- Thread-safe result collection
- Better banner grabbing
- Safer port parsing and range validation
- Graceful KeyboardInterrupt handling
- Optional output to JSON/CSV
- Basic TTL-based OS detection by parsing ping output (best-effort)
"""

import os
import sys
import socket
import subprocess
import argparse
import ipaddress
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


class NetworkScanner:
    def __init__(self, target, ports=None, threads=100):
        self.target = target
        # ports can be an iterable (range or list) or None
        self.ports = ports if ports is not None else range(1, 1001)
        self.threads = max(1, threads)
        self.open_ports = []
        self.hosts_up = []
        self._lock = Lock()

    def validate_target(self):
        """Validate if target is a valid IP or resolvable hostname"""
        try:
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            try:
                socket.gethostbyname(self.target)
                return True
            except socket.gaierror:
                return False

    def ping_sweep(self, network):
        """Perform ICMP ping sweep on a network range (returns list of up hosts)."""
        print(f"[*] Performing ping sweep on {network}")
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError:
            print("[!] Invalid network range")
            return []

        def ping_host(ip):
            ip_str = str(ip)
            try:
                if sys.platform.startswith("win"):
                    cmd = ["ping", "-n", "1", "-w", "1000", ip_str]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", ip_str]

                result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    return ip_str
            except Exception:
                return None
            return None

        hosts_up = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in network_obj.hosts()}
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        hosts_up.append(res)
                        print(f"[+] Host is up: {res}")
                except Exception:
                    pass

        with self._lock:
            self.hosts_up = hosts_up
        return hosts_up

    def port_scan(self, target_ip=None):
        """Perform TCP port scan on target. Returns list of tuples (port, service)."""
        target_ip = target_ip or self.target
        try:
            target_ip = socket.gethostbyname(target_ip)
        except socket.gaierror:
            print(f"[!] Could not resolve hostname: {target_ip}")
            return []

        print(f"[*] Scanning target: {target_ip}")
        print(f"[*] Time started: {datetime.now()}")

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target_ip, int(port)))
                if result == 0:
                    try:
                        service = socket.getservbyport(int(port))
                    except OSError:
                        service = "unknown"
                    sock.close()
                    return (int(port), service)
                sock.close()
            except Exception:
                return None
            return None

        open_ports = []
        # Submit tasks and collect results in the main thread (thread-safe)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in self.ports}
            try:
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        open_ports.append(res)
                        print(f"[+] Port {res[0]}: Open ({res[1]})")
            except KeyboardInterrupt:
                print("\n[!] Scan interrupted by user")

        # sort ports by number
        open_ports.sort(key=lambda x: x[0])
        with self._lock:
            self.open_ports = open_ports
        return open_ports

    def banner_grab(self, target_ip, port):
        """Grab banner from an open port with a best-effort approach."""
        try:
            target_ip = socket.gethostbyname(target_ip)
        except socket.gaierror:
            return None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((target_ip, int(port)))

            banner = b""
            try:
                # try to receive banner that may be sent upon connect
                banner = sock.recv(1024)
            except socket.timeout:
                # no banner received proactively; try provoking a response for HTTP
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024)
                except Exception:
                    banner = b""

            sock.close()
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None
        return None

    def os_detection(self, target_ip):
        """Basic OS guess by parsing ping TTL field (best-effort, not reliable).
        Returns a string guess or 'Unknown'. Requires that the ping command output includes 'ttl'.
        """
        try:
            target_ip = socket.gethostbyname(target_ip)
        except socket.gaierror:
            return "Unknown"

        try:
            if sys.platform.startswith("win"):
                cmd = ["ping", "-n", "1", target_ip]
            else:
                cmd = ["ping", "-c", "1", target_ip]

            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            out = proc.stdout.lower()
            # Try to find ttl=NN pattern
            import re
            m = re.search(r"ttl\s*=\s*(\d+)", out)
            if not m:
                m = re.search(r"ttl=(\d+)", out)
            if m:
                ttl = int(m.group(1))
                # heuristics
                if ttl <= 64:
                    return "Linux/Unix (guess)"
                elif ttl <= 128:
                    return "Windows (guess)"
                else:
                    return "Network device / Cisco (guess)"
        except Exception:
            pass
        return "Unknown"

    def dns_lookup(self, target):
        """Perform DNS lookup (A record)."""
        try:
            ip = socket.gethostbyname(target)
            print(f"[+] DNS Lookup: {target} -> {ip}")
            return ip
        except socket.gaierror:
            print(f"[!] DNS Lookup failed for: {target}")
            return None

    def reverse_dns_lookup(self, ip):
        """Perform reverse DNS lookup."""
        try:
            host = socket.gethostbyaddr(ip)
            print(f"[+] Reverse DNS: {ip} -> {host[0]}")
            return host[0]
        except socket.herror:
            print(f"[-] No reverse DNS record for: {ip}")
            return None

    def whois_lookup(self, target):
        """Placeholder WHOIS output -- for a real WHOIS use `python-whois` or external API."""
        print(f"[*] WHOIS information for {target}")
        print("[*] This is placeholder output; integrate a WHOIS library for real results")
        print(f"Domain: {target}")
        print("Registrar: Example Registrar")
        print("Creation Date: 2020-01-01")
        print("Expiration Date: 2025-01-01")
        print("Name Servers: ns1.example.com, ns2.example.com")

    def save_results(self, filename):
        """Save results to JSON and CSV (if extension is .json or .csv, or both if no ext)."""
        base, ext = os.path.splitext(filename)
        if not ext:
            # write both
            json_path = f"{filename}.json"
            csv_path = f"{filename}.csv"
        elif ext.lower() == ".json":
            json_path = filename
            csv_path = None
        elif ext.lower() == ".csv":
            csv_path = filename
            json_path = None
        else:
            # unknown extension -> write json
            json_path = filename
            csv_path = None

        data = {
            "target": self.target,
            "scanned_at": datetime.now().isoformat(),
            "hosts_up": self.hosts_up,
            "open_ports": self.open_ports,
        }

        if json_path:
            try:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                print(f"[+] Results saved to {json_path}")
            except Exception as e:
                print(f"[!] Failed to save JSON: {e}")

        if csv_path:
            try:
                with open(csv_path, "w", newline='', encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["target", data["target"]])
                    writer.writerow(["scanned_at", data["scanned_at"]])
                    writer.writerow([])
                    writer.writerow(["hosts_up"])
                    for h in data["hosts_up"]:
                        writer.writerow([h])
                    writer.writerow([])
                    writer.writerow(["port", "service"])
                    for p, s in data["open_ports"]:
                        writer.writerow([p, s])
                print(f"[+] Results saved to {csv_path}")
            except Exception as e:
                print(f"[!] Failed to save CSV: {e}")


def parse_ports(port_arg):
    """Parse port argument like '1-1000', '22,80,443' or single '80'. Validate 1-65535."""
    if port_arg is None:
        return None
    ports = set()
    parts = port_arg.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-', 1))
            except ValueError:
                raise ValueError("Invalid port range")
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Port numbers must be in 1-65535 and start <= end")
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError("Invalid port number")
            if p < 1 or p > 65535:
                raise ValueError("Port numbers must be in 1-65535")
            ports.add(p)
    # return sorted list or range if continuous
    ports_list = sorted(ports)
    return ports_list


def main():
    parser = argparse.ArgumentParser(description="Network Reconnaissance Tool (improved)")
    parser.add_argument("target", help="Target IP, hostname, or network range (for ping sweep)")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000 or 22,80,443)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--ping-sweep", action="store_true", help="Perform ping sweep (requires /24 etc)")
    parser.add_argument("--port-scan", action="store_true", help="Perform port scan")
    parser.add_argument("--dns", action="store_true", help="Perform DNS lookup")
    parser.add_argument("--reverse-dns", action="store_true", help="Perform reverse DNS lookup")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup (placeholder)")
    parser.add_argument("--output", help="Save results to file (basename or .json/.csv)")

    args = parser.parse_args()

    # Parse ports
    ports = None
    try:
        if args.ports:
            parsed = parse_ports(args.ports)
            # Use a list (ThreadPoolExecutor can iterate it)
            ports = parsed
    except ValueError as e:
        print(f"[!] Invalid port specification: {e}")
        return

    scanner = NetworkScanner(args.target, ports, args.threads)

    # Validate target when necesario
    if not scanner.validate_target() and not args.ping_sweep:
        print("[!] Invalid target specified")
        return

    print(f"[*] Starting network reconnaissance on {args.target}")
    print("-" * 50)

    try:
        if args.dns:
            scanner.dns_lookup(args.target)

        if args.reverse_dns:
            # If the target is an IP, use it directly; otherwise, try resolving first
            if '/' not in args.target and not any(c.isalpha() for c in args.target):
                scanner.reverse_dns_lookup(args.target)
            else:
                resolved = scanner.dns_lookup(args.target)
                if resolved:
                    scanner.reverse_dns_lookup(resolved)

        if args.whois:
            scanner.whois_lookup(args.target)

        if args.ping_sweep:
            if '/' in args.target:
                scanner.ping_sweep(args.target)
            else:
                print("[!] Ping sweep requires a network range (e.g., 192.168.1.0/24)")

        if args.port_scan:
            open_ports = scanner.port_scan()
            if open_ports:
                print(f"\n[*] Found {len(open_ports)} open ports:")
                for port, service in open_ports:
                    print(f"  Port {port} ({service})")
                    if port in [21, 22, 23, 25, 80, 110, 143, 443, 993, 995]:
                        banner = scanner.banner_grab(args.target, port)
                        if banner:
                            print(f"    Banner: {banner[:200]}...")
                # try OS detection (best-effort)
                os_guess = scanner.os_detection(args.target)
                print(f"\n[*] OS detection guess: {os_guess}")
            else:
                print("[-] No open ports found")

    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")

    print("-" * 50)
    print(f"[*] Scan completed at: {datetime.now()}")

    if args.output:
        scanner.save_results(args.output)


if __name__ == "__main__":
    # Check if running with appropriate permissions (informational)
    try:
        if sys.platform != "win32" and hasattr(os, "geteuid") and os.geteuid() != 0:
            print("[!] Note: Some features (raw sockets, packet capture) may require root privileges")
    except Exception:
        pass

    main()
