#!/usr/bin/env python3
"""
ReconScan - Custom Network Reconnaissance Tool
Author: Tyler Thomas
GitHub: tthomas-cyber

A lightweight network scanner built from scratch using only
Python standard library. No external dependencies required.
"""

import socket       
import subprocess   
import threading    
import argparse     
import ipaddress    
import sys          
import datetime     
from queue import Queue  

VULNERABLE_VERSIONS = {
    "vsftpd 2.3.4": {
        "cve": "CVE-2011-2523",
        "severity": "CRITICAL",
        "description": "vsftpd 2.3.4 backdoor - unauthenticated root shell"
    },
    "proftpd 1.3.1": {
        "cve": "CVE-2008-4242",
        "severity": "HIGH",
        "description": "ProFTPD 1.3.1 cross-site request forgery"
    },

    "openssh 4.7": {
        "cve": "CVE-2008-5161",
        "severity": "MEDIUM",
        "description": "OpenSSH 4.7 CBC mode information disclosure"
    },

    "apache/2.2.8": {
        "cve": "CVE-2009-1195",
        "severity": "HIGH",
        "description": "Apache 2.2.8 mod_proxy reverse proxy bypass"
    },
    "apache-coyote/1.1": {
        "cve": "CVE-2014-0230",
        "severity": "HIGH",
        "description": "Apache Tomcat 5.5 denial of service"
    },

    "mysql 5.0": {
        "cve": "CVE-2012-2122",
        "severity": "HIGH",
        "description": "MySQL 5.0 authentication bypass"
    },

    "samba 3.0": {
        "cve": "CVE-2007-2447",
        "severity": "CRITICAL",
        "description": "Samba 3.0.x username map script RCE"
    },
}

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    1099: "Java-RMI",
    1433: "MSSQL",
    1521: "Oracle",
    1524: "Bindshell",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6667: "IRC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

BANNER = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██║     ███████║██╔██╗ ██║
╚════██║██║     ██╔══██║██║╚██╗██║
███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

Custom Network Reconnaissance Tool
Author: Tyler Thomas | github.com/tthomas-cyber
For authorized testing only
"""

def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def discover_hosts(network):
    live_hosts = []
    print(f"\n[*] Discovering live hosts on {network}...")

    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
    except ValueError:
        hosts = [ipaddress.ip_address(network)]

    for ip in hosts:
        if ping_host(str(ip)):
            print(f"[+] Host up: {ip}")
            live_hosts.append(str(ip))

    return live_hosts

def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in [80, 8080, 8443, 443]:
            sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        return banner.split('\n')[0]

    except Exception:
        return None

def check_vulnerable(banner):
    if not banner:
        return None

    banner_lower = banner.lower()

    for version, vuln_info in VULNERABLE_VERSIONS.items():
        if version.lower() in banner_lower:
            return vuln_info

    return None
	
def scan_port(ip, port, results, lock):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            banner = grab_banner(ip, port)
            vuln = check_vulnerable(banner)
            service = COMMON_PORTS.get(port, "Unknown")

            with lock:
                results.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "vulnerable": vuln
                })

    except Exception:
        pass


def scan_host(ip, port_range):
    print(f"\n[*] Scanning {ip} ports {port_range[0]}-{port_range[-1]}...")

    results = []
    lock = threading.Lock()
    threads = []

    queue = Queue()
    for port in port_range:
        queue.put(port)

    def worker():
        while not queue.empty():
            try:
                port = queue.get(timeout=1)
                scan_port(ip, port, results, lock)
                queue.task_done()
            except Exception:
                break

    for _ in range(100):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    results.sort(key=lambda x: x['port'])
    return results

def print_results(ip, results):
    print(f"\n{'='*60}")
    print(f"SCAN RESULTS: {ip}")
    print(f"{'='*60}")

    if not results:
        print("[-] No open ports found")
        return

    print(f"{'PORT':<10}{'SERVICE':<15}{'BANNER':<30}")
    print(f"{'-'*55}")

    for r in results:
        port = str(r['port'])
        service = r['service']
        banner = (r['banner'] or 'No banner')[:30]

        print(f"{port:<10}{service:<15}{banner:<30}")

        if r['vulnerable']:
            v = r['vulnerable']
            print(f"  [!!!] VULNERABLE: {v['cve']} - {v['severity']}")
            print(f"  [!!!] {v['description']}")


def generate_report(scan_results, output_file):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, 'w') as f:
        f.write(f"# ReconScan Report\n\n")
        f.write(f"**Generated:** {timestamp}\n")
        f.write(f"**Tool:** ReconScan by tthomas-cyber\n\n")
        f.write(f"---\n\n")

        for ip, results in scan_results.items():
            f.write(f"## Host: {ip}\n\n")

            if not results:
                f.write("No open ports found.\n\n")
                continue

            vulns = [r for r in results if r['vulnerable']]

            f.write(f"**Open Ports:** {len(results)}\n")
            f.write(f"**Vulnerable Services:** {len(vulns)}\n\n")

            f.write(f"| Port | Service | Banner | CVE |\n")
            f.write(f"|------|---------|--------|-----|\n")

            for r in results:
                port = r['port']
                service = r['service']
                banner = (r['banner'] or 'None')[:40]
                cve = r['vulnerable']['cve'] if r['vulnerable'] else 'None'
                f.write(f"| {port} | {service} | {banner} | {cve} |\n")

            if vulns:
                f.write(f"\n### Vulnerability Details\n\n")
                for r in results:
                    if r['vulnerable']:
                        v = r['vulnerable']
                        f.write(f"**Port {r['port']} — {v['cve']}**\n")
                        f.write(f"- Severity: {v['severity']}\n")
                        f.write(f"- Description: {v['description']}\n\n")

            f.write("\n---\n\n")

    print(f"\n[+] Report saved to {output_file}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconScan - Custom Network Reconnaissance Tool",
        epilog="Example: python3 reconscan.py -t 192.168.56.0/24"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address or subnet (e.g. 192.168.56.101 or 192.168.56.0/24)"
    )
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Port range to scan: 'common', '1-1000', or '80,443,8080'"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to file (e.g. report.md)"
    )
    return parser.parse_args()


def parse_ports(port_arg):
    if port_arg == "common":
        return list(COMMON_PORTS.keys())

    elif "-" in port_arg:
        start, end = port_arg.split("-")
        return list(range(int(start), int(end) + 1))

    elif "," in port_arg:
        return [int(p) for p in port_arg.split(",")]

    else:
        return [int(port_arg)]

def main():
    print(BANNER)

    args = parse_args()
    port_range = parse_ports(args.ports)
    scan_results = {}

    print(f"[*] Target: {args.target}")
    print(f"[*] Ports: {len(port_range)} ports queued")
    print(f"[*] Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        net = ipaddress.ip_network(args.target, strict=False)
        if net.num_addresses > 1:
            live_hosts = discover_hosts(args.target)
        else:
            live_hosts = [args.target]
    except ValueError:
        live_hosts = [args.target]

    if not live_hosts:
        print("[-] No live hosts found")
        sys.exit(0)

    print(f"\n[*] Found {len(live_hosts)} live host(s)")

    for ip in live_hosts:
        results = scan_host(ip, port_range)
        scan_results[ip] = results
        print_results(ip, results)

    if args.output:
        generate_report(scan_results, args.output)

    print(f"\n[*] Scan complete: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
