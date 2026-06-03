#!/usr/bin/env python3
"""
SMBEnum - Custom SMB Enumeration Tool
Author: Tyler Thomas
GitHub: tthomas-cyber

Description:
    A custom Python tool for enumerating SMB services on Windows
    targets. Tests for null sessions, enumerates shares, checks
    SMB signing, and pulls domain information.

Usage:
    python3 smbenum.py -t <target_ip>
    python3 smbenum.py -t <target_ip> -u <username> -p <password>

Example:
    python3 smbenum.py -t 192.168.56.102
    python3 smbenum.py -t 192.168.56.102 -u Administrator -p Password333

Legal Notice:
    Only use against systems you own or have explicit written
    authorization to test. Unauthorized access is illegal.
"""

# ============================================================
# IMPORTS
# socket   - raw network connections
# struct   - packs/unpacks binary data for SMB packets
# argparse - handles command line arguments
# sys      - system exit and output
# datetime - timestamps for reports
# binascii - converts between binary and hex for debugging
# ============================================================
import socket
import struct
import argparse
import sys
import datetime


BANNER = r"""
 _____ ___  ___ ___                      
/  ___||  \/  || _ )  ___  _ __   _   _ 
\ `--. | .  . || _ \ / _ \| '_ \ | | | |
 `--. \| |\/| || |_)|  __/| | | || |_| |
/\__/ /| |  | ||___/ \___||_| |_| \__,_|
\____/ \_|  |_/                          

Custom SMB Enumeration Tool
Author: Tyler Thomas | github.com/tthomas-cyber
FOR AUTHORIZED TESTING ONLY
"""


# ============================================================
# SMB CONSTANTS
# These are fixed values defined by the SMB protocol spec
# Every SMB packet must use these exact byte sequences
# to identify itself as valid SMB traffic
#
# SMB uses a binary protocol - everything is raw bytes
# not human readable text like HTTP
# ============================================================

# SMB protocol identifier - first 4 bytes of every SMB packet
# \xffSMB in hex - tells the server this is an SMB message
SMB_HEADER = b'\xff\x53\x4d\x42'

# NetBIOS session service header
# Used to wrap SMB packets for transport over TCP port 445
NETBIOS_HEADER = b'\x00'

# SMB Commands
SMB_COM_NEGOTIATE = 0x72      # Negotiate protocol version
SMB_COM_SESSION_SETUP = 0x73  # Authenticate to server
SMB_COM_TREE_CONNECT = 0x75   # Connect to a share
SMB_COM_TRANSACTION2 = 0x25   # Extended operations

# SMB Flags
SMB_FLAGS_CANONICAL = 0x08
SMB_FLAGS2_UNICODE = 0x8000
SMB_FLAGS2_LONG_NAMES = 0x4000
SMB_FLAGS2_SECURITY_SIGNATURE = 0x0004
SMB_FLAGS2_NT_STATUS = 0x4000


# ============================================================
# SMB PACKET BUILDER
# SMB communicates using carefully structured binary packets
# Each packet has a fixed header followed by command-specific data
# struct.pack() converts Python values into raw bytes
# '<' means little-endian byte order (Windows uses little-endian)
# 'B' = unsigned byte (1 byte)
# 'H' = unsigned short (2 bytes)
# 'I' = unsigned int (4 bytes)
# ============================================================

def build_smb_negotiate():
    """
    Builds an SMB Negotiate Protocol Request packet.

    This is the first packet sent in any SMB session.
    It tells the server what SMB dialects we support.
    The server responds with which dialect it prefers.

    We offer NT LM 0.12 which is SMBv1 - the older protocol
    that has more security issues we can probe for.

    The packet structure:
    [NetBIOS header][SMB header][Word count][Dialects]
    """

    # The dialect string we're offering
    # NT LM 0.12 is the standard SMBv1 dialect
    dialects = b'\x02NT LM 0.12\x00'

    # Build the SMB header
    # This 32-byte structure appears at the start of every SMB packet
    smb_header = (
        SMB_HEADER +                    # Protocol identifier \xffSMB
        struct.pack('<B', SMB_COM_NEGOTIATE) +  # Command: Negotiate
        struct.pack('<I', 0) +          # NT Status (0 = no error yet)
        struct.pack('<B', 0x18) +       # Flags
        struct.pack('<H', 0x2801) +     # Flags2
        struct.pack('<H', 0) +          # Process ID High
        struct.pack('<Q', 0) +          # Signature (8 bytes of zeros)
        struct.pack('<H', 0) +          # Reserved
        struct.pack('<H', 0) +          # Tree ID
        struct.pack('<H', 0xffff) +     # Process ID
        struct.pack('<H', 0) +          # User ID
        struct.pack('<H', 0)            # Multiplex ID
    )

    # Build the negotiate request body
    # Word count = 0 for negotiate request
    # Byte count = length of dialect list
    negotiate_body = (
        struct.pack('<B', 0) +                          # Word count
        struct.pack('<H', len(dialects)) +              # Byte count
        dialects                                        # Dialect list
    )

    # Wrap everything in NetBIOS session service header
    # First byte = 0x00 (session message type)
    # Next 3 bytes = length of the SMB packet
    smb_packet = smb_header + negotiate_body
    netbios = struct.pack('>I', len(smb_packet)) 
    netbios = b'\x00' + netbios[1:]  # Set type byte to 0x00

    return netbios + smb_packet


def build_session_setup_null():
    """
    Builds an SMB Session Setup request with null credentials.

    A null session uses empty username and password.
    If the server accepts this it means unauthenticated
    access is possible - a significant security finding.

    In older Windows configurations null sessions allow
    enumeration of users, shares, and domain information
    without any credentials at all.
    """

    # Empty credentials for null session attempt
    username = b'\x00'      # Null username
    password = b'\x00'      # Null password
    domain = b'WORKGROUP\x00'
    native_os = b'Unix\x00'
    native_lan_man = b'Samba\x00'

    # Session setup parameters
    # These are the capabilities we're advertising to the server
    andx_command = 0xff     # No chained command
    max_buffer = 65535      # Max buffer size we can handle
    max_mpx_count = 2       # Max simultaneous requests
    vc_number = 1           # Virtual circuit number
    session_key = 0         # Session key (0 for null session)
    capabilities = 0x00000044  # Basic capabilities

    # Word parameters for session setup
    words = struct.pack('<BBHHHHI',
        andx_command,       # AndXCommand
        0,                  # AndXReserved
        max_buffer,         # MaxBufferSize
        max_mpx_count,      # MaxMpxCount
        vc_number,          # VcNumber
        session_key,        # SessionKey
        len(password)       # PasswordLength
    )
    words += struct.pack('<IH',
        capabilities,       # Capabilities
        0                   # ByteCount placeholder
    )

    # Build the data section
    data = password + username + domain + native_os + native_lan_man

    smb_header = (
        SMB_HEADER +
        struct.pack('<B', SMB_COM_SESSION_SETUP) +
        struct.pack('<I', 0) +
        struct.pack('<B', 0x18) +
        struct.pack('<H', 0x2801) +
        struct.pack('<H', 0) +
        struct.pack('<Q', 0) +
        struct.pack('<H', 0) +
        struct.pack('<H', 0) +
        struct.pack('<H', 0xffff) +
        struct.pack('<H', 0) +
        struct.pack('<H', 1)
    )

    # Word count for session setup is 13 words
    body = struct.pack('<B', 13) + words[:26] + struct.pack('<H', len(data)) + data

    smb_packet = smb_header + body
    netbios = struct.pack('>I', len(smb_packet))
    netbios = b'\x00' + netbios[1:]

    return netbios + smb_packet


# ============================================================
# NETWORK FUNCTIONS
# These handle the actual TCP connections to the target
# SMB runs on port 445 (direct) or 139 (via NetBIOS)
# We use port 445 as it's more common in modern networks
# ============================================================

def connect_smb(target_ip, port=445, timeout=5):
    """
    Opens a TCP connection to the SMB service.

    Returns the socket object if successful, None if failed.
    We set a timeout so the script doesn't hang forever
    if the host is unreachable.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        return sock
    except ConnectionRefusedError:
        return None
    except socket.timeout:
        return None
    except Exception:
        return None


def send_recv(sock, packet, timeout=5):
    """
    Sends a packet and receives the response.

    recv(4096) reads up to 4096 bytes of response.
    SMB responses can be longer but the headers we
    care about are always in the first few hundred bytes.
    """
    try:
        sock.settimeout(timeout)
        sock.send(packet)
        response = sock.recv(4096)
        return response
    except Exception:
        return None


# ============================================================
# ENUMERATION FUNCTIONS
# Each function probes a specific aspect of the SMB service
# ============================================================

def check_smb_port(target_ip):
    """
    Checks if SMB port 445 is open.
    Also tries port 139 as a fallback.
    Returns the open port number or None.
    """
    print(f"[*] Checking SMB ports on {target_ip}")

    for port in [445, 139]:
        sock = connect_smb(target_ip, port)
        if sock:
            sock.close()
            print(f"[+] Port {port}/tcp open - SMB service detected")
            return port

    print(f"[-] No SMB ports open on {target_ip}")
    return None


def negotiate_smb(target_ip, port):
    """
    Sends SMB Negotiate packet and parses the response.

    The negotiate response tells us:
    - Which SMB dialect the server uses
    - Whether message signing is required
    - Server capabilities
    - Server OS and domain information

    SMB signing is important - if disabled the server is
    vulnerable to relay attacks where we intercept and
    forward authentication to gain access.
    """
    print(f"\n[*] Negotiating SMB protocol with {target_ip}:{port}")

    sock = connect_smb(target_ip, port)
    if not sock:
        print(f"[-] Could not connect to SMB service")
        return None

    # Send negotiate packet
    negotiate_packet = build_smb_negotiate()
    response = send_recv(sock, negotiate_packet)
    sock.close()

    if not response or len(response) < 36:
        print(f"[-] No valid negotiate response received")
        return None

    results = {}

    try:
        # Parse the NetBIOS header (4 bytes) + SMB header (32 bytes)
        # Response starts at byte 4 (after NetBIOS length)
        smb_response = response[4:]

        # Check the SMB signature in the response
        # Bytes 0-3 should be \xffSMB
        if smb_response[:4] != SMB_HEADER:
            print(f"[-] Invalid SMB response signature")
            return None

        # Extract NT Status code (bytes 5-8)
        # 0x00000000 means success
        nt_status = struct.unpack('<I', smb_response[5:9])[0]
        results['nt_status'] = nt_status

        # Extract Flags2 field (bytes 13-14)
        # Contains security feature flags
        flags2 = struct.unpack('<H', smb_response[13:15])[0]

        # Check if SMB signing is enabled
        # Bit 0x0004 in Flags2 indicates signing
        signing_enabled = bool(flags2 & 0x0004)
        results['signing_enabled'] = signing_enabled

        if signing_enabled:
            print(f"[+] SMB Signing: ENABLED")
        else:
            print(f"[!!!] SMB Signing: DISABLED - Vulnerable to relay attacks!")
            results['signing_vuln'] = True

        # Try to extract OS info from the negotiate response
        # It's embedded in the variable data section after the fixed header
        try:
            # Skip past the fixed header and word parameters
            # Word count is at byte 32 of SMB header
            word_count = smb_response[32]
            # Each word is 2 bytes, plus 1 byte for word count itself
            # Plus 2 bytes for byte count
            data_offset = 33 + (word_count * 2) + 2

            if data_offset < len(smb_response):
                # OS info is unicode encoded in the data section
                os_data = smb_response[data_offset:]
                # Decode unicode and clean up null bytes
                os_string = os_data.decode('utf-16-le', errors='ignore')
                os_string = os_string.replace('\x00', ' ').strip()

                if os_string:
                    results['os_info'] = os_string[:60]
                    print(f"[+] OS Info: {os_string[:60]}")

        except Exception:
            pass

        print(f"[+] SMB Negotiate successful")
        return results

    except Exception as e:
        print(f"[-] Error parsing negotiate response: {e}")
        return None


def test_null_session(target_ip, port):
    """
    Tests whether the SMB service accepts null session authentication.

    A null session is an anonymous connection with no credentials.
    If accepted it means anyone on the network can:
    - List shares
    - Enumerate users and groups
    - Read domain information

    This was common in older Windows but is now a misconfiguration.
    Still found regularly in real enterprise environments.
    """
    print(f"\n[*] Testing for null session authentication")

    sock = connect_smb(target_ip, port)
    if not sock:
        return False

    # First negotiate the protocol
    negotiate_packet = build_smb_negotiate()
    response = send_recv(sock, negotiate_packet)

    if not response:
        sock.close()
        return False

    # Now attempt session setup with null credentials
    null_session_packet = build_session_setup_null()
    response = send_recv(sock, null_session_packet)
    sock.close()

    if not response or len(response) < 9:
        print(f"[-] No response to null session attempt")
        return False

    # Check NT Status in response
    # 0x00000000 = success (null session accepted)
    # 0xc000006d = logon failure (null session rejected)
    try:
        smb_response = response[4:]
        nt_status = struct.unpack('<I', smb_response[5:9])[0]

        if nt_status == 0x00000000:
            print(f"[!!!] NULL SESSION ACCEPTED - Anonymous access possible!")
            print(f"[!!!] Unauthenticated enumeration may be possible")
            return True
        else:
            print(f"[+] Null session rejected (NT Status: 0x{nt_status:08x})")
            print(f"[+] Anonymous access not permitted")
            return False

    except Exception as e:
        print(f"[-] Error parsing null session response: {e}")
        return False


def enumerate_with_credentials(target_ip, username, password):
    """
    Uses impacket to enumerate shares with valid credentials.
    This runs as a subprocess since impacket has the full
    SMB implementation we need for authenticated enumeration.

    In a real engagement you'd have credentials from:
    - Previous exploitation
    - Password spraying
    - Phishing campaign
    - Default credentials
    """
    import subprocess

    print(f"\n[*] Enumerating shares with credentials")
    print(f"[*] Username: {username}")

    try:
        # Use smbclient to list shares
        # -L lists shares, -N means no password prompt if empty
        cmd = [
            "smbclient",
            f"//{target_ip}/",
            "-U", f"{username}%{password}",
            "-L", target_ip,
            "--no-pass" if not password else ""
        ]

        # Remove empty strings from command
        cmd = [c for c in cmd if c]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 or "Sharename" in result.stdout:
            print(f"[+] Share enumeration successful")
            print()

            # Parse and display shares
            lines = result.stdout.split('\n')
            shares = []
            in_shares = False

            for line in lines:
                if 'Sharename' in line:
                    in_shares = True
                    print(f"  {'SHARE':<20} {'TYPE':<15} DESCRIPTION")
                    print(f"  {'-'*50}")
                    continue
                if in_shares and line.strip():
                    if '---' in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_type = parts[1] if len(parts) > 1 else 'Unknown'
                        share_comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                        print(f"  {share_name:<20} {share_type:<15} {share_comment}")
                        shares.append(share_name)

                if in_shares and not line.strip():
                    in_shares = False

            return shares

        else:
            print(f"[-] Share enumeration failed")
            if result.stderr:
                print(f"[-] Error: {result.stderr[:100]}")
            return []

    except FileNotFoundError:
        print(f"[-] smbclient not found - install with: sudo apt install smbclient")
        return []
    except Exception as e:
        print(f"[-] Enumeration error: {e}")
        return []


def check_smb_vulnerabilities(target_ip, port, signing_disabled):
    """
    Reports on known SMB vulnerabilities based on what we found.

    Signing disabled is the most common SMB misconfiguration.
    It enables NTLM relay attacks where we sit between the
    client and server and forward authentication to gain access.
    """
    print(f"\n[*] SMB Vulnerability Assessment")
    print(f"{'='*50}")

    vulns_found = []

    if signing_disabled:
        vulns_found.append({
            "name": "SMB Signing Disabled",
            "severity": "HIGH",
            "description": "SMB message signing is not required. "
                         "Vulnerable to NTLM relay attacks.",
            "cve": "No specific CVE - configuration issue",
            "remediation": "Enable SMB signing via Group Policy: "
                         "Microsoft network server: Digitally sign "
                         "communications (always) = Enabled"
        })

    if vulns_found:
        for v in vulns_found:
            print(f"\n[!!!] {v['name']}")
            print(f"      Severity:    {v['severity']}")
            print(f"      Description: {v['description']}")
            print(f"      CVE:         {v['cve']}")
            print(f"      Remediation: {v['remediation']}")
    else:
        print(f"[+] No critical SMB misconfigurations detected")

    return vulns_found


def generate_report(target_ip, smb_port, negotiate_results,
                   null_session, shares, vulns, output_file):
    """
    Writes a professional markdown report of all SMB findings.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, 'w') as f:
        f.write(f"# SMB Enumeration Report\n\n")
        f.write(f"**Target:** {target_ip}\n")
        f.write(f"**Date:** {timestamp}\n")
        f.write(f"**Tool:** SMBEnum by tthomas-cyber\n\n")
        f.write(f"---\n\n")

        f.write(f"## Service Discovery\n\n")
        f.write(f"| Port | Protocol | Status |\n")
        f.write(f"|------|----------|--------|\n")
        f.write(f"| {smb_port} | SMB | Open |\n\n")

        if negotiate_results:
            f.write(f"## Protocol Information\n\n")
            signing = negotiate_results.get('signing_enabled', 'Unknown')
            os_info = negotiate_results.get('os_info', 'Unknown')
            f.write(f"| Setting | Value |\n")
            f.write(f"|---------|-------|\n")
            f.write(f"| SMB Signing | {'Enabled' if signing else 'DISABLED'} |\n")
            f.write(f"| OS Info | {os_info} |\n\n")

        f.write(f"## Authentication Testing\n\n")
        f.write(f"| Test | Result |\n")
        f.write(f"|------|--------|\n")
        null_result = "ACCEPTED - Anonymous access possible" if null_session else "Rejected"
        f.write(f"| Null Session | {null_result} |\n\n")

        if shares:
            f.write(f"## Enumerated Shares\n\n")
            f.write(f"| Share Name |\n")
            f.write(f"|------------|\n")
            for share in shares:
                f.write(f"| {share} |\n")
            f.write(f"\n")

        if vulns:
            f.write(f"## Vulnerabilities Found\n\n")
            for v in vulns:
                f.write(f"### {v['name']}\n")
                f.write(f"- **Severity:** {v['severity']}\n")
                f.write(f"- **Description:** {v['description']}\n")
                f.write(f"- **Remediation:** {v['remediation']}\n\n")

        f.write(f"## Recommendations\n\n")
        f.write(f"1. Enable SMB signing on all Windows systems\n")
        f.write(f"2. Disable null session access\n")
        f.write(f"3. Restrict SMB access via firewall to trusted hosts\n")
        f.write(f"4. Monitor Event ID 4624 for anonymous logon attempts\n")

    print(f"\n[+] Report saved to {output_file}")


# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="SMBEnum - Custom SMB Enumeration Tool",
        epilog="Example: python3 smbenum.py -t 192.168.56.102 -u Administrator -p Password333"
    )
    parser.add_argument("-t", "--target", required=True,
                       help="Target IP address")
    parser.add_argument("-u", "--username", default="",
                       help="Username for authenticated enumeration")
    parser.add_argument("-p", "--password", default="",
                       help="Password for authenticated enumeration")
    parser.add_argument("-o", "--output", default="smb-report.md",
                       help="Output report file (default: smb-report.md)")
    args = parser.parse_args()

    print(f"[*] SMBEnum - Custom SMB Enumeration Tool")
    print(f"[*] Target: {args.target}")
    print(f"[*] Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Step 1 - Check if SMB is open
    smb_port = check_smb_port(args.target)
    if not smb_port:
        print("[-] SMB not available on target")
        sys.exit(1)

    # Step 2 - Negotiate SMB protocol
    negotiate_results = negotiate_smb(args.target, smb_port)
    signing_disabled = False
    if negotiate_results:
        signing_disabled = not negotiate_results.get('signing_enabled', True)

    # Step 3 - Test for null session
    null_session = test_null_session(args.target, smb_port)

    # Step 4 - Enumerate shares if credentials provided
    shares = []
    if args.username:
        shares = enumerate_with_credentials(
            args.target, args.username, args.password
        )

    # Step 5 - Vulnerability assessment
    vulns = check_smb_vulnerabilities(
        args.target, smb_port, signing_disabled
    )

    # Step 6 - Generate report
    generate_report(
        args.target, smb_port, negotiate_results,
        null_session, shares, vulns, args.output
    )

    print(f"\n[*] Scan complete: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
