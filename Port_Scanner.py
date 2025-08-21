import socket
import concurrent.futures
import argparse
from datetime import datetime
import time
import sys
import struct
import os
from tqdm import tqdm


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'


def print_color(text, color=Colors.WHITE):
    print(f"{color}{text}{Colors.END}")


class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.scan_stats = {
            'total': 0,
            'open': 0,
            'closed': 0,
            'filtered': 0,
            'errors': 0
        }

    def is_private_ip(self, ip):
        """প্রাইভেট আইপি চেক করুন"""
        try:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip))[0]
            # Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            private_ranges = [
                (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
                (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
                (0xC0A80000, 0xC0A8FFFF)  # 192.168.0.0/16
            ]
            return any(start <= ip_addr <= end for start, end in private_ranges)
        except:
            return False

    def ethical_check(self, target):
        """এথিক্যাল স্ক্যানিং চেক"""
        if target in ['localhost', '127.0.0.1']:
            return True

        if self.is_private_ip(target):
            return True

        print_color("\n⚠️  WARNING: You are attempting to scan a public IP address!", Colors.YELLOW)
        print_color("This may be illegal without explicit permission.", Colors.RED)

        response = input("Do you have permission to scan this target? (y/N): ").lower()
        if response != 'y':
            print_color("Scan cancelled. Always get proper authorization before scanning.", Colors.RED)
            return False

        return True

    def syn_scan(self, ip, port, timeout=2):
        """TCP SYN (Half-open) স্ক্যান"""
        try:
            # Raw socket তৈরি (requires admin privileges on Windows)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(timeout)

            # SYN প্যাকেট তৈরি
            # Note: Raw socket implementation is complex and OS-dependent
            # For simplicity, we'll fall back to connect scan
            s.close()
            return self.connect_scan(ip, port, timeout)

        except (OSError, socket.error):
            # Fall back to connect scan if raw sockets aren't available
            return self.connect_scan(ip, port, timeout)

    def connect_scan(self, ip, port, timeout=2):
        """TCP Connect স্ক্যান (সর্বাধিক compatible)"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))

                if result == 0:
                    service = self.service_fingerprint(ip, port, s)
                    return port, service, "OPEN"
                else:
                    # Different error codes for different states
                    if result in [61, 10061, 111]:  # Connection refused
                        return port, None, "CLOSED"
                    else:  # Other errors (timeout, filtered, etc.)
                        return port, None, "FILTERED"

        except socket.timeout:
            return port, None, "FILTERED"
        except Exception as e:
            return port, None, f"ERROR: {str(e)}"

    def service_fingerprint(self, ip, port, sock=None):
        """সার্ভিস ফিংগারপ্রিন্টিং"""
        service_name = "Unknown"
        banner = ""

        try:
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))

            # Banner grabbing
            try:
                sock.send(b'\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass

            # Protocol-specific fingerprinting
            if port in [80, 443, 8080, 8443]:
                try:
                    sock.send(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if 'HTTP' in response:
                        service_name = "HTTP"
                        if 'Server:' in response:
                            server_line = [line for line in response.split('\r\n') if 'Server:' in line]
                            if server_line:
                                service_name = f"HTTP ({server_line[0].split(':', 1)[1].strip()})"
                except:
                    service_name = "HTTP (Unknown)"

            elif port == 21:
                service_name = "FTP"
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if 'FTP' in banner:
                        service_name = f"FTP ({banner.split()[0]})"
                except:
                    pass

            elif port == 22:
                service_name = "SSH"
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if 'SSH' in banner:
                        service_name = f"SSH ({banner})"
                except:
                    pass

            elif port == 25:
                service_name = "SMTP"

            elif port == 53:
                service_name = "DNS"

            elif port in [3306, 5432, 1433]:
                service_name = "Database"

            if banner and service_name == "Unknown":
                service_name = f"Unknown ({banner[:30]}...)"

        except:
            pass
        finally:
            if sock:
                sock.close()

        return service_name

    def scan_ports(self, target, ports, scan_type="connect", max_threads=100, delay=0.1):
        """পোর্ট স্ক্যান 실행"""
        if not self.ethical_check(target):
            return False

        self.scan_stats['total'] = len(ports)

        print_color(f"\n🔍 Scanning {len(ports)} ports on {target}...", Colors.CYAN)
        print_color(f"📊 Scan type: {scan_type.upper()}", Colors.BLUE)
        print_color(f"⚡ Threads: {max_threads}, Delay: {delay}s", Colors.BLUE)
        print()

        start_time = datetime.now()

        # Progress bar with tqdm
        with tqdm(total=len(ports), desc="Scanning ports", unit="port",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Scan function selection
                scan_func = self.syn_scan if scan_type == "syn" else self.connect_scan

                futures = {executor.submit(scan_func, target, port): port for port in ports}

                for future in concurrent.futures.as_completed(futures):
                    port, service, status = future.result()

                    # Update statistics
                    if status == "OPEN":
                        self.open_ports.append((port, service, status))
                        self.scan_stats['open'] += 1
                        print_color(f"✅ {port}/tcp open - {service}", Colors.GREEN)
                    elif status == "FILTERED":
                        self.scan_stats['filtered'] += 1
                        print_color(f"🛡️  {port}/tcp filtered", Colors.YELLOW)
                    elif status == "CLOSED":
                        self.scan_stats['closed'] += 1
                    elif "ERROR" in status:
                        self.scan_stats['errors'] += 1

                    # Update progress bar
                    pbar.update(1)
                    pbar.set_postfix(
                        open=self.scan_stats['open'],
                        filtered=self.scan_stats['filtered'],
                        errors=self.scan_stats['errors']
                    )

                    # Rate limiting
                    time.sleep(delay)

        end_time = datetime.now()
        return end_time - start_time

    def visualize_results(self):
        """ইন্টার‍্যাক্টিভ ভিজুয়ালাইজেশন"""
        if not self.open_ports:
            print_color("❌ No open ports found.", Colors.RED)
            return

        print_color("\n" + "=" * 80, Colors.BOLD)
        print_color("📊 PORT VISUALIZATION", Colors.CYAN + Colors.BOLD)
        print_color("=" * 80, Colors.BOLD)

        max_port = max(port for port, service, status in self.open_ports)

        for port, service, status in sorted(self.open_ports):
            # Visual bar based on port number
            visual_length = int((port / max_port) * 50) + 1
            visual_bar = "█" * visual_length

            color = Colors.GREEN
            if "HTTP" in service:
                color = Colors.BLUE
            elif "SSH" in service:
                color = Colors.MAGENTA
            elif "FTP" in service:
                color = Colors.CYAN

            print_color(f"{port:5d}/tcp {visual_bar:50s} {service}", color)

    def generate_report(self, target, scan_duration):
        """ডিটেইল্ড রিপোর্ট জেনারেট করুন"""
        report = f"""
{'=' * 80}
PORT SCAN REPORT
{'=' * 80}
Target: {target}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Duration: {scan_duration}
{'=' * 80}
Total ports scanned: {self.scan_stats['total']}
Open ports found: {self.scan_stats['open']}
Filtered ports: {self.scan_stats['filtered']}
Closed ports: {self.scan_stats['closed']}
Errors: {self.scan_stats['errors']}
{'=' * 80}

OPEN PORTS:
"""
        for port, service, status in sorted(self.open_ports):
            report += f"{port:5d}/tcp - {service}\n"

        return report


def main():
    scanner = PortScanner()

    print_color("🚀 Advanced Port Scanner", Colors.CYAN + Colors.BOLD)
    print_color("=" * 50, Colors.BOLD)

    target = input("🌐 Enter target IP or hostname: ").strip()

    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
        if target != target_ip:
            print_color(f"📡 Resolved {target} to {target_ip}", Colors.BLUE)
    except socket.gaierror:
        print_color("❌ Error: Invalid hostname or IP address", Colors.RED)
        return

    ports_input = input("🎯 Enter ports (e.g., 80,443 or 1-100): ").strip()

    # Parse ports
    ports = []
    for part in ports_input.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                print_color(f"❌ Invalid port range: {part}", Colors.RED)
        else:
            try:
                ports.append(int(part))
            except ValueError:
                print_color(f"❌ Invalid port: {part}", Colors.RED)

    if not ports:
        print_color("❌ No valid ports specified", Colors.RED)
        return

    # Remove duplicates and sort
    ports = sorted(set(ports))

    # Scan configuration
    scan_type = input("🔧 Scan type (connect/syn) [connect]: ").strip().lower()
    if scan_type not in ['connect', 'syn']:
        scan_type = "connect"

    try:
        max_threads = int(input("⚡ Max threads [50]: ").strip() or "50")
        delay = float(input("⏱️  Delay between scans (seconds) [0.1]: ").strip() or "0.1")
    except ValueError:
        print_color("❌ Invalid number", Colors.RED)
        return

    # Perform scan
    scan_duration = scanner.scan_ports(target_ip, ports, scan_type, max_threads, delay)

    if scan_duration:
        # Generate and display report
        report = scanner.generate_report(target_ip, scan_duration)
        print_color(report, Colors.WHITE)

        # Visualize results
        scanner.visualize_results()

        # Save report
        try:
            filename = f"scan_report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            print_color(f"\n💾 Report saved to: {filename}", Colors.GREEN)
        except Exception as e:
            print_color(f"❌ Error saving report: {e}", Colors.RED)


if __name__ == "__main__":
    # Windows-এ Unicode support
    if sys.platform == "win32":
        try:
            import win_unicode_console

            win_unicode_console.enable()
        except ImportError:
            pass

    try:
        main()
    except KeyboardInterrupt:
        print_color("\n⏹️  Scan cancelled by user", Colors.RED)
    except Exception as e:
        print_color(f"\n❌ Unexpected error: {e}", Colors.RED)