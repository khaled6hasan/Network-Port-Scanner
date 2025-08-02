import socket
import threading

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
        else:
            print(f"[-] Port {port} is CLOSED")
        s.close()
    except Exception as e:
        print(f"[!] Error scanning port {port}: {e}")

def get_ports_from_input():
    port_input = input("🎯 Enter ports to scan (e.g., 22,80,443 or 20-100): ")
    ports = set()
    for part in port_input.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part.strip()))
    return list(ports)

def main():
    target = input("🌐 Enter target IP: ")
    custom = input("🔧 Use custom ports? (y/n): ").lower()

    if custom == 'y':
        ports = get_ports_from_input()
    else:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

    print(f"🔍 Starting scan on {target}...\n")

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n✅ Scan complete.")

if __name__ == "__main__":
    main()
# Why not use Nmap's Python lib (python-nmap)?  