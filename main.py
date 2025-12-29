import socket
from datetime import datetime
import ipaddress

def scan_port(host, ports):
    start = datetime.now().replace(microsecond=0)
    open_ports = []

    try:
        ip = socket.gethostbyname(host)
        print(f"Scanning {ip}...")

        for port in ports:
            cont = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cont.settimeout(1)
            try:
                result = cont.connect_ex((ip, port))
                if result == 0:
                    service = get_service_name(port)
                    print(f"{ip}:{port} is open/{service}")
                    open_ports.append((port, service))
            except Exception as e:
                pass
            finally:
                cont.close()

    except socket.gaierror:
        print(f"Could not resolve hostname: {host}")
    except Exception as e:
        print(f"Error scanning {host}: {e}")

    ends = datetime.now().replace(microsecond=0)
    print(f"<Time: {ends - start}>")
    return open_ports

def get_service_name(port):
    services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 43: "WHOIS", 53: "DNS", 80: "HTTP",
        115: "SFTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
        179: "BGP", 443: "HTTPS", 445: "MICROSOFT-DS",
        514: "SYSLOG", 515: "PRINTER", 993: "IMAPS",
        995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
        1433: "SQL Server", 1723: "PPTP", 3128: "HTTP",
        3268: "LDAP", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 8080: "Tomcat",
        10000: "Webmin"
    }
    return services.get(port, "Unknown")

def scan_ip_range(ip_range, port_list):
    try:
        network = ipaddress.IPv4Network(ip_range, strict=False)
        print(f"\nScanning network: {network}\n")

        for ip in network.hosts():
            scan_port(str(ip), port_list)
            print("-" * 50)
    except Exception as e:
        print(f"Invalid IP range: {e}")

def main():
    print('Welcome to VAN Port Scanner!' + '\n')

    ports = [20, 21, 22, 23, 25, 43, 53, 80, 115, 123, 143, 161,
             179, 443, 445, 514, 515, 993, 995, 1080, 1194,
             1433, 1723, 3128, 3268, 3306, 3389, 5432, 5900, 8080, 10000]

    choice = input("Choose mode:\n1 - Scan single host\n2 - Scan IP range (e.g. 192.168.1.0/24)\n3 - Exit\n> ")

    match choice:
        case "1":
            host = input('Enter the host name or IP address: ')
            if host:
                scan_port(host, ports)

        case "2":
            ip_range = input("Enter IP range (CIDR format, e.g. 192.168.1.0/24): ")
            scan_ip_range(ip_range, ports)
        case "3":
            exit(0)


if __name__ == '__main__':
    main()