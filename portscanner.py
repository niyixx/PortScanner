import socket
import termcolor


opened_ports = []


# Checks for opened and closed ports
def scan_port(ipaddress, port):
    try:
        # returning value for only opened ports
        sock = socket.socket()
        sock.connect((ipaddress, port))
        opened_ports.append(str(port))
        print("[+] Port Opened " + str(port))
        sock.close()
    except:
        pass


# Scans all the ports per target entered
def scan(target, ports):
    print("\n" + "Starting Scan For " + str(target))
    for port in range(1, ports):
        scan_port(target, port)
    num_of_opened_ports = len(opened_ports)
    if num_of_opened_ports > 0:
        print(termcolor.colored(f"You have {num_of_opened_ports} number of opened ports on " + str(target), "green"))
        opened_ports.clear()
    elif num_of_opened_ports == 0:
        print(termcolor.colored("You have no opened ports on " + str(target) + "!!!", "red"))


# Accepts IP address(es) from the user and number of port to scan
targets = input("[*] Enter Targets To Scan(Split the targets by ,): ")
ports = int(input("[*] Enter How Many Ports You Want To Scan: "))

# This separates the IP addresses entered by the user
if ',' in targets:
    print(termcolor.colored("\n[*] Scanning Multiple Targets", "green"))
    for ip_addr in targets.split(","):
        scan(ip_addr.strip(" "), ports)
else:
    scan(targets, ports)