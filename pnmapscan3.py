import nmap
import json

scanner = nmap.PortScanner()

print('Welcome, this is a simple nmap tool')
print('<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>')

ip_address = input('Please enter the IP address you would like to scan: ')
print('The IP address you entered is ==', ip_address)

response = input("""\nPlease enter the type of scan you want to run:
                    1) SYN ACK scan
                    2) UDP scan
                    3) Comprehensive scan\n""")

print("You have selected the option:", response)

if response == '1':
    print('Nmap version:', scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sS')
    scan_result = scanner.scaninfo()

    ip_status = scanner[ip_address].state()
    protocols = scanner[ip_address].all_protocols()
    open_ports = list(scanner[ip_address]['tcp'].keys())

    scan_result['ip_status'] = ip_status
    scan_result['protocols'] = protocols
    scan_result['open_ports'] = open_ports

    with open('scan_results.json', 'w') as file:
        json.dump(scan_result, file, indent=4)

    print("Scan results saved in 'scan_results.json'")
    print("Ip status:", ip_status)
    print("Protocols:", protocols)
    print('Open ports:', open_ports)

elif response == '2':
    print('Nmap version:', scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sU')
    scan_result = scanner.scaninfo()

    ip_status = scanner[ip_address].state()
    protocols = scanner[ip_address].all_protocols()
    open_ports = list(scanner[ip_address]['udp'].keys())

    scan_result['ip_status'] = ip_status
    scan_result['protocols'] = protocols
    scan_result['open_ports'] = open_ports

    with open('scan_results.json', 'w') as file:
        json.dump(scan_result, file, indent=4)

    print("Scan results saved in 'scan_results.json'")
    print("Ip status:", ip_status)
    print("Protocols:", protocols)
    print('Open ports:', open_ports)

elif response == '3':
    print('Nmap version:', scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sS -sV -sC -A -O')
    scan_result = scanner.scaninfo()

    ip_status = scanner[ip_address].state()
    protocols = scanner[ip_address].all_protocols()
    open_ports = list(scanner[ip_address]['tcp'].keys())

    scan_result['ip_status'] = ip_status
    scan_result['protocols'] = protocols
    scan_result['open_ports'] = open_ports

    with open('scan_results.json', 'w') as file:
        json.dump(scan_result, file, indent=4)

    print("Scan results saved in 'scan_results.json'")
    print("Ip status:", ip_status)
    print("Protocols:", protocols)
    print('Open ports:', open_ports)

else:
    print('Please enter a valid option')
