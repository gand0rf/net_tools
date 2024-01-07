import nmap3, sys

def host_up(host, nmap):
    results = nmap.nmap_no_portscan(host)
    if results[host]['state']['state'] == 'up':
        print(f'\t{host} is up')
        return 1
    else:
        return 0

def port_scan_top(host, nmap):
    ports = nmap.scan_top_ports(host, 100)
    open_ports = []
    for port in ports[host]['ports']:
        if port['state'] == 'open':
            print(f"\t{port['portid']}/{port['protocol']} - {port['service']['name']} - {port['state']}")
            open_ports.append(port['portid'])
    if len(open_ports) == 0:
        print('No open ports found')
        return 0
    else:
        return open_ports

def service_version(host, ports):
    for port in ports:
        result = nmap3.Nmap().nmap_version_detection(host, args=f'-p {port}')
        if "product" in result[host]["ports"][0]["service"]:  
            print(f'\t{port} - {result[host]["ports"][0]["service"]["product"]} - {result[host]["ports"][0]["service"]["version"]} ')
        else:
            print(f'\t{port} - Unable to identify service on port')

nmap = nmap3.NmapHostDiscovery()
host = sys.argv[1]

print('running probe...')
result = host_up(host, nmap)

print('scanning host for ports...')
ports = port_scan_top(host, nmap)

print('Finding port details...')
service_version(host, ports)
 

    

