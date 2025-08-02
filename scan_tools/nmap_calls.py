import nmap3, sys

def host_up(host):
    nmap = nmap3.NmapHostDiscovery()
    results = nmap.nmap_no_portscan(host)
    if results[host]['state']['state'] == 'up':
        print(f'\t{host} is up')
        return 1
    else:
        print(f'\t{host} is not up')
        return 0

def port_scan_top(host):
    nmap = nmap3.NmapHostDiscovery()
    ports = nmap.scan_top_ports(host, 100)
    open_ports = []
    for port in ports[host]['ports']:
        if port['state'] == 'open':
            print(f"\t{port['portid']}/{port['protocol']} - {port['service']['name']} - {port['state']}")
            open_ports.append(port['portid'])
    if len(open_ports) == 0:
        print('\tNo open ports found')
        return 0
    else:
        return open_ports

def service_version(host, ports):
    for port in ports:
        result = nmap3.Nmap().nmap_version_detection(host, args=f'-p {port}')
        if "product" in result[host]["ports"][0]["service"].keys():
            if "version" in result[host]["ports"][0]["service"].keys(): 
                print(f'\t{port} - {result[host]["ports"][0]["service"]["product"]} - {result[host]["ports"][0]["service"]["version"]}')
            else:
                print(f'\t{port} - {result[host]["ports"][0]["service"]["product"]}')
        else:
            print(f'\t{port} - Unable to identify service on port')

def info_search(host, port):
    nl = '\n'
    nmap = nmap3.NmapHostDiscovery()
    result = nmap.nmap_portscan_only(host, args=f'-sC -p {port}')
    if len(result[host]["ports"][0]["scripts"]) > 1:
        if "raw" in result[host]["ports"][0]["scripts"][0].keys():
            if port == '21':
                for x in range(0, len(result[host]["ports"][0]["scripts"])):
                    if 'ftp-anon' in {result[host]["ports"][0]["scripts"][x]["name"]}:
                        print(f'\t{port}: {result[host]["ports"][0]["scripts"][x]["raw"].split(nl)[0]}')
            elif port == "443":
                for x in range(0, len(result[host]["ports"][0]["scripts"])):
                    if 'ssl-cert' in {result[host]["ports"][0]["scripts"][x]["name"]}:
                        parts = result[host]["ports"][0]["scripts"][x]["raw"].split(" ")
                        for x in parts:
                            if 'commonName' in x: 
                                print(f'\t{port}: Common Name = {x.split("=")[1].split("/")[0]}')
                            if 'DNS' in x:
                                print(f'\t{port}: DNS entry = {x.split(":")[1][:-1].split(nl)[0]}')
    else:
        print(f'\t{port}: Nothing found for this port')


if __name__==("__main__"):
   end
