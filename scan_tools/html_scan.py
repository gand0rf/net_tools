import os
from subprocess import Popen, PIPE

def basic_scan(host,switches):
    file_path = '/home/gand0rf/hacky/wordlist/SecLists/Discovery/Web-Content/big.txt'
    command = f"ffuf -w {file_path} -u http://{host}/FUZZ {switches}"
    print(f'\nRunning command: {command}')
    scan_results = Popen([command],stdout=PIPE,stderr=PIPE,shell=True)
    scan_output, scan_error = scan_results.communicate()
    if scan_output:
        print('\n Output of directory scan:')
        print(scan_output.decode('utf-8'))
    else:
        print('\nError when attempting scan:')
        print(scan_error.decode('utf-8'))

if __name__ == ("__main__"):
    exit
