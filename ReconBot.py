# Coded by Cyb3rEagle
import socket
import whois
import nmap
import requests
from bs4 import BeautifulSoup

def whois_lookup(target):
    try:
        w = whois.whois(target)
        print(f"Registrar: {w.registrar}")
        print(f"Registration Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Nameservers: {w.name_servers}")
        print(f"Contact Email: {w.emails}")
        print(f"Domain Status: {w.status}")
    except Exception as e:
        print(f"Error: {e}")

def port_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sS -p 1-65535 -T4')
        for host in nm.all_hosts():
            print(f"Open Ports for {host}:")
            for port in nm[host]['tcp'].keys():
                print(f"  Port {port}: {nm[host]['tcp'][port]['name']} - {nm[host]['tcp'][port]['state']}")
    except Exception as e:
        print(f"Error: {e}")

def dns_enum(target):
    try:
        ip = socket.gethostbyname(target)
        mx_records = socket.gethostbyname_ex(target)[-1]
        ns_records = socket.gethostbyname_ex(target)[-2]
        print(f"IP Address: {ip}")
        print(f"MX Records: {mx_records}")
        print(f"NS Records: {ns_records}")
        # Additional DNS record types can be retrieved here
    except socket.gaierror:
        print("Unable to resolve target")

def web_enum(target):
    try:
        r = requests.get(f"http://{target}")
        soup = BeautifulSoup(r.text, 'html.parser')
        print(f"Website Title: {soup.title.string}")
        print(f"Website Headers: {r.headers}")
        # Additional web enumeration tasks can be performed here
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target = input("Enter the target domain or IP address: ")
    dns_enum(target)
    whois_lookup(target)
    port_scan(target)
    web_enum(target)
