import socket
import whois
import nmap
import requests
from bs4 import BeautifulSoup
from ip2geotools.databases.noncommercial import DbIpCity

def whois_lookup(target):
    try:
        w = whois.whois(target)
        print(f"Registrar: {w.registrar}")
        print(f"Registration Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
    except Exception as e:
        print(f"Error: {e}")

def port_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-p 1-1024 -sV')
        print(f"Open Ports: {nm[target]['tcp'].keys()}")
        for port, info in nm[target]['tcp'].items():
            print(f"Port {port}: {info['product']} {info['version']}")
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
    except socket.gaierror:
        print("Unable to resolve target")

def web_enum(target):
    try:
        r = requests.get(f"http://{target}")
        soup = BeautifulSoup(r.text, 'html.parser')
        print(f"Website Title: {soup.title.string}")
        print(f"Website Headers: {r.headers}")
    except Exception as e:
        print(f"Error: {e}")

def server_location(target):
    try:
        response = DbIpCity.get(target, api_key='free')
        print(f"Server Location: {response.city}, {response.region}, {response.country}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target = input("Enter the target domain or IP address: ")
    dns_enum(target)
    whois_lookup(target)
    port_scan(target)
    web_enum(target)
    server_location(target)
