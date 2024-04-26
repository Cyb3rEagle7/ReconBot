import socket
import whois
import nmap
import requests
from bs4 import BeautifulSoup

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
        nm.scan(target, arguments='-p 1-1024')
        print(f"Open Ports: {nm[target]['tcp'].keys()}")
    except Exception as e:
        print(f"Error: {e}")

def web_enum(target):
    try:
        r = requests.get(f"http://{target}")
        soup = BeautifulSoup(r.text, 'html.parser')
        print(f"Website Title: {soup.title.string}")
        print(f"Website Headers: {r.headers}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target = input("Enter the target domain or IP address: ")
    dns_enum(target)
    whois_lookup(target)
    port_scan(target)
    web_enum(target)
