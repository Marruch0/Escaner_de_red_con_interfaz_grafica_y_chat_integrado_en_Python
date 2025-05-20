#!/usr/bin/env python3
from scapy.all import *
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

# Ctrl+C handler
def def_handler(sig, frame):
    print("\n[!] Saliendo del programa...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Obtener los argumentos del usuario
def get_arguments():
    parser = argparse.ArgumentParser(description='Advanced TCP Port Scanner with SYN and Fragmentation')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target to scan (e.g., -t 192.168.1.1)")
    parser.add_argument("-p", "--port", dest="port", required=True, help="Port range to scan (e.g., -p 0-1000, 22,80,443)")
    parser.add_argument("-f", "--fragment", action="store_true", help="Enable packet fragmentation (like nmap -f)")
    options = parser.parse_args()
    return options.target, options.port, options.fragment

# Parsear puertos
def parse_ports(ports_str):
    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return range(start, end + 1)
    elif ',' in ports_str:
        return map(int, ports_str.split(','))
    else:
        return [int(ports_str)]

# Escaneo SYN de un puerto
def syn_scan(port, target, fragment=False):
    ip = IP(dst=target)
    tcp = TCP(dport=port, flags="S", sport=RandShort())  # SYN flag
    pkt = ip / tcp  # Paquete completo

    # Fragmentar paquete si se requiere (-f)
    if fragment:
        fragments = fragment(pkt, fragsize=8)
        print(f"[DEBUG] Enviando paquetes fragmentados al puerto {port}")
        for frag in fragments:
            send(frag, verbose=0)
        return  # Fragmentación no espera respuesta

    # Enviar paquete y esperar respuesta
    print(f"[DEBUG] Enviando paquete SYN al puerto {port}")
    resp = sr1(pkt, timeout=2, verbose=0)

    # Analizar respuesta
    if resp:
        if resp.haslayer(TCP):
            if resp[TCP].flags == "SA":  # SYN-ACK recibido
                print(f"[+] Puerto {port} está ABIERTO")
                # Enviar RST para cerrar el handshake
                send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)
            elif resp[TCP].flags == "RA":  # RST recibido
                print(f"[-] Puerto {port} está CERRADO")
        elif resp.haslayer(ICMP):
            print(f"[!] Puerto {port} está FILTRADO (ICMP recibido)")
    else:
        print(f"[?] Sin respuesta en el puerto {port} (posiblemente FILTRADO)")

# Escanear múltiples puertos usando hilos
def scan_ports(ports, target, fragment):
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(lambda port: syn_scan(port, target, fragment), ports)

# Función principal
def main():
    target, ports_str, fragment = get_arguments()  # Obtener argumentos
    ports = parse_ports(ports_str)  # Parsear puertos
    print(f"[+] Escaneando {target} en los puertos: {ports_str}")
    print(f"[+] Fragmentación habilitada: {'Sí' if fragment else 'No'}")
    scan_ports(ports, target, fragment)

if __name__ == "__main__":
    main()