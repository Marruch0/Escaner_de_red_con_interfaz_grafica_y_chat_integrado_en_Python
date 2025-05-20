#!/usr/bin/env python3
import socket, threading, re, os, time, platform, datetime, getpass
from scapy.all import IP, TCP, ICMP, sr1, send, conf
import matplotlib.pyplot as plt
from vulnerabilidades_db import VULN_DATABASE

# Constantes
COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 
                123: "NTP", 135: "Microsoft RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 
                445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "Microsoft SQL Server", 
                3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP Proxy", 8443: "HTTPS-Alt"}
LOG_DIR = "logs_escaneo"
LOG_FILE = f"{LOG_DIR}/registro_escaneos.txt"
os.makedirs(LOG_DIR, exist_ok=True)

# Patrones para identificación de servicios
PATTERNS = [
    (r'Server: Apache/([0-9.]+)', 'Apache'),
    (r'Server: nginx/([0-9.]+)', 'nginx'),
    (r'Server: Microsoft-IIS/([0-9.]+)', 'Microsoft IIS'),
    (r'SSH-2.0-OpenSSH_([0-9.]+)', 'OpenSSH'),
    (r'SSH-2.0-([a-zA-Z0-9._-]+)', ''),
    (r'220 .* FTP .* \(([a-zA-Z0-9._-]+)\)', ''),
    (r'220 .* ProFTPD ([0-9.]+)', 'ProFTPD'),
    (r'220 .* FileZilla Server ([0-9.]+)', 'FileZilla'),
    (r'220 .* ESMTP Postfix ([0-9.]+)', 'Postfix'),
    (r'220 .* ESMTP Sendmail ([0-9.]+)', 'Sendmail'),
    (r'MySQL v([0-9.]+)', 'MySQL')
]

# Funciones de utilidad
def log_registro(mensaje, separador=False):
    """Registra un mensaje en el archivo de log único"""
    with open(LOG_FILE, "a") as f:
        if separador:
            separador_texto = "\n" + "="*50 + "\n"
            f.write(separador_texto)
        f.write(mensaje + "\n")

def log_escaneo(ip, puertos_rango, modo_sigilo=False):
    """Registra información básica sobre el escaneo realizado"""
    fecha_hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    usuario = getpass.getuser()
    
    # Información básica del escaneo
    info_escaneo = f"""
==== NUEVO ESCANEO ====
Fecha y hora: {fecha_hora}
Usuario: {usuario}
IP objetivo: {ip}
Puertos: {puertos_rango}
Modo sigilo: {'Activado' if modo_sigilo else 'Desactivado'}
"""
    
    # Guardar en archivo de texto único
    log_registro(info_escaneo, separador=True)
    
    print(f"\nEscaneo iniciado en: {fecha_hora}")
    print(f"Usuario: {usuario}")
    
    return fecha_hora

# Funciones de escaneo y detección
def detect_service(port):
    return COMMON_PORTS.get(port, "Desconocido")

def analyze_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)
            if port in [80, 8080, 8443]:
                sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
            elif port == 21: sock.sendall(b"USER anonymous\r\n")
            elif port == 25: sock.sendall(b"HELO test\r\n")
            return sock.recv(1024).decode().strip()
    except: return "Sin respuesta"

def extract_service_version(banner):
    for pattern, service_name in PATTERNS:
        match = re.search(pattern, banner)
        if match:
            version = match.group(1)
            if not service_name: service_name = match.group(0).split('-')[0]
            return (service_name, version)
    return (None, None)

def os_fingerprinting(ip):
    try:
        conf.verb = 0
        # SYN/ACK y análisis
        syn_resp = sr1(IP(dst=ip)/TCP(dport=80, flags="SA"), timeout=2, verbose=0)
        if syn_resp and syn_resp.haslayer(TCP):
            ttl, win = syn_resp[IP].ttl, syn_resp[TCP].window
            if ttl == 64 and win == 29200: return "Linux"
            elif ttl == 128 and win == 8192: return "Windows"
            elif ttl == 255: return "Cisco Router"
        
        # ICMP y análisis
        icmp_resp = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
        if icmp_resp and icmp_resp.haslayer(ICMP):
            ttl = icmp_resp[IP].ttl
            if ttl == 64: return "Linux/Unix"
            elif ttl == 128: return "Windows"
    except Exception as e:
        print(f"Error en OS fingerprinting: {e}")
    return "Desconocido"

def scan_port(ip, port, timeout=1, stealth=False):
    try:
        resp = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
        if resp is None:
            return port, "Filtrado", detect_service(port), "N/A"
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags == 0x12:  # SYN-ACK
                if stealth: send(IP(dst=ip)/TCP(dport=port, flags="R"), verbose=0)
                banner = analyze_banner(ip, port)
                return port, "Abierto", detect_service(port), banner
            elif flags == 0x14:  # RST
                return port, "Cerrado", detect_service(port), "N/A"
        elif resp.haslayer(ICMP):
            if resp[ICMP].type == 3 and resp[ICMP].code in [1, 2, 3, 9, 10, 13]:
                return port, "Filtrado", detect_service(port), "N/A"
    except:
        pass
    return port, "Desconocido", detect_service(port), "N/A"

def scan_ports(ip, ports, timeout=1, stealth=False, show_only_open=False):
    results, threads = [], []
    
    def worker(port):
        result = scan_port(ip, port, timeout, stealth)
        if show_only_open and result[1] != "Abierto": return
        results.append(result)
    
    for port in ports:
        t = threading.Thread(target=worker, args=(port,))
        threads.append(t)
        t.start()
    
    for t in threads: t.join()
    
    return sorted(results, key=lambda x: x[0])

# Funciones de visualización y análisis
def generate_graph(results, filename="resultados_escaneo.png"):
    statuses = [s for _, s, _, _ in results]
    counts = {"Abiertos": statuses.count("Abierto"), 
              "Cerrados": statuses.count("Cerrado"), 
              "Filtrados": statuses.count("Filtrado")}
    
    labels, sizes, colors = [], [], []
    if counts["Abiertos"]: labels.append("Abiertos"); sizes.append(counts["Abiertos"]); colors.append("green")
    if counts["Cerrados"]: labels.append("Cerrados"); sizes.append(counts["Cerrados"]); colors.append("red")
    if counts["Filtrados"]: labels.append("Filtrados"); sizes.append(counts["Filtrados"]); colors.append("yellow")
    
    if sizes:
        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
        plt.title("Puertos")
        plt.axis("equal")
        plt.savefig(filename)
        plt.close()
        
        try:
            os_name = platform.system()
            cmd = {"Windows": f"start {filename}", "Linux": f"xdg-open {filename}", 
                  "Darwin": f"open {filename}"}.get(os_name, "")
            if cmd: os.system(cmd)
        except:
            print(f"Imagen guardada como: {filename}")

def check_vulns(service_name, version):
    return VULN_DATABASE.get(service_name, {}).get(version, [])

def analyze_vulnerabilities(results):
    print("\n=== Análisis de Vulnerabilidades ===")
    vulns = []
    info_log = "\n==== VULNERABILIDADES DETECTADAS ===="
    
    for port, status, service, banner in results:
        if status == "Abierto" and banner != "N/A":
            print(f"\nAnalizando {service} en puerto {port}...")
            service_name, version = extract_service_version(banner)
            
            if service_name and version:
                print(f"Servicio detectado: {service_name} versión {version}")
                info_log += f"\n\nPuerto {port}: {service_name} versión {version}"
                
                found_vulns = check_vulns(service_name, version)
                if found_vulns:
                    print("Vulnerabilidades encontradas:")
                    info_log += "\nVulnerabilidades encontradas:"
                    for cve_id, desc, cvss in found_vulns:
                        vulns.append((port, service_name, version, cve_id, desc, cvss))
                        print(f"  - {cve_id}: {desc} (CVSS: {cvss})")
                        info_log += f"\n  - {cve_id}: {desc} (CVSS: {cvss})"
                else:
                    info_log += "\n  No se encontraron vulnerabilidades conocidas"
            else:
                info_log += f"\n\nPuerto {port}: No se pudo identificar versión específica"
    
    log_registro(info_log)
    
    if not vulns:
        print("\nNo se encontraron vulnerabilidades conocidas")
    
    return vulns

# Interfaz de usuario
def user_interface():
    """Interfaz de usuario para configurar el escaneo."""
    print("=== Herramienta de Escaneo de Puertos, OS Fingerprinting y Análisis de Vulnerabilidades ===")
    ip = input("IP objetivo: ")

    print("\n¿Qué puertos deseas escanear?")
    print("1. Todos los puertos (0-65535)")
    print("2. Rango específico de puertos")
    print("3. Los puertos más comunes")
    option = input("Selecciona una opción (1, 2 o 3): ")

    if option == "1":
        ports = range(0, 65536)
        rango_str = "0-65535"
    elif option == "2":
        port_range = input("Introduce el rango de puertos (por ejemplo: 80,443 o 8080-8085): ")
        ports = set()
        for item in port_range.split(","):
            if "-" in item:
                start, end = map(int, item.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(item))
        ports = sorted(ports)
        rango_str = port_range
    elif option == "3":
        ports = COMMON_PORTS.keys()
        rango_str = "Puertos comunes"
    else:
        print("Opción no válida. Saliendo...")
        return

    stealth = input("\n¿Deseas realizar un escaneo stealth (half-open)? (s/n): ").lower() == "s"
    show_only_open = input("\n¿Deseas mostrar solo los puertos abiertos? (s/n): ").lower() == "s"
    
    # Nueva opción
    analyze_vulns = input("\n¿Deseas realizar análisis de vulnerabilidades? (s/n): ").lower() == "s"
    
    # Registrar información del escaneo
    log_escaneo(ip, rango_str, stealth)
    
    print("\nIniciando escaneo de puertos...")
    start_time = time.time()

    results = scan_ports(ip, ports, timeout=1, stealth=stealth, show_only_open=show_only_open)
    os_detected = os_fingerprinting(ip)

    # Actualizar el registro con el sistema operativo detectado
    log_registro(f"\n==== SISTEMA OPERATIVO DETECTADO ====\nSO: {os_detected}")

    end_time = time.time()
    total_time = end_time - start_time

    if results:
        print("\n=== Resultados del Escaneo ===")
        
        # Actualizar el log con los resultados
        resultados_log = f"\n==== RESULTADOS DEL ESCANEO DE {ip} ===="
        
        for port, status, service, banner in results:
            info_puerto = f"Puerto {port}: {status} ({service}) | Banner: {banner}"
            print(info_puerto)
            resultados_log += f"\n{info_puerto}"
            
        log_registro(resultados_log)
        
        print(f"\nSistema operativo detectado: {os_detected}")
        generate_graph(results)  # Llamada para generar y abrir la gráfica
        
        # Análisis de vulnerabilidades si se seleccionó
        if analyze_vulns:
            vulnerabilidades = analyze_vulnerabilities(results)
    else:
        print("\nNo se encontraron resultados para los puertos seleccionados.")
        log_registro(f"\n==== RESULTADOS DEL ESCANEO DE {ip} ====\nNo se encontraron puertos abiertos")

    # Actualizar el log con el tiempo de escaneo
    log_registro(f"\nTiempo total de escaneo: {total_time:.2f} segundos")
    
    print(f"\nTiempo total de escaneo: {total_time:.2f} segundos")
    print(f"Todos los resultados han sido guardados en la carpeta: {LOG_DIR}")

if __name__ == "__main__":
    user_interface()