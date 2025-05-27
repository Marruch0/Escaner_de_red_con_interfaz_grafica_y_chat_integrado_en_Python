#!/usr/bin/env python3
import socket
import threading
import ssl
import re
import datetime
import os
import time
import platform
import getpass
import sys
import urllib.request
import networkx as nx
import numpy as np
from customtkinter import *
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from scapy.all import IP, TCP, ICMP, sr1, send, conf, Ether, ARP, srp
from io import BytesIO

# Importar la base de datos de vulnerabilidades existente
from vulnerabilidades_db import VULN_DATABASE

# Configuración del tema oscuro
set_appearance_mode("dark")
set_default_color_theme("blue")

# Lista de palabras feas
PALABRAS_FEAS = [
    "mierda", "puta", "puto", "joder", "jodido", "cabrón", "cabron", "gilipollas", 
    "idiota", "imbécil", "imbecil", "cojones", "hostia", "coño", "polla", "capullo", 
    "hijo de puta", "hdp", "pendejo", "marica", "maricón", "maricon", "zorra", 
    "follar", "jodete", "cabrona", "maldito", "carajo", "pito", "chinga", "maldita",
    "pene"
]

# Control de logs
recibiendo_logs = False
buffer_logs = []

#################################
# CÓDIGO DEL ESCÁNER DE HOSTS #
#################################

# Crear directorio para guardar resultados e iconos si no existe
RESULTS_DIR = "resultados_scan"
ICONS_DIR = "iconos_red"
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(ICONS_DIR, exist_ok=True)

# URLs de iconos online - iconos seleccionados por el usuario
ICONS_MAP = {
    "router": "https://cdn-icons-png.flaticon.com/512/1183/1183657.png",
    "server": "https://cdn-icons-png.flaticon.com/512/4227/4227991.png",
    "virtualbox": "https://cdn-icons-png.flaticon.com/512/873/873151.png",
    "pc": "https://cdn-icons-png.flaticon.com/512/1865/1865273.png",
    "scanner": "https://cdn-icons-png.flaticon.com/512/196/196345.png",
    "linux": "https://cdn-icons-png.flaticon.com/512/15465/15465695.png",
    "windows": "https://cdn-icons-png.flaticon.com/512/882/882702.png",
    "unknown": "https://cdn-icons-png.flaticon.com/512/5093/5093500.png",
    "firewall": "https://cdn-icons-png.flaticon.com/512/6071/6071236.png",
    "vmware": "https://cdn-icons-png.flaticon.com/512/873/873151.png",  # Usando el mismo de VirtualBox por ahora
    "switch": "https://cdn-icons-png.flaticon.com/512/1183/1183657.png", # Usando el mismo de router por ahora
    "printer": "https://cdn-icons-png.flaticon.com/512/5091/5091214.png"  # Añadido una impresora básica
}

def descargar_iconos():
    """Descarga los iconos necesarios si no existen localmente"""
    print("\nVerificando iconos disponibles...")
    
    for nombre, url in ICONS_MAP.items():
        icon_path = os.path.join(ICONS_DIR, f"{nombre}.png")
        if not os.path.exists(icon_path):
            try:
                print(f"Descargando icono: {nombre}")
                urllib.request.urlretrieve(url, icon_path)
            except Exception as e:
                print(f"Error al descargar {nombre}: {e}")
                # Crear un icono genérico si falla la descarga
                create_placeholder_icon(icon_path)

def create_placeholder_icon(path):
    """Crea un icono de marcador de posición simple"""
    img = Image.new('RGBA', (128, 128), (0, 0, 0, 0))
    with open(path, 'wb') as f:
        img.save(f, 'PNG')

def descubrir_hosts(red, iface=None, timeout=5, retries=3):
    """
    Función dedicada a descubrir hosts en una red específica
    
    Args:
        red: La dirección de red en formato CIDR (ej: 192.168.56.0/24)
        iface: Interfaz de red específica a usar
        timeout: Tiempo de espera para respuestas
        retries: Número de reintentos
    """
    try:
        # Crear paquete ARP
        ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_layer = ARP(pdst=red)
        paquete = ether_layer / arp_layer
        
        # Enviar paquetes y recibir respuestas
        conf.verb = 0  # Desactivar mensajes de scapy
        
        # Opciones adicionales para resolver problemas
        ans, unans = srp(
            paquete, 
            timeout=timeout, 
            retry=retries, 
            verbose=0,
            iface=iface,
            filter="arp"
        )
        
        # Procesar resultados
        hosts_encontrados = []
        
        for enviado, recibido in ans:
            ip = recibido.psrc
            mac = recibido.hwsrc
                
            hosts_encontrados.append({'ip': ip, 'mac': mac})
        
        return hosts_encontrados
    
    except Exception as e:
        print(f"Error durante el descubrimiento de hosts: {e}")
        return []

def obtener_tipo_dispositivo(mac):
    """
    Determina el tipo de dispositivo basado en el OUI (primeros 6 dígitos del MAC)
    """
    # Simplificación - en un entorno real se consultaría una base de datos OUI
    mac = mac.lower().replace(':', '').replace('-', '')
    
    # Ejemplos de OUI - esto es solo ilustrativo
    oui_map = {
        '000c29': 'VMware',
        '001c42': 'Parallels',
        '0025ae': 'Microsoft',
        '001bfd': 'Oracle',
        '5254': 'Red Hat KVM',
        '080027': 'VirtualBox',
        '001999': 'Cisco',
        'c4ad': 'Brother',
        'd85e': 'Dell',
        'f816': 'Dell',
        '7ce9': 'Intel',
        '8c16': 'Hewlett Packard',
        '8c85': 'Intel',
        '48c7': 'Dell',
        '5cea': 'ASIX',
        '6045': 'D-Link',
        'fc15': 'Mediatek'
    }
    
    # Buscar coincidencias
    for prefix, vendor in oui_map.items():
        if mac.startswith(prefix):
            return vendor
    
    # Si no encontramos coincidencia exacta
    if mac.startswith('00'):
        return "Dispositivo virtual"
    
    return "Dispositivo desconocido"

def obtener_ruta_icono(tipo_dispositivo):
    """Determina qué icono usar basado en el tipo de dispositivo"""
    tipo = tipo_dispositivo.lower()
    
    if "router" in tipo or "gateway" in tipo:
        return os.path.join(ICONS_DIR, "router.png")
    elif "firewall" in tipo:
        return os.path.join(ICONS_DIR, "firewall.png")
    elif "vmware" in tipo:
        return os.path.join(ICONS_DIR, "vmware.png")
    elif "virtualbox" in tipo:
        return os.path.join(ICONS_DIR, "virtualbox.png")
    elif "virtual" in tipo:
        return os.path.join(ICONS_DIR, "virtualbox.png")
    elif "cisco" in tipo or "switch" in tipo:
        return os.path.join(ICONS_DIR, "switch.png")
    elif "server" in tipo:
        return os.path.join(ICONS_DIR, "server.png")
    elif "escáner" in tipo.lower():
        return os.path.join(ICONS_DIR, "scanner.png")
    elif "brother" in tipo or "printer" in tipo or "print" in tipo:
        return os.path.join(ICONS_DIR, "printer.png")
    elif "linux" in tipo:
        return os.path.join(ICONS_DIR, "linux.png")
    elif "windows" in tipo or "microsoft" in tipo:
        return os.path.join(ICONS_DIR, "windows.png")
    elif "pc" in tipo or "dell" in tipo or "intel" in tipo or "hewlett" in tipo:
        return os.path.join(ICONS_DIR, "pc.png")
    else:
        return os.path.join(ICONS_DIR, "unknown.png")

def agregar_icono_al_grafo(fig, ax, x, y, ruta_icono, zoom=0.1):
    """Agrega un icono en la posición especificada del gráfico"""
    try:
        img = plt.imread(ruta_icono)
        # Crear un OffsetImage
        imagebox = OffsetImage(img, zoom=zoom)
        # Crear un AnnotationBbox
        ab = AnnotationBbox(imagebox, (x, y), frameon=False, pad=0.0)
        # Añadir al eje
        ax.add_artist(ab)
        return True
    except Exception as e:
        print(f"Error al agregar icono {ruta_icono}: {e}")
        # Si falla, dibujar un círculo como respaldo
        circle = plt.Circle((x, y), 0.02, color='white', ec='cyan')
        ax.add_patch(circle)
        return False

def generar_topologia_red(hosts, escaner_ip, red, iface, timeout, retries):
    """
    Genera una visualización avanzada de la topología de red
    con iconos gráficos reales y modo oscuro
    """
    if not hosts:
        print("No hay hosts suficientes para generar una topología de red.")
        return None
    
    # Asegurarse de que los iconos estén disponibles
    descargar_iconos()
    
    # Crear un grafo dirigido para nuestra red
    G = nx.DiGraph()
    
    # Añadir nodo para el escáner (nuestro dispositivo)
    G.add_node(escaner_ip, 
              ip=escaner_ip,
              tipo="Escáner", 
              mac=conf.ifaces[iface].mac if iface else "Desconocido")
    
    # Obtener el OUI (primeros 6 dígitos del MAC) de cada dispositivo
    # para intentar determinar su tipo/fabricante
    for host in hosts:
        tipo_dispositivo = obtener_tipo_dispositivo(host['mac'])
        G.add_node(host['ip'], 
                  ip=host['ip'], 
                  mac=host['mac'], 
                  tipo=tipo_dispositivo)
        
        # Añadir conexión desde el escáner hacia este host
        G.add_edge(escaner_ip, host['ip'], tipo="descubierto")
    
    # Añadir Gateway/Router si está entre los hosts
    gateway_candidates = [h for h in hosts if h['ip'].endswith('.1') or h['ip'].endswith('.254')]
    if gateway_candidates:
        gateway = gateway_candidates[0]['ip']
        G.nodes[gateway]['tipo'] = 'Router/Gateway'
        
        # Añadir conexiones desde el router a todos los dispositivos
        for host in hosts:
            if host['ip'] != gateway:
                G.add_edge(gateway, host['ip'], tipo="conectado")
    
    # Configurar el estilo para modo oscuro
    plt.style.use('dark_background')
    
    # Configurar el tamaño de la figura
    fig = plt.figure(figsize=(14, 10))
    
    # Crear un diseño de red con una distribución atractiva
    pos = nx.spring_layout(G, k=0.3, seed=42)
    
    # Crear un mapa de colores neón para modo oscuro
    colors = ['#00FF00', '#FF00FF', '#00FFFF', '#FFFF00', '#FF3366', '#33FF33', '#3366FF', '#FF6633']
    
    # Agrupar nodos por tipo para colorearlos
    node_types = set(nx.get_node_attributes(G, 'tipo').values())
    color_map = {t: colors[i % len(colors)] for i, t in enumerate(node_types)}
    
    # Configurar los ejes
    ax = plt.gca()
    ax.set_facecolor('#111111')
    
    # Dibujar conexiones con estilo neón
    # Conexiones desde el escáner son punteadas
    scanner_edges = [(u, v) for u, v, d in G.edges(data=True) if u == escaner_ip]
    nx.draw_networkx_edges(G, pos, edgelist=scanner_edges, 
                         width=1.5, 
                         alpha=0.7, 
                         edge_color='#00FFFF', 
                         style='dashed',
                         arrows=True, 
                         arrowstyle='-|>', 
                         arrowsize=15)
    
    # Otras conexiones son continuas
    other_edges = [(u, v) for u, v, d in G.edges(data=True) if u != escaner_ip]
    nx.draw_networkx_edges(G, pos, edgelist=other_edges, 
                         width=2.0, 
                         alpha=0.8, 
                         edge_color='#FFFF00',
                         arrows=True, 
                         arrowstyle='-|>', 
                         arrowsize=15)
    
    # Lista para almacenar los nodos correctamente dibujados (con iconos)
    nodos_con_iconos = []
    
    # Añadir los iconos para cada nodo
    for node, node_attrs in G.nodes(data=True):
        # Obtener el tipo de dispositivo para determinar el icono
        tipo = node_attrs.get('tipo', 'Desconocido')
        
        # Obtener la ruta del icono correcto según el tipo
        ruta_icono = None
        if node == escaner_ip:  # Para el escáner, usar específicamente el icono de escáner
            ruta_icono = os.path.join(ICONS_DIR, "scanner.png")
        else:
            ruta_icono = obtener_ruta_icono(tipo)
        
        # Añadir el icono en la posición del nodo
        x, y = pos[node]
        if agregar_icono_al_grafo(fig, ax, x, y, ruta_icono, zoom=0.15):
            nodos_con_iconos.append(node)
        
        # Añadir la etiqueta debajo del nodo
        label_text = f"{node_attrs['ip']}\n{tipo}"
        ax.text(x, y-0.08, label_text,
               horizontalalignment='center',
               verticalalignment='center',
               fontsize=9,
               color=color_map.get(tipo, colors[0]),
               weight='bold',
               bbox=dict(boxstyle="round,pad=0.2", 
                        fc='#222222', 
                        ec='#444444', 
                        alpha=0.8))
    
    # Añadir título con estilo neón
    plt.title(f"Topología de Red - {red}", 
             fontsize=18, 
             fontweight='bold', 
             color='#00FFFF',
             pad=20)
    
    # Leyenda para tipos de dispositivos - CORREGIDO PARA COMPATIBILIDAD
    legend_handles = [plt.Line2D([0], [0], marker='o', color='w',
                              markerfacecolor=color_map.get(tipo, '#1f77b4'), 
                              markersize=10, 
                              label=tipo) 
                   for tipo in node_types]
    
    # Crear la leyenda de manera compatible con todas las versiones de matplotlib
    legend = plt.legend(handles=legend_handles, 
                      loc='upper right',
                      facecolor='#222222', 
                      edgecolor='#444444')
    
    # Configurar el título de la leyenda y colores de manera compatible
    legend.set_title("Tipos de dispositivos")
    plt.setp(legend.get_title(), color='white')
    plt.setp(legend.get_texts(), color='white')
    
    # Añadir información de escaneo con estilo neón
    info_text = (
        f"Escaneo realizado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Interfaz: {iface}\n"
        f"Tiempo de espera: {timeout}s - Reintentos: {retries}\n"
        f"Total de hosts: {len(hosts)}"
    )
    plt.figtext(0.02, 0.02, info_text, 
               color='#00FF00',
               bbox=dict(facecolor='#222222', 
                        edgecolor='#333333', 
                        alpha=0.8))
    
    # Eliminar ejes
    plt.axis('off')
    
    # Añadir un borde con efecto neón alrededor de la figura
    for spine in ax.spines.values():
        spine.set_edgecolor('#00FFFF')
        spine.set_linewidth(2)
    
    # Guardar la imagen
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    topology_filename = f"{RESULTS_DIR}/topologia_red_{timestamp}_dark.png"
    plt.savefig(topology_filename, dpi=300, bbox_inches='tight', facecolor='#111111')
    
    # Cerrar la figura
    plt.close()
    
    return topology_filename, fig

#################################
# CÓDIGO DEL ESCÁNER DE PUERTOS #
#################################

# Constantes para el escáner
COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 
                123: "NTP", 135: "Microsoft RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 
                445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "Microsoft SQL Server", 
                3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP Proxy", 8443: "HTTPS-Alt"}
LOG_DIR = "logs_escaneo"
LOG_FILE = f"{LOG_DIR}/registro_escaneos.txt"
os.makedirs(LOG_DIR, exist_ok=True)

# Configuración de tiempos de escaneo (similar a nmap -T0 a -T5)
TIMING_TEMPLATES = {
    0: {"timeout": 5.0, "threads_max": 5, "scan_delay": 1.5},    # Paranoid - Muy lento y sigiloso
    1: {"timeout": 3.0, "threads_max": 10, "scan_delay": 0.8},   # Sneaky - Lento y sigiloso
    2: {"timeout": 2.0, "threads_max": 20, "scan_delay": 0.4},   # Polite - Moderado
    3: {"timeout": 1.0, "threads_max": 50, "scan_delay": 0.2},   # Normal - Por defecto
    4: {"timeout": 0.5, "threads_max": 100, "scan_delay": 0.1},  # Aggressive - Rápido
    5: {"timeout": 0.3, "threads_max": 200, "scan_delay": 0.0}   # Insane - Muy rápido
}

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

# Funciones de utilidad para el escáner
def log_registro(mensaje, separador=False):
    """Registra un mensaje en el archivo de log único"""
    with open(LOG_FILE, "a") as f:
        if separador:
            separador_texto = "\n" + "="*50 + "\n"
            f.write(separador_texto)
        f.write(mensaje + "\n")

def log_escaneo(ip, puertos_rango, modo_sigilo=False, timing_level=3):
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
Nivel de temporización: T{timing_level}
"""
    
    # Guardar en archivo de texto único
    log_registro(info_escaneo, separador=True)
    
    print(f"\nEscaneo iniciado en: {fecha_hora}")
    print(f"Usuario: {usuario}")
    
    return fecha_hora

# Funciones de escaneo y detección
def detect_service(port):
    return COMMON_PORTS.get(port, "Desconocido")

def analyze_banner(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
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

def os_fingerprinting(ip, timeout=2):
    try:
        conf.verb = 0
        # SYN/ACK y análisis
        syn_resp = sr1(IP(dst=ip)/TCP(dport=80, flags="SA"), timeout=timeout, verbose=0)
        if syn_resp and syn_resp.haslayer(TCP):
            ttl, win = syn_resp[IP].ttl, syn_resp[TCP].window
            if ttl == 64 and win == 29200: return "Linux"
            elif ttl == 128 and win == 8192: return "Windows"
            elif ttl == 255: return "Cisco Router"
        
        # ICMP y análisis
        icmp_resp = sr1(IP(dst=ip)/ICMP(), timeout=timeout, verbose=0)
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
                banner = analyze_banner(ip, port, timeout)
                return port, "Abierto", detect_service(port), banner
            elif flags == 0x14:  # RST
                return port, "Cerrado", detect_service(port), "N/A"
        elif resp.haslayer(ICMP):
            if resp[ICMP].type == 3 and resp[ICMP].code in [1, 2, 3, 9, 10, 13]:
                return port, "Filtrado", detect_service(port), "N/A"
    except:
        pass
    return port, "Desconocido", detect_service(port), "N/A"

def scan_ports(ip, ports, timeout=1, stealth=False, show_only_open=False, timing_level=3):
    results, threads = [], []
    
    # Aplicar configuración de temporización
    timing_config = TIMING_TEMPLATES[timing_level]
    timeout = timing_config["timeout"]
    max_threads = timing_config["threads_max"]
    scan_delay = timing_config["scan_delay"]
    
    active_threads = []
    
    def worker(port):
        result = scan_port(ip, port, timeout, stealth)
        if show_only_open and result[1] != "Abierto": return
        results.append(result)
    
    for port in ports:
        while len(active_threads) >= max_threads:
            # Esperar a que terminen algunos hilos antes de crear más
            active_threads = [t for t in active_threads if t.is_alive()]
            time.sleep(0.1)
            
        # Aplicar retraso entre escaneos según la configuración
        if scan_delay > 0:
            time.sleep(scan_delay)
            
        t = threading.Thread(target=worker, args=(port,))
        active_threads.append(t)
        threads.append(t)
        t.start()
    
    for t in threads: t.join()
    
    return sorted(results, key=lambda x: x[0])

def check_vulns(service_name, version):
    return VULN_DATABASE.get(service_name, {}).get(version, [])

def analyze_vulnerabilities(results):
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

# Clase para la interfaz gráfica del escáner de hosts
class HostScannerGUI:
    def __init__(self, parent_frame):
        # Definir colores para una interfaz con tema oscuro
        self.color_fondo = "#1E202F"
        self.color_panel = "#252836"
        self.color_boton = "#6C5CE7"
        self.color_hover = "#5d4fd1"
        self.color_texto_claro = "#E4E6F3"
        self.color_texto_oscuro = "#8A8D9F"
        self.color_success = "#4CAF50"
        self.color_success_hover = "#388E3C"
        
        # Panel principal (dos columnas)
        self.frame_principal = CTkFrame(parent_frame, fg_color=self.color_fondo)
        self.frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Columna izquierda - Configuración
        self.columna_izq = CTkFrame(self.frame_principal, fg_color=self.color_fondo)
        self.columna_izq.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Panel de configuración
        self.panel_config = CTkFrame(self.columna_izq, fg_color=self.color_panel)
        self.panel_config.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Título
        self.titulo = CTkLabel(self.panel_config, text="Escáner de Hosts en Red", 
                              font=("Arial", 18, "bold"), text_color=self.color_texto_claro)
        self.titulo.pack(pady=(10, 5))
        
        # Panel de entrada
        self.panel_datos = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_datos.pack(fill="x", padx=10, pady=5)
        
        # Red objetivo
        self.label_red = CTkLabel(self.panel_datos, text="Red objetivo:", anchor="w", 
                                text_color=self.color_texto_claro)
        self.label_red.pack(pady=(5, 0), anchor="w")
        
        self.campo_red = CTkEntry(self.panel_datos, placeholder_text="Ej: 192.168.1.0/24", width=200)
        self.campo_red.pack(pady=5, fill="x")
        
        # Interfaz de red
        self.label_iface = CTkLabel(self.panel_datos, text="Interfaz de red:", 
                                  anchor="w", text_color=self.color_texto_claro)
        self.label_iface.pack(pady=(5, 0), anchor="w")
        
        # Combobox para las interfaces
        self.frame_iface = CTkFrame(self.panel_datos, fg_color=self.color_panel)
        self.frame_iface.pack(fill="x", pady=5)
        
        self.ifaces_var = StringVar()
        self.ifaces_combo = CTkComboBox(self.frame_iface, variable=self.ifaces_var, 
                                     values=["Cargando interfaces..."],
                                     width=200)
        self.ifaces_combo.pack(side="left", fill="x", expand=True)
        
        self.refrescar_button = CTkButton(self.frame_iface, text="⟳", 
                                       command=self.cargar_interfaces,
                                       width=30)
        self.refrescar_button.pack(side="right", padx=(5, 0))
        
        # Opciones adicionales
        self.panel_opciones = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_opciones.pack(fill="x", padx=10, pady=5)
        
        # Tiempo de espera
        self.label_timeout = CTkLabel(self.panel_opciones, text="Tiempo de espera (segundos):", 
                                   anchor="w", text_color=self.color_texto_claro)
        self.label_timeout.pack(pady=(5, 0), anchor="w")
        
        self.timeout_slider = CTkSlider(self.panel_opciones, from_=1, to=10, number_of_steps=9,
                                     command=self.update_timeout_label)
        self.timeout_slider.pack(fill="x", pady=5)
        self.timeout_slider.set(5)  # Valor predeterminado: 5 segundos
        
        self.timeout_label = CTkLabel(self.panel_opciones, text="5 segundos", 
                                  text_color=self.color_texto_claro)
        self.timeout_label.pack()
        
        # Reintentos
        self.label_retries = CTkLabel(self.panel_opciones, text="Número de reintentos:", 
                                   anchor="w", text_color=self.color_texto_claro)
        self.label_retries.pack(pady=(5, 0), anchor="w")
        
        self.retries_slider = CTkSlider(self.panel_opciones, from_=1, to=5, number_of_steps=4,
                                     command=self.update_retries_label)
        self.retries_slider.pack(fill="x", pady=5)
        self.retries_slider.set(3)  # Valor predeterminado: 3 reintentos
        
        self.retries_label = CTkLabel(self.panel_opciones, text="3 reintentos", 
                                   text_color=self.color_texto_claro)
        self.retries_label.pack()
        
        # Opción para generar topología
        self.var_topo = IntVar(value=1)
        self.check_topo = CTkCheckBox(self.panel_opciones, text="Generar topología de red", 
                                   variable=self.var_topo,
                                   text_color=self.color_texto_claro,
                                   fg_color=self.color_boton, hover_color=self.color_hover)
        self.check_topo.pack(pady=10, anchor="w")
        
        # Botones
        self.panel_botones = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_botones.pack(fill="x", padx=10, pady=10)
        
        self.boton_escanear = CTkButton(self.panel_botones, text="Iniciar Escaneo", 
                                     command=self.iniciar_escaneo,
                                     fg_color=self.color_success, 
                                     hover_color=self.color_success_hover,
                                     height=40, font=("Arial", 14, "bold"))
        self.boton_escanear.pack(fill="x", pady=10)
        
        # Columna derecha - Resultados
        self.columna_der = CTkFrame(self.frame_principal, fg_color=self.color_fondo)
        self.columna_der.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        self.panel_resultado = CTkFrame(self.columna_der, fg_color=self.color_panel)
        self.panel_resultado.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.titulo_resultado = CTkLabel(self.panel_resultado, text="Resultados del Escaneo", 
                                      font=("Arial", 18, "bold"), text_color=self.color_texto_claro)
        self.titulo_resultado.pack(pady=(10, 5))
        
        # Pestañas para la visualización de resultados
        self.tab_view = CTkTabview(self.panel_resultado, fg_color=self.color_panel,
                                segmented_button_fg_color=self.color_boton,
                                segmented_button_selected_color=self.color_hover,
                                segmented_button_unselected_color=self.color_panel,
                                segmented_button_selected_hover_color=self.color_hover)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Crear pestañas
        self.tab_view.add("Hosts")
        self.tab_view.add("Topología")
        
        # Pestaña 1: Hosts encontrados
        self.frame_hosts = CTkFrame(self.tab_view.tab("Hosts"), fg_color=self.color_panel)
        self.frame_hosts.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Área de texto para mostrar resultados
        self.area_hosts = CTkTextbox(self.frame_hosts, font=("Consolas", 11), 
                                  text_color=self.color_texto_claro)
        self.area_hosts.pack(fill="both", expand=True, padx=5, pady=5)
        self.area_hosts.insert("1.0", "Los resultados del escaneo aparecerán aquí.")
        self.area_hosts.configure(state="disabled")
        
        # Pestaña 2: Topología de red
        self.frame_topologia = CTkFrame(self.tab_view.tab("Topología"), fg_color=self.color_panel)
        self.frame_topologia.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Imagen de topología (placeholder)
        self.label_topologia = CTkLabel(self.frame_topologia, text="La topología de red se mostrará aquí\ndespués del escaneo.", 
                                     font=("Arial", 12), text_color=self.color_texto_claro)
        self.label_topologia.pack(expand=True)
        
        # Barra de estado
        self.frame_estado = CTkFrame(self.panel_resultado, fg_color=self.color_panel, height=30)
        self.frame_estado.pack(fill="x", padx=10, pady=(5, 10))
        
        self.label_estado = CTkLabel(self.frame_estado, text="Listo para escanear", 
                                  text_color=self.color_texto_claro)
        self.label_estado.pack(side="left", padx=10)
        
        self.progress_bar = CTkProgressBar(self.frame_estado, width=150, 
                                       progress_color=self.color_boton)
        self.progress_bar.pack(side="right", padx=10)
        self.progress_bar.set(0)
        
        # Variable para el hilo de escaneo
        self.scan_thread = None
        self.stop_event = threading.Event()
        
        # Cargar interfaces al iniciar
        self.cargar_interfaces()
    
    def cargar_interfaces(self):
        """Carga las interfaces de red disponibles en el combobox"""
        try:
            interfaces = []
            for iface_name, iface_data in conf.ifaces.items():
                if hasattr(iface_data, 'ip') and iface_data.ip != '0.0.0.0' and iface_data.ip:
                    interfaces.append(f"{iface_name}: {iface_data.ip}")
            
            if interfaces:
                self.ifaces_combo.configure(values=interfaces)
                self.ifaces_combo.set(interfaces[0])
            else:
                self.ifaces_combo.configure(values=["No se encontraron interfaces con IP"])
                self.ifaces_combo.set("No se encontraron interfaces con IP")
        except Exception as e:
            print(f"Error al cargar interfaces: {e}")
            self.ifaces_combo.configure(values=["Error al cargar interfaces"])
            self.ifaces_combo.set("Error al cargar interfaces")
    
    def update_timeout_label(self, value):
        """Actualiza la etiqueta de tiempo de espera"""
        timeout = int(value)
        self.timeout_label.configure(text=f"{timeout} segundos")
    
    def update_retries_label(self, value):
        """Actualiza la etiqueta de reintentos"""
        retries = int(value)
        self.retries_label.configure(text=f"{retries} reintentos")
    
    def mostrar_resultado(self, hosts, tiempo_total):
        """Muestra los resultados del escaneo en la interfaz"""
        self.area_hosts.configure(state='normal')
        self.area_hosts.delete("1.0", END)
        
        if hosts:
            texto = f"=== Hosts Descubiertos ===\n\n"
            texto += "| {:^15} | {:^17} | {:^20} |\n".format("Dirección IP", "Dirección MAC", "Tipo de Dispositivo")
            texto += "-" * 60 + "\n"
            
            for host in hosts:
                tipo = obtener_tipo_dispositivo(host['mac'])
                texto += "| {:<15} | {:<17} | {:<20} |\n".format(host['ip'], host['mac'], tipo)
            
            texto += "-" * 60 + "\n\n"
            texto += f"Total de hosts encontrados: {len(hosts)}\n"
            texto += f"Tiempo total de escaneo: {tiempo_total:.2f} segundos"
        else:
            texto = "No se encontraron hosts activos en la red.\n\nPosibles causas:\n"
            texto += "1. No hay hosts activos en esta red\n"
            texto += "2. Un firewall está bloqueando los paquetes ARP\n"
            texto += "3. La interfaz de red no está configurada correctamente\n"
            texto += "4. La red virtual no permite broadcast ARP"
        
        self.area_hosts.insert("1.0", texto)
        self.area_hosts.configure(state='disabled')
    
    def mostrar_topologia(self, imagen_path, figura=None):
        """Muestra la topología de red en la interfaz"""
        # Limpiar frame
        for widget in self.frame_topologia.winfo_children():
            widget.destroy()
        
        if imagen_path and os.path.exists(imagen_path):
            try:
                # Si tenemos la figura, la mostramos en un canvas de matplotlib
                if figura:
                    # Crear canvas de matplotlib
                    canvas = FigureCanvasTkAgg(figura, master=self.frame_topologia)
                    canvas.draw()
                    canvas.get_tk_widget().pack(fill="both", expand=True)
                else:
                    # Sino, cargamos la imagen desde el archivo
                    img = Image.open(imagen_path)
                    img = img.resize((800, 600), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    
                    # Mostrar la imagen
                    label = CTkLabel(self.frame_topologia, image=photo, text="")
                    label.image = photo  # Guardar referencia
                    label.pack(expand=True)
            except Exception as e:
                print(f"Error al mostrar topología: {e}")
                label_error = CTkLabel(self.frame_topologia, 
                                      text=f"Error al cargar la topología: {str(e)}", 
                                      text_color="red")
                label_error.pack(expand=True)
                
                # Botón para abrir la imagen externamente
                boton_abrir = CTkButton(self.frame_topologia, 
                                      text="Abrir imagen en visor externo", 
                                      command=lambda: self.abrir_imagen(imagen_path))
                boton_abrir.pack(pady=10)
        else:
            label = CTkLabel(self.frame_topologia, 
                           text="No se generó ninguna topología", 
                           text_color=self.color_texto_claro)
            label.pack(expand=True)
    
    def abrir_imagen(self, path):
        """Abre una imagen en el visor predeterminado del sistema"""
        try:
            system_platform = sys.platform
            if system_platform == "linux" or system_platform == "linux2":
                os.system(f"xdg-open {path}")
            elif system_platform == "darwin":  # macOS
                os.system(f"open {path}")
            elif system_platform == "win32":
                os.system(f"start {path}")
            else:
                print("No se puede abrir automáticamente en este sistema.")
        except Exception as e:
            print(f"Error al abrir la imagen: {e}")
    
    def iniciar_escaneo(self):
        """Inicia el escaneo de hosts en un hilo separado"""
        # Validar la entrada
        red = self.campo_red.get().strip()
        if not red:
            self.mostrar_error("Por favor, introduce una red en formato CIDR (ej: 192.168.1.0/24).")
            return
        
        # Obtener la interfaz seleccionada
        iface_str = self.ifaces_combo.get()
        if ":" in iface_str:
            iface = iface_str.split(":")[0].strip()
        else:
            iface = None
        
        # Obtener otras opciones
        timeout = int(self.timeout_slider.get())
        retries = int(self.retries_slider.get())
        generar_topo = bool(self.var_topo.get())
        
        # Desactivar botón durante el escaneo
        self.boton_escanear.configure(state="disabled", text="Escaneando...")
        self.update_estado("Iniciando escaneo...", 0.1)
        
        # Reiniciar evento de parada
        self.stop_event.clear()
        
        # Función para ejecutar en un hilo separado
        def run_scan():
            try:
                # Registrar inicio
                start_time = time.time()
                
                # Actualizar interfaz
                self.update_estado(f"Escaneando hosts en {red}...", 0.3)
                
                # Ejecutar escaneo
                hosts = descubrir_hosts(red, iface=iface, timeout=timeout, retries=retries)
                
                if self.stop_event.is_set():
                    return
                
                # Calcular tiempo total
                end_time = time.time()
                total_time = end_time - start_time
                
                # Mostrar resultados en la interfaz
                self.update_estado("Procesando resultados...", 0.8)
                self.mostrar_resultado(hosts, total_time)
                
                # Generar topología si está activado
                if generar_topo and hosts:
                    self.update_estado("Generando topología de red...", 0.9)
                    
                    # Obtener IP del escáner
                    escaner_ip = conf.ifaces[iface].ip if iface else "127.0.0.1"
                    
                    # Generar topología
                    topo_result = generar_topologia_red(hosts, escaner_ip, red, iface, timeout, retries)
                    
                    if topo_result:
                        topo_file, topo_fig = topo_result
                        self.mostrar_topologia(topo_file, topo_fig)
                
                # Finalizar
                self.update_estado(f"Escaneo completado en {total_time:.2f} segundos", 1)
                
            except Exception as e:
                self.mostrar_error(f"Error durante el escaneo: {str(e)}")
            finally:
                # Reactivar botón de escaneo
                self.boton_escanear.configure(state="normal", text="Iniciar Escaneo")
        
        # Iniciar hilo
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def update_estado(self, mensaje, progreso=None):
        """Actualiza el estado del escaneo en la interfaz"""
        self.label_estado.configure(text=mensaje)
        if progreso is not None:
            self.progress_bar.set(progreso)
    
    def mostrar_error(self, mensaje):
        """Muestra un mensaje de error"""
        self.update_estado(f"Error: {mensaje}", 0)
        self.boton_escanear.configure(state="normal", text="Iniciar Escaneo")

# Clase para la interfaz gráfica del escáner de puertos
class PortScannerGUI:
    def __init__(self, parent_frame):
        # Definir colores - usar misma paleta que la interfaz principal
        self.color_fondo = "#1E202F"
        self.color_panel = "#252836"
        self.color_boton = "#6C5CE7"
        self.color_hover = "#5d4fd1"
        self.color_texto_claro = "#E4E6F3"
        self.color_texto_oscuro = "#8A8D9F"
        
        # Colores de acción
        self.color_danger = "#F25757"
        self.color_danger_hover = "#D32F2F"
        self.color_success = "#4CAF50"
        self.color_success_hover = "#388E3C"
        
        # Panel principal (dos columnas)
        self.frame_principal = CTkFrame(parent_frame, fg_color=self.color_fondo)
        self.frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Columna izquierda - Configuración
        self.columna_izq = CTkFrame(self.frame_principal, fg_color=self.color_fondo)
        self.columna_izq.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Panel de configuración
        self.panel_config = CTkFrame(self.columna_izq, fg_color=self.color_panel)
        self.panel_config.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Título
        self.titulo = CTkLabel(self.panel_config, text="Configuración del Escáner", 
                             font=("Arial", 18, "bold"), text_color=self.color_texto_claro)
        self.titulo.pack(pady=(10, 5))
        
        # Panel de entrada
        self.panel_datos = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_datos.pack(fill="x", padx=10, pady=5)
        
        # IP objetivo
        self.label_ip = CTkLabel(self.panel_datos, text="IP objetivo:", anchor="w", 
                               text_color=self.color_texto_claro)
        self.label_ip.pack(pady=(5, 0), anchor="w")
        
        self.campo_ip = CTkEntry(self.panel_datos, placeholder_text="Ej: 192.168.1.1", width=200)
        self.campo_ip.pack(pady=5, fill="x")
        
        # Opciones de puertos
        self.label_puertos = CTkLabel(self.panel_datos, text="Puertos a escanear:", 
                                    anchor="w", text_color=self.color_texto_claro)
        self.label_puertos.pack(pady=(5, 0), anchor="w")
        
        # Variables para las opciones
        self.option_var = IntVar(value=3)  # Default: puertos comunes
        
        # Opciones con RadioButtons
        self.radio_todos = CTkRadioButton(self.panel_datos, text="Todos los puertos (0-65535)", 
                                         variable=self.option_var, value=1, 
                                         text_color=self.color_texto_claro,
                                         fg_color=self.color_boton, hover_color=self.color_hover)
        self.radio_todos.pack(pady=5, anchor="w")
        
        self.radio_rango = CTkRadioButton(self.panel_datos, text="Rango específico", 
                                        variable=self.option_var, value=2,
                                        text_color=self.color_texto_claro,
                                        fg_color=self.color_boton, hover_color=self.color_hover)
        self.radio_rango.pack(pady=5, anchor="w")
        
        # Campo para rango específico
        self.campo_rango = CTkEntry(self.panel_datos, placeholder_text="Ej: 80,443 o 8080-8085", width=200)
        self.campo_rango.pack(pady=5, fill="x")
        
        self.radio_comunes = CTkRadioButton(self.panel_datos, text="Puertos comunes", 
                                          variable=self.option_var, value=3,
                                          text_color=self.color_texto_claro,
                                          fg_color=self.color_boton, hover_color=self.color_hover)
        self.radio_comunes.pack(pady=5, anchor="w")
        
        # Opciones adicionales
        self.panel_opciones = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_opciones.pack(fill="x", padx=10, pady=5)
        
        self.label_opciones = CTkLabel(self.panel_opciones, text="Opciones adicionales:", 
                                     anchor="w", text_color=self.color_texto_claro)
        self.label_opciones.pack(pady=(5, 0), anchor="w")
        
        # Variables para checkboxes
        self.var_stealth = IntVar(value=0)
        self.var_only_open = IntVar(value=1)
        self.var_vulns = IntVar(value=1)
        
        # Checkboxes
        self.check_stealth = CTkCheckBox(self.panel_opciones, text="Modo sigiloso (half-open)", 
                                       variable=self.var_stealth, 
                                       text_color=self.color_texto_claro,
                                       fg_color=self.color_boton, hover_color=self.color_hover)
        self.check_stealth.pack(pady=5, anchor="w")
        
        self.check_only_open = CTkCheckBox(self.panel_opciones, text="Mostrar solo puertos abiertos", 
                                         variable=self.var_only_open,
                                         text_color=self.color_texto_claro,
                                         fg_color=self.color_boton, hover_color=self.color_hover)
        self.check_only_open.pack(pady=5, anchor="w")
        
        self.check_vulns = CTkCheckBox(self.panel_opciones, text="Analizar vulnerabilidades", 
                                     variable=self.var_vulns,
                                     text_color=self.color_texto_claro,
                                     fg_color=self.color_boton, hover_color=self.color_hover)
        self.check_vulns.pack(pady=5, anchor="w")
        
        # Nivel de temporización
        self.panel_tiempo = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_tiempo.pack(fill="x", padx=10, pady=5)
        
        self.label_timing = CTkLabel(self.panel_tiempo, text="Nivel de temporización:", 
                                   anchor="w", text_color=self.color_texto_claro)
        self.label_timing.pack(pady=(5, 0), anchor="w")
        
        self.nivel_texto = CTkLabel(self.panel_tiempo, text="T3: Normal - Equilibrio entre velocidad y precisión", 
                                 anchor="w", text_color=self.color_texto_claro)
        self.nivel_texto.pack(pady=(5, 0), anchor="w")
        
        def actualizar_nivel(valor):
            nivel = int(float(valor))
            descripciones = {
                0: "T0: Paranoid - Muy lento, ideal para evadir IDS",
                1: "T1: Sneaky - Lento y sigiloso",
                2: "T2: Polite - Moderado, menor carga en la red",
                3: "T3: Normal - Equilibrio entre velocidad y precisión",
                4: "T4: Aggressive - Rápido, asume buena conectividad",
                5: "T5: Insane - Muy rápido, puede perder información"
            }
            self.nivel_texto.configure(text=descripciones[nivel])
        
        self.slider_timing = CTkSlider(self.panel_tiempo, from_=0, to=5, number_of_steps=5, 
                                   command=actualizar_nivel,
                                   progress_color=self.color_boton, button_color=self.color_boton, 
                                   button_hover_color=self.color_hover)
        self.slider_timing.pack(fill="x", pady=5)
        self.slider_timing.set(3)  # Default: T3
        
        # Botones
        self.panel_botones = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_botones.pack(fill="x", padx=10, pady=10)
        
        self.boton_escanear = CTkButton(self.panel_botones, text="Iniciar Escaneo", 
                                      command=self.iniciar_escaneo,
                                      fg_color=self.color_success, 
                                      hover_color=self.color_success_hover,
                                      height=40, font=("Arial", 14, "bold"))
        self.boton_escanear.pack(fill="x", pady=10)
        
        # Columna derecha - Resultados
        self.columna_der = CTkFrame(self.frame_principal, fg_color=self.color_fondo)
        self.columna_der.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        self.panel_resultado = CTkFrame(self.columna_der, fg_color=self.color_panel)
        self.panel_resultado.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.titulo_resultado = CTkLabel(self.panel_resultado, text="Resultados del Escaneo", 
                                       font=("Arial", 18, "bold"), text_color=self.color_texto_claro)
        self.titulo_resultado.pack(pady=(10, 5))
        
        # Notebook (pestañas) para organizar resultados
        self.tab_view = CTkTabview(self.panel_resultado, fg_color=self.color_panel, 
                                 segmented_button_fg_color=self.color_boton,
                                 segmented_button_selected_color=self.color_hover,
                                 segmented_button_unselected_color=self.color_panel,
                                 segmented_button_selected_hover_color=self.color_hover)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Crear pestañas
        self.tab_view.add("Puertos")
        self.tab_view.add("Gráfico")
        self.tab_view.add("Vulnerabilidades")
        
                # Pestaña 1: Puertos
        self.area_puertos = CTkTextbox(self.tab_view.tab("Puertos"), font=("Consolas", 11), 
                                     text_color=self.color_texto_claro)
        self.area_puertos.pack(fill="both", expand=True, padx=5, pady=5)
        self.area_puertos.insert("1.0", "Los resultados del escaneo aparecerán aquí.")
        self.area_puertos.configure(state="disabled")
        
        # Pestaña 2: Gráfico
        self.frame_grafico = CTkFrame(self.tab_view.tab("Gráfico"), fg_color=self.color_panel)
        self.frame_grafico.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Espacio para gráfico matplotlib
        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.fig.patch.set_facecolor(self.color_panel)
        self.ax.set_facecolor(self.color_panel)
        self.ax.text(0.5, 0.5, "Ejecute un escaneo para ver el gráfico", 
                    ha='center', va='center', color=self.color_texto_claro, fontsize=12)
        self.ax.axis('off')
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.frame_grafico)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Pestaña 3: Vulnerabilidades
        self.area_vulnerabilidades = CTkTextbox(self.tab_view.tab("Vulnerabilidades"), 
                                             font=("Consolas", 11), text_color=self.color_texto_claro)
        self.area_vulnerabilidades.pack(fill="both", expand=True, padx=5, pady=5)
        self.area_vulnerabilidades.insert("1.0", "El análisis de vulnerabilidades aparecerá aquí si está activado.")
        self.area_vulnerabilidades.configure(state="disabled")
        
        # Estado del escaneo
        self.frame_estado = CTkFrame(self.panel_resultado, fg_color=self.color_panel, height=30)
        self.frame_estado.pack(fill="x", padx=10, pady=(5, 10))
        
        self.label_estado = CTkLabel(self.frame_estado, text="Listo para escanear", 
                                   text_color=self.color_texto_claro)
        self.label_estado.pack(side="left", padx=10)
        
        self.progress_bar = CTkProgressBar(self.frame_estado, width=150, 
                                        progress_color=self.color_boton)
        self.progress_bar.pack(side="right", padx=10)
        self.progress_bar.set(0)
        
        # Variable para el hilo de escaneo
        self.scan_thread = None
        self.stop_event = threading.Event()

    def update_estado(self, mensaje, progreso=None):
        """Actualiza el estado del escaneo en la interfaz"""
        self.label_estado.configure(text=mensaje)
        if progreso is not None:
            self.progress_bar.set(progreso)

    def mostrar_resultados(self, results, os_detected, total_time):
        """Muestra los resultados del escaneo en la interfaz"""
        # Actualizar pestaña de puertos
        self.area_puertos.configure(state='normal')
        self.area_puertos.delete("1.0", END)
        
        if results:
            texto = f"=== Resultados del Escaneo ===\n\n"
            for port, status, service, banner in results:
                texto += f"Puerto {port}: {status} ({service})\n"
                if banner != "N/A":
                    texto += f"  Banner: {banner}\n"
            
            texto += f"\nSistema operativo detectado: {os_detected}\n"
            texto += f"Tiempo total de escaneo: {total_time:.2f} segundos"
        else:
            texto = "No se encontraron puertos abiertos en el rango especificado."
        
        self.area_puertos.insert("1.0", texto)
        self.area_puertos.configure(state='disabled')
        
        # Actualizar gráfico
        if results:
            self.generar_grafico(results)
    
    def generar_grafico(self, results):
        """Genera y muestra el gráfico de resultados"""
        statuses = [s for _, s, _, _ in results]
        counts = {
            "Abiertos": statuses.count("Abierto"), 
            "Cerrados": statuses.count("Cerrado"), 
            "Filtrados": statuses.count("Filtrado")
        }
        
        labels, sizes, colors = [], [], []
        if counts["Abiertos"]: 
            labels.append("Abiertos")
            sizes.append(counts["Abiertos"])
            colors.append("green")
        if counts["Cerrados"]: 
            labels.append("Cerrados")
            sizes.append(counts["Cerrados"])
            colors.append("red")
        if counts["Filtrados"]: 
            labels.append("Filtrados")
            sizes.append(counts["Filtrados"])
            colors.append("yellow")
        
        self.ax.clear()
        if sizes:
            self.ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
            self.ax.set_title("Estado de los puertos", color=self.color_texto_claro)
            self.ax.axis("equal")
        else:
            self.ax.text(0.5, 0.5, "No hay datos para mostrar", 
                       ha='center', va='center', color=self.color_texto_claro, fontsize=12)
            self.ax.axis('off')
        
        self.fig.patch.set_facecolor(self.color_panel)
        self.ax.set_facecolor(self.color_panel)
        for text in self.ax.texts:
            text.set_color(self.color_texto_claro)
        
        self.canvas.draw()
    
    def mostrar_vulnerabilidades(self, vulns):
        """Muestra las vulnerabilidades encontradas"""
        self.area_vulnerabilidades.configure(state='normal')
        self.area_vulnerabilidades.delete("1.0", END)
        
        if vulns:
            texto = "=== Vulnerabilidades Detectadas ===\n\n"
            for port, service, version, cve_id, desc, cvss in vulns:
                texto += f"Puerto {port}: {service} versión {version}\n"
                texto += f"  CVE: {cve_id}\n"
                texto += f"  Descripción: {desc}\n"
                texto += f"  Puntuación CVSS: {cvss}\n\n"
        else:
            texto = "No se encontraron vulnerabilidades conocidas en los servicios detectados."
        
        self.area_vulnerabilidades.insert("1.0", texto)
        self.area_vulnerabilidades.configure(state='disabled')
    
    def iniciar_escaneo(self):
        """Inicia el escaneo de puertos en un hilo separado"""
        # Validar la IP
        ip = self.campo_ip.get().strip()
        if not ip:
            self.mostrar_error("Por favor, introduce una dirección IP válida.")
            return
        
        # Determinar los puertos según la opción seleccionada
        option = self.option_var.get()
        if option == 1:  # Todos los puertos
            ports = range(0, 65536)
            rango_str = "0-65535"
        elif option == 2:  # Rango específico
            port_range = self.campo_rango.get().strip()
            if not port_range:
                self.mostrar_error("Por favor, introduce un rango de puertos válido.")
                return
            
            try:
                ports = set()
                for item in port_range.split(","):
                    if "-" in item:
                        start, end = map(int, item.split("-"))
                        ports.update(range(start, end + 1))
                    else:
                        ports.add(int(item))
                ports = sorted(ports)
                rango_str = port_range
            except ValueError:
                self.mostrar_error("Formato de rango de puertos inválido.")
                return
        elif option == 3:  # Puertos comunes
            ports = COMMON_PORTS.keys()
            rango_str = "Puertos comunes"
        
        # Obtener otras opciones
        stealth = bool(self.var_stealth.get())
        show_only_open = bool(self.var_only_open.get())
        analyze_vulns = bool(self.var_vulns.get())
        timing_level = int(self.slider_timing.get())
        
        # Desactivar botón de escaneo durante el proceso
        self.boton_escanear.configure(state="disabled", text="Escaneando...")
        self.update_estado("Iniciando escaneo...", 0.1)
        
        # Reiniciar evento de parada
        self.stop_event.clear()
        
        # Función para ejecutar en un hilo separado
        def run_scan():
            try:
                # Registrar inicio
                start_time = time.time()
                log_escaneo(ip, rango_str, stealth, timing_level)
                
                # Actualizar interfaz
                self.update_estado(f"Escaneando {ip}, nivel T{timing_level}...", 0.3)
                
                # Ejecutar escaneo
                results = scan_ports(
                    ip, ports, stealth=stealth, 
                    show_only_open=show_only_open, 
                    timing_level=timing_level
                )
                
                if self.stop_event.is_set():
                    return
                
                # Detectar sistema operativo
                self.update_estado("Detectando sistema operativo...", 0.7)
                os_detected = os_fingerprinting(
                    ip, TIMING_TEMPLATES[timing_level]["timeout"]
                )
                
                # Calcular tiempo total
                end_time = time.time()
                total_time = end_time - start_time
                
                # Mostrar resultados en la interfaz
                self.update_estado("Procesando resultados...", 0.8)
                self.mostrar_resultados(results, os_detected, total_time)
                
                # Analizar vulnerabilidades si está activado
                if analyze_vulns and results:
                    self.update_estado("Analizando vulnerabilidades...", 0.9)
                    vulns = analyze_vulnerabilities(results)
                    self.mostrar_vulnerabilidades(vulns)
                
                # Finalizar
                self.update_estado(f"Escaneo completado en {total_time:.2f} segundos", 1)
                
            except Exception as e:
                self.mostrar_error(f"Error durante el escaneo: {str(e)}")
            finally:
                # Reactivar botón de escaneo
                self.boton_escanear.configure(state="normal", text="Iniciar Escaneo")
        
        # Iniciar hilo
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def mostrar_error(self, mensaje):
        """Muestra un mensaje de error"""
        self.update_estado(f"Error: {mensaje}", 0)
        self.boton_escanear.configure(state="normal", text="Iniciar Escaneo")

#############################
# CÓDIGO DEL CHAT ORIGINAL #
#############################

def censurar_mensaje(mensaje):
    """Censura palabras feas en un mensaje"""
    for palabra in PALABRAS_FEAS:
        patron = r'\b' + re.escape(palabra) + r'\b'
        mensaje = re.sub(patron, '*' * len(palabra), mensaje, flags=re.IGNORECASE)
    return mensaje

def enviar_mensaje(socket, username, text_area, entrada, role):
    """Envía un mensaje al servidor"""
    mensaje = entrada.get().strip()
    if not mensaje:  # No enviar mensajes vacíos
        return
    
    # Si es comando administrativo
    if mensaje.startswith('/') and role == "admin":
        if mensaje.startswith('/logs'):
            global recibiendo_logs
            recibiendo_logs = True
            buffer_logs.clear()
        
        socket.sendall(mensaje.encode())
        entrada.delete(0, END)
        return
    
    # Mensaje normal
    socket.sendall(f"[{username}] -> {mensaje}".encode())
    
    # Mostrar localmente (censurado)
    mensaje_censurado = censurar_mensaje(mensaje)
    text_area.configure(state='normal')
    text_area.insert(END, f"[{username}] -> {mensaje_censurado}\n")
    text_area.see(END)
    text_area.configure(state='disabled')
    
    # Limpiar entrada
    entrada.delete(0, END)
    
    # Log local
    with open("chat_local.log", "a") as log:
        log.write(f"[{datetime.datetime.now()}] {username}: {mensaje_censurado}\n")

def es_mensaje_de_log(mensaje):
    """Determina si un mensaje es parte de los logs"""
    if (mensaje.startswith("[20") and "] " in mensaje[:22]):  # Timestamp
        return True
    if any(x in mensaje for x in ["=== LOGS DEL SERVIDOR ===", "=== FIN DE LOS LOGS ===", 
                                 "Obteniendo logs", " SISTEMA: "]):
        return True
    return False

def es_mensaje_admin(mensaje):
    """Determina si un mensaje es administrativo"""
    patrones = [
        "+ Lista de usuarios", "Usuario ", "ERROR: ", "expulsado correctamente",
        "bloqueado por", "desbloqueado", "eliminado", "creado correctamente",
        "Ejecutando:"
    ]
    return any(p in mensaje for p in patrones)

def recibir_mensajes(socket, area_chat, username, ventana, area_admin=None):
    """Recibe mensajes del servidor"""
    global recibiendo_logs, buffer_logs
    
    while True:
        try:
            mensaje = socket.recv(1024).decode()
            if not mensaje:
                break
            
            # Detectar mensajes de expulsión o eliminación de cuenta
            if "Has sido expulsado por " in mensaje or "Tu cuenta ha sido eliminada por " in mensaje or "Has sido bloqueado por " in mensaje:
                area_chat.configure(state='normal')
                area_chat.insert(END, f"\n\n{mensaje}\n\nLa aplicación se cerrará en 5 segundos...\n")
                area_chat.see(END)
                area_chat.configure(state='disabled')
                
                # Cerrar la conexión
                socket.close()
                
                # Programar cierre forzado después de 5 segundos
                ventana.after(5000, lambda: os._exit(0))
                return
            
            # Evitar duplicación de mensajes propios
            if mensaje.startswith(f"[{username}] -> "):
                continue
            
            # Inicio de logs
            if "=== LOGS DEL SERVIDOR ===" in mensaje:
                recibiendo_logs = True
                buffer_logs = [mensaje]
                
                if area_admin:
                    area_admin.configure(state='normal')
                    area_admin.delete("1.0", END)
                    area_admin.insert(END, mensaje)
                    area_admin.configure(state='disabled')
                continue
                
            # Fin de logs
            if "=== FIN DE LOS LOGS ===" in mensaje and recibiendo_logs:
                buffer_logs.append(mensaje)
                recibiendo_logs = False
                
                if area_admin:
                    area_admin.configure(state='normal')
                    area_admin.delete("1.0", END)
                    area_admin.insert(END, "".join(buffer_logs))
                    area_admin.see("1.0")
                    area_admin.configure(state='disabled')
                
                buffer_logs = []
                continue
            
            # Acumulación de logs
            if recibiendo_logs:
                buffer_logs.append(mensaje)
                continue
            
            # Mensaje de log individual
            if es_mensaje_de_log(mensaje) and area_admin:
                area_admin.configure(state='normal')
                area_admin.insert(END, mensaje)
                area_admin.see(END)
                area_admin.configure(state='disabled')
                continue
            
            # Mensaje administrativo
            if area_admin and es_mensaje_admin(mensaje):
                area_admin.configure(state='normal')
                area_admin.delete("1.0", END)
                area_admin.insert(END, mensaje)
                area_admin.see(END)
                area_admin.configure(state='disabled')
            else:
                # Mensaje normal
                area_chat.configure(state='normal')
                area_chat.insert(END, mensaje)
                area_chat.see(END)
                area_chat.configure(state='disabled')
        
        except Exception as e:
            print(f"Error recibiendo mensaje: {e}")
            break

def solicitar_usuarios(socket):
    """Solicita lista de usuarios conectados"""
    socket.sendall("!usuarios".encode())

def salir(socket, username, ventana):
    """Cierra la conexión y la ventana"""
    try:
        socket.sendall(f"\n--El usuario [{username}] se ha desconectado\n".encode())
        socket.close()
    except:
        pass
    ventana.quit()
    ventana.destroy()
    # Forzar cierre completo de la aplicación
    os._exit(0)

def ventana_login():
    """Crea una ventana de inicio de sesión adaptativa y optimizada para diferentes resoluciones"""
    def iniciar_chat():
        username = campo_usuario.get()
        password = campo_password.get()
        
        if not username.strip() or not password.strip():
            label_error.configure(text="Usuario y contraseña son obligatorios")
            return
        
        try:
            # Conectar al servidor
            socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_cliente = ssl._create_unverified_context().wrap_socket(socket_cliente, server_hostname='192.168.56.10')
            socket_cliente.connect((host, port))
            
            # Autenticar
            socket_cliente.sendall(f"{username}:{password}".encode())
            respuesta = socket_cliente.recv(1024).decode()
            
            if respuesta.startswith("ERROR:"):
                label_error.configure(text=respuesta[6:])
                socket_cliente.close()
                return
            
            if respuesta.startswith("AUTH_OK:"):
                role = respuesta.split(":", 1)[1]
                # Ocultar la ventana antes de destruirla para evitar artefactos visuales
                ventana_login.withdraw()
                ventana_login.update()
                ventana_login.destroy()
                iniciar_cliente(username, socket_cliente, role)
            else:
                label_error.configure(text="Error de autenticación")
                socket_cliente.close()
                
        except Exception as e:
            label_error.configure(text=f"Error de conexión: {str(e)}")

    # Configuración
    host = '192.168.56.10'
    port = 12345

    # Definir colores - usar constantes para consistencia
    COLOR_FONDO = "#2d1b54"       # Púrpura muy oscuro para el fondo
    COLOR_CARD = "#523999"        # Púrpura para la tarjeta
    COLOR_CAMPO = "#6647c4"       # Púrpura claro para campos
    COLOR_BOTON = "#ffffff"       # Botón blanco
    COLOR_TEXTO_BTN = "#523999"   # Texto púrpura en botón
    COLOR_TEXTO = "#ffffff"       # Texto blanco
    COLOR_TEXTO_MUTED = "#d9c7ff" # Texto claro para enlaces
    COLOR_ERROR = "#ff6b6b"       # Color para mensajes de error

    # Configuración de escala - usando método correcto según la versión
    # En vez de CTkSettings, usamos directamente métodos de la clase CTk
    set_appearance_mode("dark")  # Asegurar modo oscuro
    set_default_color_theme("blue")  # Tema base
    
    # Crear ventana con mejor configuración
    ventana_login = CTk()
    ventana_login.title("Chat - Login")
    ventana_login.minsize(350, 450)  # Tamaño mínimo para evitar distorsiones
    
    # Calcular tamaño basado en la resolución de pantalla
    ancho_pantalla = ventana_login.winfo_screenwidth()
    alto_pantalla = ventana_login.winfo_screenheight()
    
    # Tamaño adaptativo según resolución
    ancho = min(900, int(ancho_pantalla * 0.75))
    alto = min(600, int(alto_pantalla * 0.75))
    ventana_login.geometry(f"{ancho}x{alto}")
    
    # Establecer fondo
    ventana_login.configure(fg_color=COLOR_FONDO)
    
    # Función para reajustar el layout cuando cambia el tamaño
    def ajustar_layout(event=None):
        frame_login.place_configure(relx=0.5, rely=0.5, anchor="center")
    
    ventana_login.bind("<Configure>", ajustar_layout)
    
    # Tarjeta central (panel de login) - Usando porcentajes relativos en vez de tamaños fijos
    ancho_login = min(400, int(ancho * 0.8))
    frame_login = CTkFrame(
        ventana_login, 
        fg_color=COLOR_CARD, 
        corner_radius=20, 
        border_width=0,  # Eliminar borde para evitar artefactos
        width=ancho_login,
        height=320
    )
    frame_login.place(relx=0.5, rely=0.5, anchor="center")
    # Establecer propagación para evitar que el tamaño cambie inesperadamente
    frame_login.pack_propagate(False)
    
    # Título
    label_titulo = CTkLabel(
        frame_login, 
        text="Login", 
        font=("Arial", 36, "bold"),
        text_color=COLOR_TEXTO
    )
    label_titulo.pack(pady=(35, 25))
    
    # Campo usuario - Con bordes limpios
    frame_usuario = CTkFrame(frame_login, fg_color=COLOR_CAMPO, corner_radius=20, border_width=0)
    frame_usuario.pack(padx=40, fill="x")
    
    # Icono de usuario
    label_user_icon = CTkLabel(frame_usuario, text="👤", font=("Arial", 14), text_color=COLOR_TEXTO)
    label_user_icon.pack(side="right", padx=(0, 15))
    
    campo_usuario = CTkEntry(
        frame_usuario, 
        placeholder_text="Username",
        placeholder_text_color=COLOR_TEXTO_MUTED,
        fg_color=COLOR_CAMPO,
        bg_color="transparent",
        text_color=COLOR_TEXTO,
        border_width=0,
        height=42
    )
    campo_usuario.pack(side="left", fill="x", padx=(15, 0), expand=True)
    
    # Campo contraseña - Con bordes limpios
    frame_password = CTkFrame(frame_login, fg_color=COLOR_CAMPO, corner_radius=20, border_width=0)
    frame_password.pack(padx=40, fill="x", pady=(20, 0))
    
    # Icono de candado
    label_pass_icon = CTkLabel(frame_password, text="🔒", font=("Arial", 14), text_color=COLOR_TEXTO)
    label_pass_icon.pack(side="right", padx=(0, 15))
    
    campo_password = CTkEntry(
        frame_password, 
        placeholder_text="Password",
        placeholder_text_color=COLOR_TEXTO_MUTED,
        fg_color=COLOR_CAMPO,
        text_color=COLOR_TEXTO,
        border_width=0,
        height=42,
        show="•"
    )
    campo_password.pack(side="left", fill="x", padx=(15, 0), expand=True)
    campo_password.bind("<Return>", lambda _: iniciar_chat())
    
    # Mensaje de error - Área dedicada
    frame_error = CTkFrame(frame_login, fg_color="transparent", height=20)
    frame_error.pack(fill="x", pady=(15, 0))
    
    label_error = CTkLabel(
        frame_error, 
        text="",
        text_color=COLOR_ERROR,
        height=20
    )
    label_error.pack(fill="x")
    
    # Botón de login - Con efectos suavizados
    boton_login = CTkButton(
        frame_login, 
        text="Login", 
        command=iniciar_chat,
        fg_color=COLOR_BOTON,
        hover_color="#f0f0f0",
        text_color=COLOR_TEXTO_BTN,
        height=42,
        corner_radius=20,
        font=("Arial", 16, "bold"),
        border_width=0
    )
    boton_login.pack(fill="x", padx=40, pady=(20, 0))
    
    # Opción "Forgot password?" - Texto más pequeño para evitar problemas de espacio
    label_olvidado = CTkLabel(
        frame_login, 
        text="Forgot password?",
        text_color=COLOR_TEXTO_MUTED,
        font=("Arial", 12),
        cursor="hand2"
    )
    label_olvidado.pack(pady=(15, 30))
    
    # Centrar ventana en pantalla con mejor manejo
    ventana_login.update_idletasks()
    x = (ancho_pantalla - ventana_login.winfo_width()) // 2
    y = (alto_pantalla - ventana_login.winfo_height()) // 2
    ventana_login.geometry(f"+{x}+{y}")
    
    # Forzar actualización para evitar problemas de renderizado
    ventana_login.update()
    
    # Foco inicial
    ventana_login.after(100, lambda: campo_usuario.focus_set())
    
    # Mejorar la transición entre ventanas
    def prepare_destroy():
        ventana_login.withdraw()  # Ocultar ventana antes de destruir
        ventana_login.after(50, ventana_login.destroy)
    
    ventana_login.protocol("WM_DELETE_WINDOW", prepare_destroy)

    ventana_login.mainloop()
    
def crear_panel_admin(frame, socket, area_chat):
    """Crea el panel de administración"""
    
    # Definir colores para una paleta oscura armoniosa
    color_fondo = "#1E202F"       # Color fondo ligeramente más oscuro que el menú
    color_panel = "#252836"       # Color principal (azul oscuro)
    color_boton = "#6C5CE7"       # Color de acento (púrpura suave)
    color_hover = "#5d4fd1"       # Color hover (púrpura más oscuro)
    color_texto_claro = "#E4E6F3" # Color texto claro (casi blanco)
    color_texto_oscuro = "#8A8D9F" # Color texto oscuro (gris)
    
    # Colores de acción
    color_danger = "#F25757"      # Rojo peligro
    color_danger_hover = "#D32F2F" # Rojo peligro hover
    color_success = "#4CAF50"     # Verde éxito
    color_success_hover = "#388E3C" # Verde éxito hover
    
    # Panel principal (dos columnas)
    frame_principal = CTkFrame(frame, fg_color=color_fondo)
    frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Columna izquierda
    columna_izq = CTkFrame(frame_principal, fg_color=color_fondo)
    columna_izq.pack(side="left", fill="both", expand=True, padx=5, pady=5)
    
    # Panel de control
    panel = CTkFrame(columna_izq, fg_color=color_panel)
    panel.pack(fill="both", expand=True, padx=5, pady=5)
    
    # Título
    titulo = CTkLabel(panel, text="Panel de Control", font=("Arial", 18, "bold"), text_color=color_texto_claro)
    titulo.pack(pady=(10, 5))
    
    # Panel de entrada
    panel_datos = CTkFrame(panel, fg_color=color_panel)
    panel_datos.pack(fill="x", padx=10, pady=5)
    
    # Usuario objetivo
    label_usuario = CTkLabel(panel_datos, text="Usuario objetivo:", anchor="w", text_color=color_texto_claro)
    label_usuario.pack(pady=(5, 0), anchor="w")
    
    campo_usuario = CTkEntry(panel_datos, placeholder_text="Nombre de usuario", width=200)
    campo_usuario.pack(pady=5, fill="x")
    
    # Razón
    label_razon = CTkLabel(panel_datos, text="Razón (opcional):", anchor="w", text_color=color_texto_claro)
    label_razon.pack(pady=(5, 0), anchor="w")
    
    campo_razon = CTkEntry(panel_datos, placeholder_text="Razón de la acción", width=200)
    campo_razon.pack(pady=5, fill="x")
    
    # Contraseña
    label_password = CTkLabel(panel_datos, text="Contraseña (para nuevo usuario):", anchor="w", text_color=color_texto_claro)
    label_password.pack(pady=(5, 0), anchor="w")
    
    campo_password = CTkEntry(panel_datos, placeholder_text="Contraseña", width=200, show="*")
    campo_password.pack(pady=5, fill="x")
    
    # Opciones
    panel_opciones = CTkFrame(panel, fg_color=color_panel)
    panel_opciones.pack(fill="x", padx=10, pady=5)
    
    # Crear como admin
    var_admin = IntVar(value=0)
    check_admin = CTkCheckBox(panel_opciones, text="Crear como administrador", variable=var_admin, 
                            text_color=color_texto_claro, fg_color=color_boton, hover_color=color_hover)
    check_admin.pack(pady=5, anchor="w")
    
    # Ban permanente
    var_permanente = IntVar(value=0)
    check_permanente = CTkCheckBox(panel_opciones, text="Baneo permanente", variable=var_permanente,
                                text_color=color_texto_claro, fg_color=color_boton, hover_color=color_hover)
    check_permanente.pack(pady=5, anchor="w")
    
    # Tiempo de ban
    panel_tiempo = CTkFrame(panel, fg_color=color_panel)
    panel_tiempo.pack(fill="x", padx=10, pady=5)
    
    def actualizar_tiempo(valor):
        minutos = int(float(valor))
        if minutos < 60:
            label_tiempo.configure(text=f"Tiempo: {minutos} minutos")
        elif minutos < 1440:
            label_tiempo.configure(text=f"Tiempo: {minutos//60} horas, {minutos%60} minutos")
        else:
            dias = minutos // 1440
            horas = (minutos % 1440) // 60
            label_tiempo.configure(text=f"Tiempo: {dias} días, {horas} horas")
    
    label_tiempo = CTkLabel(panel_tiempo, text="Tiempo: 30 minutos", anchor="w", text_color=color_texto_claro)
    label_tiempo.pack(pady=(5, 0), anchor="w")
    
    slider_tiempo = CTkSlider(panel_tiempo, from_=5, to=1440, number_of_steps=100, command=actualizar_tiempo,
                         progress_color=color_boton, button_color=color_boton, button_hover_color=color_hover)
    slider_tiempo.pack(fill="x", pady=5)
    slider_tiempo.set(30)
    
    # Panel de botones
    panel_botones = CTkFrame(panel, fg_color=color_panel)
    panel_botones.pack(fill="x", padx=10, pady=10)
    
    # Funciones de botones
    def mostrar_error(mensaje):
        area_resultado.configure(state='normal')
        area_resultado.delete("1.0", END)
        area_resultado.insert(END, mensaje)
        area_resultado.configure(state='disabled')
    
    def enviar_comando(comando):
        area_resultado.configure(state='normal')
        area_resultado.delete("1.0", END)
        area_resultado.insert(END, f"Ejecutando: {comando}\n")
        area_resultado.configure(state='disabled')
        socket.sendall(comando.encode())
    
    def expulsar():
        usuario = campo_usuario.get().strip()
        razon = campo_razon.get().strip()
        
        if not usuario:
            mostrar_error("Error: Introduce un nombre de usuario")
            return
            
        comando = f"/kick {usuario}" + (f" {razon}" if razon else "")
        enviar_comando(comando)
        campo_razon.delete(0, END)
    
    def banear():
        usuario = campo_usuario.get().strip()
        razon = campo_razon.get().strip()
        minutos = int(slider_tiempo.get())
        permanente = var_permanente.get()
        
        if not usuario:
            mostrar_error("Error: Introduce un nombre de usuario")
            return
            
        if permanente:
            minutos = 525600  # 1 año

        # Primero ejecutamos el baneo básico
        comando_ban = f"/ban {usuario} {minutos}"
        enviar_comando(comando_ban)
        
        # Si existe una razón, enviamos un comando separado para la razón
        if razon:
            # Usar un nuevo comando específico para establecer la razón del baneo
            socket.sendall(f"/banreason {usuario} {razon}".encode())
    
    def desbanear():
        usuario = campo_usuario.get().strip()
        
        if not usuario:
            mostrar_error("Error: Introduce un nombre de usuario")
            return
            
        comando = f"/unban {usuario}"
        enviar_comando(comando)
    
    def añadir_usuario():
        usuario = campo_usuario.get().strip()
        password = campo_password.get().strip()
        es_admin = var_admin.get()
        
        if not usuario or not password:
            mostrar_error("Error: Completa usuario y contraseña")
            return
            
        # Crear directamente el formato que espera el sistema de usuarios
        # Los usuarios se almacenan como "usuario|contraseña|rol"
        if es_admin:
            comando = f"/adduser {usuario} {password}|admin"
        else:
            comando = f"/adduser {usuario} {password}"
        
        enviar_comando(comando)
        campo_password.delete(0, END)
    
    def eliminar_usuario():
        usuario = campo_usuario.get().strip()
        
        if not usuario:
            mostrar_error("Error: Introduce un nombre de usuario")
            return
        
        comando = f"/deluser {usuario}"
        enviar_comando(comando)
    
    def ver_logs():
        socket.sendall("/logs".encode())
        area_resultado.configure(state='normal')
        area_resultado.delete("1.0", END)
        area_resultado.insert(END, "Obteniendo logs del servidor...\n")
        area_resultado.configure(state='disabled')
    
    # Botones - primera fila
    fila1 = CTkFrame(panel_botones, fg_color=color_panel)
    fila1.pack(fill="x", pady=5)
    
    boton_expulsar = CTkButton(fila1, text="Expulsar", command=expulsar, 
                         fg_color=color_danger, hover_color=color_danger_hover, width=100)
    boton_expulsar.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_ban = CTkButton(fila1, text="Banear", command=banear,
                    fg_color=color_danger, hover_color=color_danger_hover, width=100)
    boton_ban.pack(side="right", padx=2, fill="x", expand=True)
    
    # Botones - segunda fila
    fila2 = CTkFrame(panel_botones, fg_color=color_panel)
    fila2.pack(fill="x", pady=5)
    
    boton_unban = CTkButton(fila2, text="Desbanear", command=desbanear, 
                      fg_color=color_boton, hover_color=color_hover, width=100)
    boton_unban.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_add = CTkButton(fila2, text="Añadir Usuario", command=añadir_usuario,
                    fg_color=color_success, hover_color=color_success_hover, width=100)
    boton_add.pack(side="right", padx=2, fill="x", expand=True)
    
    # Botones - tercera fila
    fila3 = CTkFrame(panel_botones, fg_color=color_panel)
    fila3.pack(fill="x", pady=5)
    
    boton_eliminar = CTkButton(fila3, text="Eliminar Usuario", command=eliminar_usuario,
                         fg_color=color_danger, hover_color=color_danger_hover, width=100)
    boton_eliminar.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_logs = CTkButton(fila3, text="Ver Logs", command=ver_logs,
                     fg_color=color_boton, hover_color=color_hover, width=100)
    boton_logs.pack(side="right", padx=2, fill="x", expand=True)
    
    # Botones - cuarta fila
    fila4 = CTkFrame(panel_botones, fg_color=color_panel)
    fila4.pack(fill="x", pady=5)
    
    boton_usuarios = CTkButton(fila4, text="Ver Usuarios", 
                         command=lambda: socket.sendall("/userlist".encode()), 
                         fg_color=color_boton, hover_color=color_hover, width=100)
    boton_usuarios.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_baneados = CTkButton(fila4, text="Ver Baneados", 
                         command=lambda: socket.sendall("/banlist".encode()), 
                         fg_color=color_boton, hover_color=color_hover, width=100)
    boton_baneados.pack(side="right", padx=2, fill="x", expand=True)
    
    # Columna derecha - Resultados
    columna_der = CTkFrame(frame_principal, fg_color=color_fondo)
    columna_der.pack(side="right", fill="both", expand=True, padx=5, pady=5)
    
    panel_resultado = CTkFrame(columna_der, fg_color=color_panel)
    panel_resultado.pack(fill="both", expand=True, padx=5, pady=5)
    
    titulo_resultado = CTkLabel(panel_resultado, text="Resultados", font=("Arial", 18, "bold"), text_color=color_texto_claro)
    titulo_resultado.pack(pady=(10, 5))
    
    # Área de texto
    area_resultado = CTkTextbox(panel_resultado, font=("Consolas", 11), text_color=color_texto_claro)
    area_resultado.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Scroll mejorado
    area_resultado.bind("<MouseWheel>", lambda e: area_resultado.yview_scroll(int(-1*(e.delta/120)), "units"))
    
    # Contenido inicial
    area_resultado.insert("1.0", "Los resultados de las acciones aparecerán aquí.")
    area_resultado.configure(state="disabled")
    
    return area_resultado

def iniciar_cliente(username, socket, role):
    """Crea la ventana principal del cliente con mejor manejo de resolución"""
    # Definir colores
    color_fondo_menu = "#252836"       # Color principal del menú (azul oscuro)
    color_boton_principal = "#2A2D3E"  # Color de botones principales
    color_hover = "#3A3F55"            # Color hover
    color_texto_claro = "#E4E6F3"      # Color texto claro
    color_texto_oscuro = "#8A8D9F"     # Color texto oscuro
    color_acento = "#6C5CE7"           # Color de acento (púrpura)

    # Crear ventana con mejor gestión de resolución
    ventana = CTk()
    ventana.title(f"CHAT - {username} ({role})")
    
    # Gestión adaptativa del tamaño
    ancho_pantalla = ventana.winfo_screenwidth()
    alto_pantalla = ventana.winfo_screenheight()
    
    # Tamaño adaptativo según resolución
    ancho = min(1000, int(ancho_pantalla * 0.8))
    alto = min(700, int(alto_pantalla * 0.8))
    ventana.geometry(f"{ancho}x{alto}")
    ventana.minsize(800, 500)  # Tamaño mínimo para evitar distorsiones
    
    # Forzar actualización y mostrar ventana cuando esté completamente lista
    ventana.withdraw()
    
    # Menú lateral con estilo actualizado
    menu = CTkFrame(ventana, width=150, fg_color=color_fondo_menu)
    menu.pack(side="left", fill="y")
    menu.pack_propagate(False)  # Mantener el ancho fijo
    
    # Frame superior para logo
    frame_logo = CTkFrame(menu, fg_color="transparent")
    frame_logo.pack(side="top", fill="x", pady=(30, 10))  # Aumentado padding superior de 15 a 30
    
    # Intenta cargar el logo
    try:
        imagen = Image.open("./logo.png")
        imagen = imagen.resize((90, 90))
        logo = ImageTk.PhotoImage(imagen)
        
        label_imagen = CTkLabel(frame_logo, image=logo, text="")
        label_imagen.photo = logo
        label_imagen.pack()
    except Exception as e:
        print(f"Error al cargar la imagen: {e}")
        # Etiqueta de respaldo si no hay logo
        label_app = CTkLabel(frame_logo, text="CHAT APP", font=("Arial", 16, "bold"), text_color=color_texto_claro)
        label_app.pack(pady=10)

    # Panel principal
    panel_principal = CTkFrame(ventana)
    panel_principal.pack(side="right", expand=True, fill="both")

    # Panel de bienvenida
    panel_bienvenida = CTkFrame(panel_principal)
    label_bienvenida = CTkLabel(panel_bienvenida, text=f"Bienvenido al sistema de chat\n\nTu rol es: {role}", font=("Arial", 16))
    label_bienvenida.pack(expand=True)
    
    # Panel de chat con mejor gestión de espacio
    panel_chat = CTkFrame(panel_principal)

    # Área de mensajes
    frame_mensajes = CTkFrame(panel_chat, fg_color='transparent')
    frame_mensajes.pack(side="top", expand=True, fill="both", padx=6, pady=(6, 2))

    area_chat = CTkTextbox(frame_mensajes)
    area_chat.pack(side="left", expand=True, fill="both")

    scrollbar = CTkScrollbar(frame_mensajes, command=area_chat.yview)
    scrollbar.pack(side="right", fill="y")
    area_chat.configure(yscrollcommand=scrollbar.set)
    area_chat.configure(state='disabled')

    # Panel inferior
    panel_inferior = CTkFrame(panel_chat, fg_color="transparent")
    panel_inferior.pack(side="bottom", fill="x", padx=6, pady=(0, 6))

    # Entrada de texto
    panel_entrada = CTkFrame(panel_inferior, fg_color="transparent")
    panel_entrada.pack(fill="x", pady=(0, 6))

    campo_entrada = CTkEntry(panel_entrada)
    campo_entrada.bind("<Return>", lambda _: enviar_mensaje(socket, username, area_chat, campo_entrada, role))
    campo_entrada.pack(side="left", fill="x", expand=True, padx=(0, 6))

    boton_enviar = CTkButton(panel_entrada, text="Enviar", 
                       command=lambda: enviar_mensaje(socket, username, area_chat, campo_entrada, role), 
                       width=50, height=28,
                       fg_color=color_acento,
                       hover_color=color_hover)
    boton_enviar.pack(side="right")

    # Botones de acción (ahora solo tiene el botón de "Usuarios conectados")
    panel_acciones = CTkFrame(panel_inferior, fg_color="transparent")
    panel_acciones.pack(anchor="center")

    boton_usuarios = CTkButton(panel_acciones, text="Usuarios conectados", 
                         command=lambda: solicitar_usuarios(socket), 
                         width=140, height=28,
                         fg_color=color_acento,
                         hover_color=color_hover)
    boton_usuarios.pack(side="left")

    # Panel de administración
    panel_admin = CTkFrame(panel_principal)
    
    area_admin = None
    if role == "admin":
        area_admin = crear_panel_admin(panel_admin, socket, area_chat)
    else:
        label_no_admin = CTkLabel(panel_admin, 
                            text="No tienes acceso al panel de administración.\nContacta con un administrador si necesitas ayuda.",
                            font=("Arial", 16))
        label_no_admin.pack(expand=True)
    
    # NUEVO: Paneles para los escáneres
    panel_escaner_puertos = CTkFrame(panel_principal)
    scanner_puertos_gui = PortScannerGUI(panel_escaner_puertos)
    
    panel_escaner_hosts = CTkFrame(panel_principal)
    scanner_hosts_gui = HostScannerGUI(panel_escaner_hosts)

    # Función para cambiar entre paneles
    def cambiar_panel(panel):
        global recibiendo_logs
        recibiendo_logs = False
        
        for p in [panel_bienvenida, panel_chat, panel_admin, panel_escaner_puertos, panel_escaner_hosts]:
            p.pack_forget()
        panel.pack(expand=True, fill="both")
    
    # Frame central para botones principales
    frame_botones = CTkFrame(menu, fg_color="transparent")
    frame_botones.pack(side="top", fill="x", expand=True, padx=10)
    
    # Estilo de botón para el menú lateral
    boton_estilo = {
        "height": 45,  # Aumentado de 35 a 45
        "corner_radius": 6, 
        "fg_color": color_boton_principal,
        "text_color": color_texto_claro,
        "hover_color": color_hover,
        "anchor": "center"
    }
    
    # Estilo para botones activos/destacados
    boton_estilo_activo = {
        "height": 45,  # Aumentado de 35 a 45
        "corner_radius": 6, 
        "fg_color": color_acento,
        "text_color": color_texto_claro,
        "hover_color": "#5d4fd1",
        "anchor": "center"
    }
    
    # Espacio adicional en la parte superior - Reducido
    espacio_superior = CTkFrame(frame_botones, height=5, fg_color="transparent")
    espacio_superior.pack(pady=5)  # Reducido de 10 a 5
    
    # Botón Chat con icono - Aumentar espacio entre botones
    boton_chat = CTkButton(
        frame_botones, 
        text="💬 Chat", 
        command=lambda: cambiar_panel(panel_chat),
        **boton_estilo_activo
    )
    boton_chat.pack(pady=(0, 15), fill="x")  # Aumentado de 8 a 15

    # Botón Admin con icono - Aumentar espacio entre botones
    if role == "admin":
        boton_admin = CTkButton(
            frame_botones, 
            text="🛠️ Admin", 
            command=lambda: cambiar_panel(panel_admin), 
            **boton_estilo
        )
        boton_admin.pack(pady=(0, 15), fill="x")  # Aumentado de 8 a 15
    
    # Botón Escáner de Puertos - Aumentar espacio entre botones
    boton_escaner_puertos = CTkButton(
        frame_botones, 
        text="🔍 Escáner Puertos", 
        command=lambda: cambiar_panel(panel_escaner_puertos), 
        **boton_estilo
    )
    boton_escaner_puertos.pack(pady=(0, 15), fill="x")  # Aumentado de 8 a 15
    
    # Botón Escáner de Hosts - Aumentar espacio entre botones
    boton_escaner_hosts = CTkButton(
        frame_botones, 
        text="🖥️ Escáner Hosts", 
        command=lambda: cambiar_panel(panel_escaner_hosts), 
        **boton_estilo
    )
    boton_escaner_hosts.pack(pady=(0, 15), fill="x")  # Aumentado de 8 a 15
    
    # Frame inferior para el nombre de usuario - Aumentar espacio inferior
    frame_cuenta = CTkFrame(menu, fg_color="transparent")
    frame_cuenta.pack(side="bottom", fill="x", pady=(5, 30), padx=10)  # Aumentado padding inferior de 15 a 30
    
    # Frame para el usuario con icono
    frame_usuario = CTkFrame(frame_cuenta, fg_color="transparent")
    frame_usuario.pack(fill="x")
    
    # Frame para alinear el icono y nombre de usuario en el centro
    frame_usuario = CTkFrame(frame_cuenta, fg_color="transparent")
    frame_usuario.pack(fill="x")
    
    # Contenedor centrado para los elementos
    frame_usuario_centrado = CTkFrame(frame_usuario, fg_color="transparent")
    frame_usuario_centrado.pack(anchor="center", expand=True)
    
    # Icono de usuario
    label_usuario_icon = CTkLabel(frame_usuario_centrado, text="👤", font=("Arial", 14), text_color=color_texto_claro)
    label_usuario_icon.pack(side="left", padx=(0, 5))
    
    # Nombre de usuario como texto normal
    label_usuario = CTkLabel(frame_usuario_centrado, text=username, font=("Arial", 15), text_color=color_texto_claro)
    label_usuario.pack(side="left")
    
    # Botón de salir
    boton_salir_menu = CTkButton(
        frame_cuenta, 
        text="Salir", 
        command=lambda: salir(socket, username, ventana), 
        fg_color="transparent",
        hover_color=color_hover,
        text_color=color_texto_oscuro,
        height=35,
        font=("Arial", 12, "bold")  # Añadido estilo de fuente
    )
    boton_salir_menu.pack(fill="x", pady=(8, 0))  # Aumentado de 5 a 8

    # Iniciar hilo de recepción
    hilo = threading.Thread(target=recibir_mensajes, args=(socket, area_chat, username, ventana, area_admin))
    hilo.daemon = True
    hilo.start()

    # Mensaje de bienvenida para admins
    if role == "admin":
        area_chat.configure(state='normal')
        area_chat.insert(END, "\nEres administrador. Utiliza la pestaña 'Administración' para gestionar usuarios.\n\n")
        area_chat.see(END)
        area_chat.configure(state='disabled')

    # Mostrar chat al inicio
    cambiar_panel(panel_chat)
    
    # Mostrar ventana cuando esté lista
    ventana.update()
    ventana.deiconify()
    
    # Centrar ventana
    x = (ancho_pantalla - ventana.winfo_width()) // 2
    y = (alto_pantalla - ventana.winfo_height()) // 2
    ventana.geometry(f"+{x}+{y}")
    
    # Forzar actualización para establecer correctamente
    ventana.update()
    
    ventana.mainloop()

# Punto de entrada
if __name__ == '__main__':
    ventana_login()