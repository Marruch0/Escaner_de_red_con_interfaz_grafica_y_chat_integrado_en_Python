#!/usr/bin/env python3
import sys
import os
import time
import datetime
import socket
import urllib.request
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import matplotlib.image as mpimg
from io import BytesIO
from PIL import Image
from scapy.all import Ether, ARP, srp, conf
from matplotlib.offsetbox import OffsetImage, AnnotationBbox

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
    
    print("Iconos disponibles correctamente")

def create_placeholder_icon(path):
    """Crea un icono de marcador de posición simple"""
    img = Image.new('RGBA', (128, 128), (0, 0, 0, 0))
    with open(path, 'wb') as f:
        img.save(f, 'PNG')

def listar_interfaces():
    """Lista las interfaces de red disponibles"""
    print("\nInterfaces de red disponibles:")
    print("=" * 60)
    for i, iface in enumerate(conf.ifaces.keys()):
        print(f"{i+1}. {iface}: {conf.ifaces[iface].ip}/{conf.ifaces[iface].mac}")
    print("=" * 60)

def descubrir_hosts(red, iface=None, timeout=5, retries=3):
    """
    Función dedicada a descubrir hosts en una red específica
    
    Args:
        red: La dirección de red en formato CIDR (ej: 192.168.56.0/24)
        iface: Interfaz de red específica a usar
        timeout: Tiempo de espera para respuestas
        retries: Número de reintentos
    """
    # Mostrar variables iniciales
    print(f"\n=== Iniciando descubrimiento de hosts en {red} ===")
    print(f"Interfaz: {iface or 'Auto'}")
    print(f"Timeout: {timeout} segundos")
    print(f"Reintentos: {retries}")
    
    try:
        # Crear paquete ARP
        ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_layer = ARP(pdst=red)
        paquete = ether_layer / arp_layer
        
        # Enviar paquetes y recibir respuestas
        print("\nEnviando paquetes ARP broadcast...")
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
        
        print(f"\nHosts descubiertos en la red {red}:")
        print("=" * 39)
        print("| {:^15} | {:^17} |".format("Dirección IP", "Dirección MAC"))
        print("=" * 39)
        
        for enviado, recibido in ans:
            ip = recibido.psrc
            mac = recibido.hwsrc
                
            hosts_encontrados.append({'ip': ip, 'mac': mac})
            print("| {:<15} | {:<17} |".format(ip, mac))
        
        print("=" * 39)
        print(f"\nTotal de hosts encontrados: {len(hosts_encontrados)}")
        
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
    
    Args:
        hosts: Lista de diccionarios con 'ip' y 'mac' de cada host
        escaner_ip: IP del dispositivo que realiza el escaneo
        red: Red escaneada en formato CIDR
        iface: Interfaz utilizada
        timeout: Tiempo de espera utilizado
        retries: Reintentos realizados
    """
    if not hosts:
        print("No hay hosts suficientes para generar una topología de red.")
        return
    
    print("\n=== Generando topología de red con iconos y modo oscuro ===")
    
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
    plt.figure(figsize=(14, 10))
    
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
        if agregar_icono_al_grafo(plt.gcf(), ax, x, y, ruta_icono, zoom=0.15):
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
    
    print(f"\nTopología de red en modo oscuro guardada como: {topology_filename}")
    
    # Mostrar la imagen
    try:
        system_platform = sys.platform
        if system_platform == "linux" or system_platform == "linux2":
            os.system(f"xdg-open {topology_filename}")
        elif system_platform == "darwin":  # macOS
            os.system(f"open {topology_filename}")
        elif system_platform == "win32":
            os.system(f"start {topology_filename}")
        else:
            print("La imagen ha sido guardada pero no se puede abrir automáticamente en este sistema.")
    except Exception as e:
        print(f"La imagen ha sido guardada, pero no se pudo abrir automáticamente: {e}")
    
    plt.close()
    
    return topology_filename

def main():
    # Verificar privilegios
    if os.geteuid() != 0:
        print("ADVERTENCIA: Este script requiere privilegios de superusuario.")
        print("Por favor, ejecútelo con 'sudo python3 descubrimiento_hosts.py'")
        sys.exit(1)
    
    # Dirección de red para escanear
    red = "192.168.56.0/24"  # Por defecto, la red solicitada
    
    # Listar interfaces disponibles
    listar_interfaces()
    
    # MODIFICADO: Hacer obligatoria la selección de interfaz
    print("\nDebe seleccionar una interfaz de red para continuar.")
    
    iface = None
    while not iface:  # Bucle hasta que se seleccione una interfaz válida
        try:
            idx = int(input("Ingrese el número de la interfaz: ")) - 1
            if 0 <= idx < len(conf.ifaces):
                iface = list(conf.ifaces.keys())[idx]
                print(f"Usando interfaz: {iface}")
            else:
                print("Número de interfaz no válido. Por favor, seleccione una interfaz válida.")
        except ValueError:
            print("Entrada no válida. Debe ingresar un número.")
    
    # Obtener IP del escáner (nuestro dispositivo)
    escaner_ip = conf.ifaces[iface].ip
    
    # Preguntar por el valor de timeout
    timeout = 5
    try:
        timeout_input = input(f"\nTimeout para esperar respuestas (predeterminado: {timeout}s): ")
        if timeout_input:
            timeout = int(timeout_input)
    except ValueError:
        print(f"Valor no válido. Usando timeout predeterminado: {timeout}s")
    
    # Preguntar por el número de reintentos
    retries = 3
    try:
        retries_input = input(f"Número de reintentos (predeterminado: {retries}): ")
        if retries_input:
            retries = int(retries_input)
    except ValueError:
        print(f"Valor no válido. Usando reintentos predeterminados: {retries}")
    
    # Preguntar si se desea generar topología
    generar_topo = input("\n¿Desea generar una topología visual de la red? (s/n): ").lower() == 's'
    
    # Realizar descubrimiento de hosts con broadcast
    print("\nIniciando el descubrimiento de hosts...")
    start_time = time.time()
    hosts = descubrir_hosts(red, iface=iface, timeout=timeout, retries=retries)
    scan_time = time.time() - start_time
    
    # Resumen final
    if hosts:
        print(f"\nEscaneo completado con éxito en {scan_time:.2f} segundos.")
        
        # Generar topología si se solicitó
        if generar_topo:
            topo_file = generar_topologia_red(hosts, escaner_ip, red, iface, timeout, retries)
    else:
        print("\nNo se encontraron hosts activos en la red.")
        print("Posibles causas:")
        print("1. No hay hosts activos en esta red")
        print("2. Un firewall está bloqueando los paquetes ARP")
        print("3. La interfaz de red no está configurada correctamente")
        print("4. La red virtual no permite broadcast ARP")

if __name__ == "__main__":
    main()