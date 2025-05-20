import socket
import threading
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf
import time
import matplotlib.pyplot as plt
import os
import platform

# Diccionario de puertos comunes
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "Microsoft RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy",
    8443: "HTTPS-Alt",
}

def detect_service(port):
    """Detectar el servicio asociado a un puerto."""
    return COMMON_PORTS.get(port, "Desconocido")

def analyze_banner(ip, port):
    """
    Obtener el banner del servicio en el puerto especificado.
    Esto proporciona información adicional sobre el servicio en ejecución.
    """
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.settimeout(5)
            # Enviar una solicitud específica según el puerto
            if port in [80, 8080, 8443]:  # HTTP/HTTPS
                http_request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(http_request.encode())
            elif port == 21:  # FTP
                sock.sendall(b"USER anonymous\r\n")
            elif port == 25:  # SMTP
                sock.sendall(b"HELO test\r\n")
            # Recibir el banner del servicio
            banner = sock.recv(1024).decode().strip()
            return banner
    except socket.timeout:
        return "Sin respuesta (timeout)"
    except Exception as e:
        return f"Error al obtener el banner: {e}"

def os_fingerprinting(ip):
    """
    Detectar el sistema operativo del objetivo utilizando técnicas de fingerprinting.
    """
    try:
        conf.verb = 0  # Desactivar salida de Scapy

        # 1. Enviar paquete SYN/ACK y analizar la respuesta
        syn_ack_pkt = IP(dst=ip) / TCP(dport=80, flags="SA")
        syn_ack_resp = sr1(syn_ack_pkt, timeout=2, verbose=0)
        if syn_ack_resp and syn_ack_resp.haslayer(TCP):
            ttl = syn_ack_resp[IP].ttl
            window_size = syn_ack_resp[TCP].window

            # Comparar TTL y tamaño de ventana con una base de datos simple
            if ttl == 64 and window_size == 29200:
                return "Linux Kernel 2.4/2.6"
            elif ttl == 128 and window_size == 8192:
                return "Windows"
            elif ttl == 255:
                return "Cisco Router"
        
        # 2. Enviar paquete ICMP y analizar la respuesta
        icmp_pkt = IP(dst=ip) / ICMP()
        icmp_resp = sr1(icmp_pkt, timeout=2, verbose=0)
        if icmp_resp and icmp_resp.haslayer(ICMP):
            ttl = icmp_resp[IP].ttl
            if ttl == 64:
                return "Linux/Unix"
            elif ttl == 128:
                return "Windows"
        
        # 3. Enviar paquete FIN y analizar la respuesta
        fin_pkt = IP(dst=ip) / TCP(dport=80, flags="F")
        fin_resp = sr1(fin_pkt, timeout=2, verbose=0)
        if not fin_resp:
            return "Sistema operativo que ignora paquetes FIN (posiblemente Linux)"
    except Exception as e:
        print(f"Error al realizar OS fingerprinting: {e}")

    return "Desconocido"

def scan_port_tcp(ip, port, timeout=1, stealth=False, delay=0):
    """Escanear el estado de un puerto TCP."""
    conf.verb = 0
    ip_layer = IP(dst=ip)
    tcp_layer = TCP(dport=port, flags="S", window=1024)

    response = None
    try:
        response = sr1(ip_layer / tcp_layer, timeout=timeout, verbose=0)
        time.sleep(delay)
    except Exception as e:
        print(f"[*] Error al enviar paquetes al puerto {port}: {e}")
        return port, "Error", detect_service(port), "N/A"

    # Clasificación de estados
    if response is None:
        return port, "Filtrado", detect_service(port), "N/A"
    if response.haslayer(TCP):
        flags = response[TCP].flags
        if flags == 0x12:  # SYN-ACK
            if stealth:
                send(IP(dst=ip) / TCP(dport=port, flags="R"))
            banner = analyze_banner(ip, port)
            return port, "Abierto", detect_service(port), banner
        elif flags == 0x14:  # RST
            return port, "Cerrado", detect_service(port), "N/A"
    elif response.haslayer(ICMP):
        icmp_layer = response[ICMP]
        if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
            return port, "Filtrado", detect_service(port), "N/A"
    return port, "Desconocido", detect_service(port), "N/A"

def scan_ports(ip, ports, timeout=1, stealth=False, delay=0, udp_scan=False, show_only_open=False):
    """Escanear varios puertos en paralelo."""
    results = []
    threads = []

    def scan(port):
        if udp_scan:
            result = scan_port_udp(ip, port, timeout)
        else:
            result = scan_port_tcp(ip, port, timeout, stealth, delay)
        if result is None:  # Ignorar resultados nulos
            return
        if show_only_open and result[1] not in ["Abierto"]:
            return
        results.append(result)

    for port in ports:
        thread = threading.Thread(target=scan, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Ordenar los resultados por número de puerto
    return sorted(results, key=lambda x: x[0])

def generate_graph_image(results, filename="scan_results.png"):
    """Generar una gráfica circular y guardarla como archivo PNG."""
    statuses = [status for _, status, _, _ in results]
    open_count = statuses.count("Abierto")
    closed_count = statuses.count("Cerrado")
    filtered_count = statuses.count("Filtrado")

    # Crear listas solo con los estados que tienen valores mayores que cero
    labels = []
    sizes = []
    colors = []
    
    if open_count > 0:
        labels.append("Abiertos")
        sizes.append(open_count)
        colors.append("green")
    
    if closed_count > 0:
        labels.append("Cerrados")
        sizes.append(closed_count)
        colors.append("red")
    
    if filtered_count > 0:
        labels.append("Filtrados")
        sizes.append(filtered_count)
        colors.append("yellow")

    # Crear gráfica circular solo si hay datos para mostrar
    if sizes:  # Verificar que hay al menos un valor
        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
        plt.title("Puertos")
        plt.axis("equal")
        
        # Guardar gráfica como archivo PNG
        plt.savefig(filename)
        plt.close()
        
        # Abrir automáticamente la imagen según el sistema operativo
        try:
            system_platform = platform.system()
            if system_platform == "Linux":
                os.system(f"xdg-open {filename}")
            elif system_platform == "Windows":
                os.system(f"start {filename}")
            elif system_platform == "Darwin":  # macOS
                os.system(f"open {filename}")
            else:
                print(f"Por favor, abre manualmente el archivo: {filename}")
        except Exception as e:
            print(f"Error al intentar abrir la imagen: {e}")

def user_interface():
    """Interfaz de usuario para configurar el escaneo."""
    print("=== Herramienta de Escaneo de Puertos y OS Fingerprinting ===")
    ip = input("Introduce la dirección IP objetivo: ")

    try:
        socket.inet_aton(ip)
    except socket.error:
        print("Dirección IP inválida. Saliendo...")
        return

    print("\n¿Qué puertos deseas escanear?")
    print("1. Todos los puertos (0-65535)")
    print("2. Rango específico de puertos")
    print("3. Los puertos más comunes")
    option = input("Selecciona una opción (1, 2 o 3): ")

    if option == "1":
        ports = range(0, 65536)
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
    elif option == "3":
        ports = COMMON_PORTS.keys()
    else:
        print("Opción no válida. Saliendo...")
        return

    #udp_scan = input("\n¿Deseas realizar un escaneo UDP? (s/n): ").lower() == "s"
    stealth = input("\n¿Deseas realizar un escaneo stealth (half-open)? (s/n): ").lower() == "s"
    show_only_open = input("\n¿Deseas mostrar solo los puertos abiertos? (s/n): ").lower() == "s"

    print("\nIniciando escaneo...")
    start_time = time.time()

    results = scan_ports(ip, ports, timeout=1, stealth=stealth, show_only_open=show_only_open)
    os_detected = os_fingerprinting(ip)

    end_time = time.time()
    total_time = end_time - start_time

    if results:
        print("\n=== Resultados del Escaneo ===")
        for port, status, service, banner in results:
            print(f"Puerto {port}: {status} ({service}) | Banner: {banner}")
        print(f"\nSistema operativo detectado: {os_detected}")
        generate_graph_image(results)  # Llamada para generar y abrir la gráfica
    else:
        print("\nNo se encontraron resultados para los puertos seleccionados.")

    print(f"\nTiempo total de escaneo: {total_time:.2f} segundos")

if __name__ == "__main__":
    user_interface()