import socket
import threading
from scapy.all import IP, TCP, ICMP, sr1, send, conf
import time

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
    8083: "PRUEBA FILTRADO",
    9090: "PRUEBA FILTRADO",
}

def detect_service(port):
    """Detectar el servicio asociado a un puerto."""
    return COMMON_PORTS.get(port, "Desconocido")

def fragment_packet(ip_layer, tcp_layer):
    """Fragmentar un paquete en partes más pequeñas."""
    payload = bytes(tcp_layer)
    fragment_size = 8
    fragments = [
        ip_layer / payload[i:i + fragment_size]
        for i in range(0, len(payload), fragment_size)
    ]
    for i, fragment in enumerate(fragments):
        fragment[IP].flags = "MF" if i < len(fragments) - 1 else 0
        fragment[IP].frag = i * (fragment_size // 8)
    return fragments

def analyze_banner(ip, port, service_name):
    """Analizar el banner del servicio en un puerto."""
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            if service_name == "HTTP" or port in [80, 8080, 8443]:
                http_request = 'HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(ip)
                sock.sendall(http_request.encode())
                return sock.recv(1024).decode().strip()
            elif service_name == "SSH" or port == 22:
                return sock.recv(1024).decode().strip()
            else:
                return sock.recv(1024).decode().strip()
    except socket.timeout:
        return "Tiempo de espera agotado para obtener el banner"
    except Exception:
        return "No se ha podido encontrar ningún banner"

def scan_port_tcp(ip, port, timeout=1, stealth=False, fragmented=False, delay=0):
    """Escanear el estado de un puerto TCP."""
    conf.verb = 0
    ip_layer = IP(dst=ip)
    tcp_layer = TCP(dport=port, flags="S")

    if fragmented:
        fragments = fragment_packet(ip_layer, tcp_layer)
        for fragment in fragments:
            send(fragment)
            time.sleep(delay)
        response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=timeout)
    else:
        response = sr1(ip_layer / tcp_layer, timeout=timeout)
        time.sleep(delay)

    # Clasificación de estados
    if response is None:
        # Si no hay respuesta, considerar como filtrado
        return port, "Filtrado", detect_service(port)
    if response.haslayer(TCP):
        flags = response[TCP].flags
        if flags == 0x12:  # SYN-ACK
            if stealth:
                send(IP(dst=ip) / TCP(dport=port, flags="R"))
            return port, "Abierto", detect_service(port)
        elif flags == 0x14:  # RST
            return port, "Cerrado", detect_service(port)
    elif response.haslayer(ICMP):
        icmp_layer = response[ICMP]
        if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
            # ICMP type 3 indica puerto filtrado
            return port, "Filtrado", detect_service(port)
    return port, "Desconocido", detect_service(port)

def scan_ports(ip, ports, timeout=1, stealth=False, fragmented=False, delay=0, show_only_open=False):
    """Escanear varios puertos en paralelo."""
    results = []
    threads = []

    def scan(port):
        result = scan_port_tcp(ip, port, timeout, stealth, fragmented, delay)
        if result is None:  # Ignorar resultados nulos
            return
        if result[1] == "Abierto":
            banner = analyze_banner(ip, port, result[2])
        else:
            banner = "No se ha podido encontrar ningún banner"
        # Incluir puertos filtrados si se usa fragmentación
        if show_only_open and result[1] not in ["Abierto", "Filtrado"]:
            return
        # Si no se usa fragmentación, ignorar puertos filtrados por completo
        if not fragmented and result[1] == "Filtrado":
            return
        results.append((*result, banner))

    for port in ports:
        thread = threading.Thread(target=scan, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Ordenar los resultados por número de puerto
    return sorted(results, key=lambda x: x[0])

def user_interface():
    """Interfaz de usuario para configurar el escaneo."""
    print("=== Herramienta de Escaneo de Puertos ===")
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

    stealth = input("\n¿Deseas realizar un escaneo stealth (half-open)? (s/n): ").lower() == "s"
    fragmented = input("\n¿Deseas usar fragmentación en los paquetes? (s/n): ").lower() == "s"
    show_only_open = input("\n¿Deseas mostrar solo los puertos abiertos? (s/n): ").lower() == "s"

    print("\nSelecciona la velocidad de escaneo:")
    print("0. Paranoid (muy lento)")
    print("1. Sneaky (lento)")
    print("2. Polite (moderado)")
    print("3. Normal (estándar)")
    print("4. Aggressive (rápido)")
    print("5. Insane (muy rápido)")
    speed = int(input("Selecciona el nivel de velocidad (0-5): "))

    speed_settings = {
        0: (5, 10),
        1: (3, 5),
        2: (2, 2),
        3: (1, 0.5),
        4: (0.5, 0.1),
        5: (0.3, 0),
    }
    timeout, delay = speed_settings.get(speed, (1, 0.5))

    print("\nIniciando escaneo...")
    start_time = time.time()

    results = scan_ports(ip, ports, timeout=timeout, stealth=stealth, fragmented=fragmented,
                         delay=delay, show_only_open=show_only_open)

    end_time = time.time()
    total_time = end_time - start_time

    if results:
        print("\n=== Resultados del Escaneo ===")
        for port, status, service, banner in results:
            print(f"Puerto {port}: {status} ({service}) | Banner: {banner}")
    else:
        print("\nNo se encontraron resultados para los puertos seleccionados.")

    print(f"\nTiempo total de escaneo: {total_time:.2f} segundos")

if __name__ == "__main__":
    user_interface()