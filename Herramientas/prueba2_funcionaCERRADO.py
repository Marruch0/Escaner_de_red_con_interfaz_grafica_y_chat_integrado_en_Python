from scapy.all import IP, TCP, ICMP, sr1, conf, send, time

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
    8081: "HTTP-Alt",
    8083: "PRUEBA FILTRADO",
    8443: "HTTPS-Alt",
    9090: "PRUEBA FILTRADO"

}

def detect_service(port):
    """
    Detecta el servicio asociado a un puerto común.
    """
    return COMMON_PORTS.get(port, "Desconocido")

def detect_os(ip):
    """
    Intenta detectar el sistema operativo detrás de la IP objetivo.
    """
    conf.verb = 0  # Desactiva mensajes de Scapy
    icmp_packet = IP(dst=ip) / ICMP()
    response = sr1(icmp_packet, timeout=1)
    if response is None:
        return "No detectado (posible filtrado ICMP)"
    elif response.haslayer(IP):
        ttl = response[IP].ttl
        if ttl <= 64:
            return "Probablemente Linux/Unix"
        elif ttl <= 128:
            return "Probablemente Windows"
        else:
            return "No identificado"
    return "No detectado"

def fragment_packet(ip_layer, tcp_layer):
    """
    Fragmenta un paquete en partes más pequeñas y configura la bandera MF.
    """
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

def analyze_icmp(response):
    """
    Analiza respuestas ICMP para determinar si un puerto está filtrado.
    """
    if response.haslayer(ICMP):
        icmp_layer = response.getlayer(ICMP)
        if icmp_layer.type == 3:  # Destination Unreachable
            code = icmp_layer.code
            if code in [1, 2, 3, 9, 10, 13]:
                return True  # Filtrado
    return False

def scan_port(ip, port, timeout=1, fragmented=False):
    """
    Escanea el estado de un puerto utilizando paquetes TCP.
    """
    conf.verb = 0
    ip_layer = IP(dst=ip)
    tcp_layer = TCP(dport=port, flags="S")

    if fragmented:
        fragments = fragment_packet(ip_layer, tcp_layer)
        for fragment in fragments:
            send(fragment)
        response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=timeout)
    else:
        syn_packet = ip_layer / tcp_layer
        response = sr1(syn_packet, timeout=timeout)

    if response is None:  # No hay respuesta
        return port, "Filtrado", detect_service(port)

    if response.haslayer(TCP):
        tcp_layer_response = response.getlayer(TCP)
        if tcp_layer_response.flags == 0x12:  # SYN-ACK
            rst_packet = IP(dst=ip) / TCP(dport=port, flags="R")
            send(rst_packet)
            return port, "Abierto", detect_service(port)
        elif tcp_layer_response.flags == 0x14:  # RST
            return port, "Cerrado", detect_service(port)

    if analyze_icmp(response):  # Analiza respuestas ICMP
        return port, "Filtrado", detect_service(port)

    return port, "Desconocido", detect_service(port)

def scan_ports(ip, ports, timeout=1, show_only_open=False, fragmented=False):
    """
    Escanea un rango o lista de puertos en una dirección IP.
    """
    results = []
    for port in ports:
        result = scan_port(ip, port, timeout=timeout, fragmented=fragmented)
        
        # Mostrar resultados según las opciones seleccionadas
        if result:
            if show_only_open:
                if fragmented and result[1] in ["Abierto", "Filtrado"]:
                    results.append(result)
                elif not fragmented and result[1] == "Abierto":
                    results.append(result)
            else:
                results.append(result)  # Mostrar todos los puertos si no se filtran
    return results

def parse_ports(port_range):
    """
    Convierte una cadena de rango de puertos (por ejemplo, "80,443" o "8080-8085")
    en una lista de números de puertos.
    """
    ports = set()
    ranges = port_range.split(",")
    for item in ranges:
        if "-" in item:
            start, end = map(int, item.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    return sorted(ports)

def user_interface():
    """
    Interacción con el usuario para configurar el escaneo.
    """
    print("=== Herramienta de Escaneo de Puertos ===")
    ip = input("Introduce la dirección IP objetivo: ")

    # Selección de puertos
    print("\n¿Qué puertos deseas escanear?")
    print("1. Todos los puertos (0-65535)")
    print("2. Rango específico de puertos")
    print("3. Los puertos más comunes")
    option = input("Selecciona una opción (1, 2 o 3): ")

    if option == "1":
        ports = range(0, 65536)
    elif option == "2":
        port_range = input("Introduce el rango de puertos (por ejemplo: 80,443 o 8080-8085): ")
        ports = parse_ports(port_range)
    elif option == "3":
        ports = COMMON_PORTS.keys()
    else:
        print("Opción no válida. Saliendo...")
        return

    # Mostrar solo puertos abiertos
    show_only_open = input("\n¿Deseas mostrar solo los puertos abiertos? (s/n): ").lower() == "s"

    # Fragmentación
    fragmented = input("\n¿Deseas usar fragmentación en los paquetes? (s/n): ").lower() == "s"

    if fragmented and show_only_open:
        print("\nNota: También se mostrarán los puertos filtrados debido al uso de fragmentación.")

    # Detectar sistema operativo
    os_info = detect_os(ip)
    print(f"\nSistema operativo detectado: {os_info}")

    # Realizar escaneo
    results = scan_ports(ip, ports, timeout=2, show_only_open=show_only_open, fragmented=fragmented)

    # Mostrar resultados
    print("\n=== Resultados del Escaneo ===")
    for port, status, service in results:
        print(f"Puerto {port}: {status} ({service})")

if __name__ == "__main__":
    user_interface()