#!/usr/bin/env python3
import socket
import threading
import ssl
import time
import csv
import re
from customtkinter import *
from PIL import Image, ImageTk
from scapy.all import IP, TCP, ICMP, sr1, send, conf
import datetime

# Configuración global para el modo oscuro
set_appearance_mode("dark")  # Cambiar la apariencia al modo oscuro
set_default_color_theme("dark-blue")  # Tema oscuro azul

# Diccionario de puertos comunes (del escáner original)
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


# Funciones del escaner de puertos
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

# Funciones del cliente de chat
def send_message(client_socket, username, text_widget, entry_widget):
    message = entry_widget.get()
    client_socket.sendall(f"[{username}] -> {message}".encode())

    entry_widget.delete(0, END)
    text_widget.configure(state='normal')
    text_widget.insert(END, f"[{username}] -> {message}\n")
    text_widget.configure(state='disabled')

def receive_message(client_socket, text_widget):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            
            text_widget.configure(state='normal')
            text_widget.insert(END, message)
            text_widget.configure(state='disabled')
        
        except:
            break

def user_request(client_socket):
    client_socket.sendall("!usuarios".encode())

def exit_request(client_socket, username, window):
    client_socket.sendall(f"\n--El usuario [{username}] se ha desconectado\n".encode())
    client_socket.close()
    window.quit()
    window.destroy()

def login_window():
    def start_chat():
        username = username_entry.get()
        if username.strip():  # Validar que el nombre de usuario no esté vacío
            login.destroy()  # Cerrar la ventana de login
            client_program(username)
        else:
            error_label.configure(text="El nombre de usuario no puede estar vacío")

    # Crear la ventana de login
    login = CTk()
    login.title("Login")
    login.geometry("300x400")

    # Frame para el login
    login_frame = CTkFrame(login, fg_color="transparent")
    login_frame.pack(side="left", fill="x", expand=True, padx=(0, 6))

    #Imagen
    image = Image.open("./logo.png")
    image = image.resize((100, 100))
    photo = ImageTk.PhotoImage(image)

    #Label para la imagen
    image_label = CTkLabel(login_frame, image=photo, text="")
    image_label.photo = photo #Esto es para hacer referencia a la imagen
    image_label.pack()



    # Etiqueta de título
    title_label = CTkLabel(login_frame, text="Iniciar Sesión", font=("Arial", 30))
    title_label.pack(pady=10)

    # Campo de entrada para el nombre de usuario
    username_label = CTkLabel(login_frame, text="Nombre de Usuario:")
    username_label.pack(pady=(5))
    username_entry = CTkEntry(login_frame, width=200)  # Ajustar el ancho del Entry
    username_entry.pack(pady=(0))
    username_entry.bind("<Return>", lambda _: start_chat())

    # Etiqueta para mostrar errores
    error_label = CTkLabel(login_frame, text="", text_color="red")
    error_label.pack(pady=(5, 0))

    # Botón para iniciar sesión
    login_button = CTkButton(login_frame, text="Iniciar Sesión", command=start_chat)
    login_button.pack(pady=0)

    login.mainloop()

def client_program(username):
    host = 'localhost'
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = ssl._create_unverified_context().wrap_socket(client_socket, server_hostname='192.168.100.15')
    client_socket.connect((host, port))

    client_socket.sendall(username.encode())

    window = CTk()
    window.title("CHAT")
    window.geometry("800x600")  # Ajustado para acomodar el escáner de puertos

    # Crear el frame del menú lateral
    menu_frame = CTkFrame(window, width=150, fg_color="#2b2b2b")
    menu_frame.pack(side="left", fill="y")

    # Crear el frame principal para el contenido
    main_frame = CTkFrame(window)
    main_frame.pack(side="right", expand=True, fill="both")

    # Frame de bienvenida
    welcome_frame = CTkFrame(main_frame)
    welcome_label = CTkLabel(welcome_frame, text="Bienvenido al sistema de chat", font=("Arial", 16))
    welcome_label.pack(expand=True)
    welcome_frame.pack(expand=True, fill="both")

    # Frame principal del chat
    chat_frame = CTkFrame(main_frame)
    chat_frame.pack(expand=True, fill="both")

    # Zona donde se muestran los mensajes y la barra de scroll
    messages_frame = CTkFrame(chat_frame, fg_color='transparent')
    messages_frame.pack(side="top", expand=True, fill="both", padx=6, pady=(6, 2))

    text_widget = CTkTextbox(messages_frame)
    text_widget.pack(side="left", expand=True, fill="both")

    scrollbar = CTkScrollbar(messages_frame, command=text_widget.yview)
    scrollbar.pack(side="right", fill="y")
    text_widget.configure(yscrollcommand=scrollbar.set)
    text_widget.configure(state='disabled')  # Para evitar que se pueda editar

    # Contenedor inferior para la entrada de texto y botones
    bottom_container = CTkFrame(chat_frame, fg_color="transparent")
    bottom_container.pack(side="bottom", fill="x", padx=6, pady=(0, 6))

    # Entrada de texto y botón de enviar
    input_frame = CTkFrame(bottom_container, fg_color="transparent")
    input_frame.pack(fill="x", pady=(0, 6))

    entry_widget = CTkEntry(input_frame)
    entry_widget.bind("<Return>", lambda _: send_message(client_socket, username, text_widget, entry_widget))
    entry_widget.pack(side="left", fill="x", expand=True, padx=(0, 6))

    send_button = CTkButton(input_frame, text="Enviar", command=lambda: send_message(client_socket, username, text_widget, entry_widget), width=50, height=28)
    send_button.pack(side="right")

    # Botones de acciones ("Usuarios conectados" y "Salir")
    actions_frame = CTkFrame(bottom_container, fg_color="transparent")
    actions_frame.pack(anchor="center")

    users_button = CTkButton(actions_frame, text="Usuarios conectados", command=lambda: user_request(client_socket), width=140, height=28)
    users_button.pack(side="left", padx=(0, 6))

    exit_button = CTkButton(actions_frame, text="Salir", command=lambda: exit_request(client_socket, username, window), width=100, height=28)
    exit_button.pack(side="left")

    # Frame vacío
    empty_frame = CTkFrame(main_frame)
    empty_label = CTkLabel(empty_frame, text="Ventana vacía", font=("Arial", 16))
    empty_label.pack(expand=True)

    # ============= NUEVO CÓDIGO: FRAME DEL ESCÁNER DE PUERTOS =============
    scanner_frame = CTkFrame(main_frame)
    
    # Título del escáner
    scanner_title = CTkLabel(scanner_frame, text="Escáner de Puertos", font=("Arial", 20, "bold"))
    scanner_title.pack(pady=(15, 10))
    
    # Contenedor principal dividido en dos columnas
    main_container = CTkFrame(scanner_frame, fg_color="transparent")
    main_container.pack(fill="both", expand=True, padx=15, pady=5)
    
    # Columna izquierda para configuración
    config_frame = CTkFrame(main_container)
    config_frame.pack(side="left", fill="both", expand=True, padx=(0, 5), pady=5)
    
    # 1. Configuración de la dirección IP objetivo
    ip_frame = CTkFrame(config_frame, fg_color="#2b2b2b")
    ip_frame.pack(fill="x", padx=10, pady=5)
    
    ip_label = CTkLabel(ip_frame, text="Dirección IP objetivo:", font=("Arial", 12))
    ip_label.pack(anchor="w", padx=10, pady=(10, 0))
    
    ip_entry = CTkEntry(ip_frame, width=200)
    ip_entry.pack(fill="x", padx=10, pady=(5, 0))
    
    ip_error_label = CTkLabel(ip_frame, text="", text_color="red", font=("Arial", 10))
    ip_error_label.pack(anchor="w", padx=10, pady=(0, 10))
    
    # 2. Selección de puertos a escanear
    ports_frame = CTkFrame(config_frame, fg_color="#2b2b2b")
    ports_frame.pack(fill="x", padx=10, pady=5)
    
    ports_label = CTkLabel(ports_frame, text="Puertos a escanear:", font=("Arial", 12))
    ports_label.pack(anchor="w", padx=10, pady=(10, 5))
    
    port_selection_var = StringVar(value="common")
    
    common_ports_radio = CTkRadioButton(ports_frame, text="Puertos comunes", variable=port_selection_var, value="common")
    common_ports_radio.pack(anchor="w", padx=10, pady=2)
    
    all_ports_radio = CTkRadioButton(ports_frame, text="Todos los puertos (0-65535)", variable=port_selection_var, value="all")
    all_ports_radio.pack(anchor="w", padx=10, pady=2)
    
    range_ports_radio = CTkRadioButton(ports_frame, text="Rango específico", variable=port_selection_var, value="range")
    range_ports_radio.pack(anchor="w", padx=10, pady=2)
    
    port_range_frame = CTkFrame(ports_frame, fg_color="transparent")
    port_range_frame.pack(fill="x", padx=10, pady=(0, 10))
    
    port_range_entry = CTkEntry(port_range_frame, placeholder_text="Ej: 80,443 o 8080-8085")
    port_range_entry.pack(side="left", fill="x", expand=True)
    
    port_error_label = CTkLabel(ports_frame, text="", text_color="red", font=("Arial", 10))
    port_error_label.pack(anchor="w", padx=10, pady=(0, 10))
    
    # 3. Opciones avanzadas
    options_frame = CTkFrame(config_frame, fg_color="#2b2b2b")
    options_frame.pack(fill="x", padx=10, pady=5)
    
    options_label = CTkLabel(options_frame, text="Opciones avanzadas:", font=("Arial", 12))
    options_label.pack(anchor="w", padx=10, pady=(10, 5))
    
    stealth_var = BooleanVar(value=False)
    stealth_check = CTkCheckBox(options_frame, text="Escaneo stealth (half-open)", variable=stealth_var)
    stealth_check.pack(anchor="w", padx=10, pady=2)
    
    fragment_var = BooleanVar(value=False)
    fragment_check = CTkCheckBox(options_frame, text="Fragmentación de paquetes", variable=fragment_var)
    fragment_check.pack(anchor="w", padx=10, pady=2)
    
    show_only_open_var = BooleanVar(value=False)
    show_only_open_check = CTkCheckBox(options_frame, text="Mostrar solo puertos abiertos", variable=show_only_open_var)
    show_only_open_check.pack(anchor="w", padx=10, pady=(2, 10))
    
    # 4. Velocidad de escaneo
    speed_frame = CTkFrame(config_frame, fg_color="#2b2b2b")
    speed_frame.pack(fill="x", padx=10, pady=5)
    
    speed_label = CTkLabel(speed_frame, text="Velocidad de escaneo:", font=("Arial", 12))
    speed_label.pack(anchor="w", padx=10, pady=(10, 5))
    
    speed_var = IntVar(value=3)  # Normal por defecto
    
    speed_options = [
        ("Paranoid (muy lento)", 0),
        ("Sneaky (lento)", 1),
        ("Polite (moderado)", 2),
        ("Normal (estándar)", 3),
        ("Aggressive (rápido)", 4),
        ("Insane (muy rápido)", 5)
    ]
    
    for text, value in speed_options:
        speed_radio = CTkRadioButton(speed_frame, text=text, variable=speed_var, value=value)
        speed_radio.pack(anchor="w", padx=10, pady=2)
    
    speed_info_label = CTkLabel(speed_frame, text="Normal: Timeout=1s, Delay=0.5s", font=("Arial", 10))
    speed_info_label.pack(anchor="w", padx=10, pady=(2, 10))
    
    def update_speed_info(value=None):
        speed_settings = {
            0: (5, 10),
            1: (3, 5),
            2: (2, 2),
            3: (1, 0.5),
            4: (0.5, 0.1),
            5: (0.3, 0),
        }
        current_speed = speed_var.get()
        timeout, delay = speed_settings.get(current_speed)
        speed_info_label.configure(text=f"Timeout={timeout}s, Delay={delay}s")
    
    # Actualizar etiqueta cuando cambia la selección
    speed_var.trace_add("write", lambda *args: update_speed_info())
    update_speed_info()  # Inicializar con valores predeterminados
    
    # Columna derecha para los resultados y logs
    results_frame = CTkFrame(main_container)
    results_frame.pack(side="right", fill="both", expand=True, padx=(5, 0), pady=5)
    
    # 5. Tabla de resultados
    results_table_frame = CTkFrame(results_frame, fg_color="#2b2b2b")
    results_table_frame.pack(fill="both", expand=True, padx=10, pady=5)
    
    results_label = CTkLabel(results_table_frame, text="Resultados del escaneo:", font=("Arial", 12))
    results_label.pack(anchor="w", padx=10, pady=(10, 5))
    
    # Crear el área de resultados con scroll
    results_view_frame = CTkFrame(results_table_frame)
    results_view_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    # Crear vista tabular para resultados
    results_text = CTkTextbox(results_view_frame, font=("Courier", 12))
    results_text.pack(side="left", fill="both", expand=True)
    results_scrollbar = CTkScrollbar(results_view_frame, command=results_text.yview)
    results_scrollbar.pack(side="right", fill="y")
    results_text.configure(yscrollcommand=results_scrollbar.set, state="disabled")
    
    # 6. Panel de logs
    logs_frame = CTkFrame(results_frame, fg_color="#2b2b2b", height=150)
    logs_frame.pack(fill="x", padx=10, pady=5)
    logs_frame.pack_propagate(False)  # Evitar que el frame se ajuste a su contenido
    
    logs_label = CTkLabel(logs_frame, text="Logs:", font=("Arial", 12))
    logs_label.pack(anchor="w", padx=10, pady=(10, 5))
    
    logs_text = CTkTextbox(logs_frame, font=("Courier", 10), height=80)
    logs_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    logs_text.configure(state="disabled")
    
    # 7. Barra de progreso y tiempo
    progress_frame = CTkFrame(results_frame, fg_color="#2b2b2b")
    progress_frame.pack(fill="x", padx=10, pady=5)
    
    progress_bar = CTkProgressBar(progress_frame)
    progress_bar.pack(fill="x", padx=10, pady=(10, 5))
    progress_bar.set(0)
    
    time_frame = CTkFrame(progress_frame, fg_color="transparent")
    time_frame.pack(fill="x", padx=10, pady=(0, 10))
    
    elapsed_label = CTkLabel(time_frame, text="Tiempo: 0s", font=("Arial", 10))
    elapsed_label.pack(side="left")
    
    total_ports_label = CTkLabel(time_frame, text="Puertos: 0/0", font=("Arial", 10))
    total_ports_label.pack(side="right")
    
    # 8. Botones de acción
    buttons_frame = CTkFrame(scanner_frame, fg_color="transparent")
    buttons_frame.pack(fill="x", padx=15, pady=(5, 15))
    
    start_button = CTkButton(buttons_frame, text="Iniciar Escaneo", command=None, width=150, height=35, 
                              fg_color="#28a745", hover_color="#218838")
    start_button.pack(side="left", padx=(0, 10))
    
    stop_button = CTkButton(buttons_frame, text="Detener", command=None, width=100, height=35,
                           fg_color="#dc3545", hover_color="#c82333", state="disabled")
    stop_button.pack(side="left", padx=(0, 10))
    
    export_button = CTkButton(buttons_frame, text="Exportar Resultados", command=None, width=150, height=35,
                              state="disabled")
    export_button.pack(side="left")
    
    clear_button = CTkButton(buttons_frame, text="Limpiar", command=None, width=100, height=35)
    clear_button.pack(side="right")
    
    # Variables para controlar el escaneo
    scanning = False
    scan_thread = None
    stop_scan = False
    scan_results = []
    
    # Función para validar la dirección IP
    def validate_ip(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    # Función para validar y procesar el rango de puertos
    def process_port_range(port_range_str):
        ports = set()
        try:
            # Verificar formato como "80,443" o "8080-8085"
            for item in port_range_str.split(","):
                item = item.strip()
                if "-" in item:
                    start, end = map(int, item.split("-"))
                    if start < 0 or end > 65535 or start > end:
                        return None, "Rango de puertos inválido. Debe estar entre 0-65535."
                    ports.update(range(start, end + 1))
                else:
                    port = int(item)
                    if port < 0 or port > 65535:
                        return None, "Puerto inválido. Debe estar entre 0-65535."
                    ports.add(port)
            return sorted(ports), None
        except ValueError:
            return None, "Formato inválido. Use '80,443' o '8080-8085'."
    
    # Función para agregar mensajes al log
    def add_log(message):
        logs_text.configure(state="normal")
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        logs_text.insert(END, f"[{current_time}] {message}\n")
        logs_text.see(END)
        logs_text.configure(state="disabled")
    
    # Función para actualizar el tiempo transcurrido
    def update_elapsed_time(start_time):
        while scanning:
            elapsed = time.time() - start_time
            elapsed_label.configure(text=f"Tiempo: {elapsed:.1f}s")
            time.sleep(0.1)
    
    # Función para actualizar los resultados en la tabla
    def update_results(result):
        port, status, service, banner = result
        
        results_text.configure(state="normal")
        
        # Usar colores según el estado del puerto
        if status == "Abierto":
            color = "#28a745"  # Verde
        elif status == "Cerrado":
            color = "#dc3545"  # Rojo
        elif status == "Filtrado":
            color = "#ffc107"  # Amarillo
        else:
            color = "white"
            
        # Formato tabular para resultados
        port_str = str(port).ljust(8)
        status_str = status.ljust(10)
        service_str = service.ljust(15)
        
        results_text.insert(END, f"{port_str}{status_str}{service_str}\n")
        
        # Colorear según el estado
        line_start = results_text.index("end-2c linestart")
        line_end = results_text.index("end-1c")
        
        if status == "Abierto":
            results_text.tag_add(f"open_{port}", line_start, line_end)
            results_text.tag_configure(f"open_{port}", foreground=color)
        
        results_text.see(END)
        results_text.configure(state="disabled")
    
    # Función para escanear un puerto individual
    def scan_port_wrapper(ip, port, timeout, stealth, fragmented, delay, ports_total, ports_done):
        nonlocal stop_scan
        
        if stop_scan:
            return None
        
        add_log(f"Escaneando puerto {port}...")
        result = scan_port_tcp(ip, port, timeout, stealth, fragmented, delay)
        
        if result and result[1] == "Abierto":
            banner = analyze_banner(ip, port, result[2])
            result = (*result, banner)
        else:
            result = (*result, "No disponible")
        
        # Actualizar progreso
        ports_done.append(1)
        progress = len(ports_done) / ports_total
        progress_bar.set(progress)
        total_ports_label.configure(text=f"Puertos: {len(ports_done)}/{ports_total}")
        
        return result
    
    # Función principal para iniciar el escaneo
    def start_scan():
        nonlocal scanning, scan_thread, stop_scan, scan_results
        
        # Validar IP
        ip = ip_entry.get().strip()
        if not validate_ip(ip):
            ip_error_label.configure(text="Dirección IP inválida")
            return
        else:
            ip_error_label.configure(text="")
        
        # Determinar puertos a escanear
        port_selection = port_selection_var.get()
        
        if port_selection == "common":
            ports = list(COMMON_PORTS.keys())
        elif port_selection == "all":
            ports = list(range(0, 65536))
        elif port_selection == "range":
            port_range_str = port_range_entry.get().strip()
            if not port_range_str:
                port_error_label.configure(text="Ingrese un rango de puertos")
                return
                
            ports, error = process_port_range(port_range_str)
            if error:
                port_error_label.configure(text=error)
                return
            else:
                port_error_label.configure(text="")
        
        # Obtener configuraciones
        stealth = stealth_var.get()
        fragmented = fragment_var.get()
        show_only_open = show_only_open_var.get()
        
        speed = speed_var.get()
        speed_settings = {
            0: (5, 10),  # Paranoid
            1: (3, 5),   # Sneaky
            2: (2, 2),   # Polite
            3: (1, 0.5), # Normal
            4: (0.5, 0.1), # Aggressive
            5: (0.3, 0),   # Insane
        }
        timeout, delay = speed_settings.get(speed, (1, 0.5))
        
        # Preparar UI para escaneo
        results_text.configure(state="normal")
        results_text.delete("1.0", END)
        results_text.insert(END, "PUERTO   ESTADO     SERVICIO      \n")
        results_text.insert(END, "------   --------   -------------\n")
        results_text.configure(state="disabled")
        
        logs_text.configure(state="normal")
        logs_text.delete("1.0", END)
        logs_text.configure(state="disabled")
        
        progress_bar.set(0)
        
        start_button.configure(state="disabled")
        stop_button.configure(state="normal")
        export_button.configure(state="disabled")
        
        # Iniciar escaneo
        add_log(f"Iniciando escaneo de {len(ports)} puertos en {ip}")
        add_log(f"Configuración: Stealth={stealth}, Fragmentado={fragmented}, Timeout={timeout}s, Delay={delay}s")
        
        scanning = True
        stop_scan = False
        scan_results = []
        
        # Iniciar cronómetro
        start_time = time.time()
        timer_thread = threading.Thread(target=update_elapsed_time, args=(start_time,))
        timer_thread.daemon = True
        timer_thread.start()
        
        # Función para ejecutar el escaneo en segundo plano
        def run_scan():
            nonlocal scanning, scan_results
            
            ports_done = []
            ports_total = len(ports)
            threads = []
            max_threads = 20 if speed >= 4 else 10 if speed >= 2 else 5
            
            # Crear lotes de puertos para procesar
            port_batches = [ports[i:i+max_threads] for i in range(0, len(ports), max_threads)]
            
            try:
                for batch in port_batches:
                    if stop_scan:
                        break
                        
                    batch_threads = []
                    batch_results = []
                    
                    for port in batch:
                        if stop_scan:
                            break
                            
                        # Crear y ejecutar hilo para cada puerto en el lote
                        thread = threading.Thread(
                            target=lambda p=port, b=batch_results: 
                                b.append(scan_port_wrapper(ip, p, timeout, stealth, fragmented, delay, ports_total, ports_done))
                        )
                        thread.daemon = True
                        batch_threads.append(thread)
                        thread.start()
                    
                    # Esperar a que termine el lote actual
                    for thread in batch_threads:
                        thread.join()
                    
                    # Procesar resultados del lote
                    for result in batch_results:
                        if result:
                            scan_results.append(result)
                            # Solo mostrar según filtros
                            if show_only_open and result[1] != "Abierto":
                                continue
                            if not fragmented and result[1] == "Filtrado":
                                continue
                            # Actualizar UI con resultados
                            update_results(result)
            
            except Exception as e:
                add_log(f"Error durante el escaneo: {str(e)}")
            
            # Finalizar escaneo
            end_time = time.time()
            scanning = False
            
            # Actualizar UI
            add_log(f"Escaneo completado. Tiempo total: {end_time - start_time:.2f}s")
            add_log(f"Puertos totales: {len(ports)}, Escaneados: {len(ports_done)}")
            add_log(f"Puertos abiertos: {sum(1 for r in scan_results if r[1] == 'Abierto')}")
            
            start_button.configure(state="normal")
            stop_button.configure(state="disabled")
            export_button.configure(state="normal")
        
        # Iniciar escaneo en segundo plano
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    # Función para detener el escaneo
    def stop_scan_func():
        nonlocal stop_scan
        
        if scanning:
            stop_scan = True
            add_log("Deteniendo escaneo...")
            stop_button.configure(state="disabled")
    
    # Función para limpiar la interfaz
    def clear_ui():
        if not scanning:
            # Limpiar resultados
            results_text.configure(state="normal")
            results_text.delete("1.0", END)
            results_text.configure(state="disabled")
            
            # Limpiar logs
            logs_text.configure(state="normal")
            logs_text.delete("1.0", END)
            logs_text.configure(state="disabled")
            
            # Resetear progreso
            progress_bar.set(0)
            elapsed_label.configure(text="Tiempo: 0s")
            total_ports_label.configure(text="Puertos: 0/0")
            
            # Limpiar errores
            ip_error_label.configure(text="")
            port_error_label.configure(text="")
    
    # Función para exportar resultados
    def export_results():
        if not scan_results:
            add_log("No hay resultados para exportar")
            return
            
        try:
            # Crear nombre de archivo con timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.csv"
            
            with open(filename, "w", newline="") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["Puerto", "Estado", "Servicio", "Banner"])
                
                for result in scan_results:
                    writer.writerow(result)
            
            add_log(f"Resultados exportados a {filename}")
        except Exception as e:
            add_log(f"Error al exportar resultados: {str(e)}")
    
    # Configurar acciones de los botones
    start_button.configure(command=start_scan)
    stop_button.configure(command=stop_scan_func)
    clear_button.configure(command=clear_ui)
    export_button.configure(command=export_results)
    
    # Mostrar banner de información sobre paquetes
    def show_banner_info(event):
        # Esta función se activaría al hacer doble clic en un resultado
        try:
            # Obtener línea seleccionada
            line = results_text.get("current linestart", "current lineend")
            if line and len(line.split()) >= 1:
                port = int(line.split()[0])
                for result in scan_results:
                    if result[0] == port:
                        # Crear ventana emergente con detalles del banner
                        banner_window = CTkToplevel(window)
                        banner_window.title(f"Detalles del puerto {port}")
                        banner_window.geometry("500x300")
                        
                        banner_frame = CTkFrame(banner_window)
                        banner_frame.pack(fill="both", expand=True, padx=10, pady=10)
                        
                        port_label = CTkLabel(banner_frame, 
                                            text=f"Puerto: {port} - {result[1]} - {result[2]}", 
                                            font=("Arial", 16, "bold"))
                        port_label.pack(anchor="w", padx=10, pady=10)
                        
                        banner_label = CTkLabel(banner_frame, text="Banner:", font=("Arial", 12))
                        banner_label.pack(anchor="w", padx=10, pady=(10, 0))
                        
                        banner_text = CTkTextbox(banner_frame, height=200)
                        banner_text.pack(fill="both", expand=True, padx=10, pady=10)
                        banner_text.insert("1.0", result[3] if result[3] else "No se ha encontrado ningún banner")
                        banner_text.configure(state="disabled")
                        
                        break
        except Exception as e:
            add_log(f"Error al mostrar información: {str(e)}")
    
    # Configurar evento de doble clic para mostrar detalles del banner
    results_text.bind("<Double-Button-1>", show_banner_info)
    
    # Realizar validación en tiempo real para la IP
    def validate_ip_input(*args):
        ip = ip_entry.get().strip()
        if ip and not validate_ip(ip):
            ip_error_label.configure(text="Dirección IP inválida")
        else:
            ip_error_label.configure(text="")
    
    # Añadir traza para validación de IP
    ip_var = StringVar()
    ip_var.trace_add("write", validate_ip_input)
    ip_entry.configure(textvariable=ip_var)
    
    # Configuración de visibilidad del campo de rango de puertos
    def update_port_range_visibility(*args):
        if port_selection_var.get() == "range":
            port_range_frame.pack(fill="x", padx=10, pady=(0, 10))
        else:
            port_range_frame.pack_forget()
    
    # Añadir traza para la visibilidad del rango de puertos
    port_selection_var.trace_add("write", update_port_range_visibility)
    update_port_range_visibility()  # Configuración inicial
    
    # Función para cambiar entre frames
    def show_frame(frame_to_show):
        for frame in [welcome_frame, chat_frame, empty_frame, scanner_frame]:
            frame.pack_forget()
        frame_to_show.pack(expand=True, fill="both")

    # Botón para la opción de chat
    chat_button = CTkButton(menu_frame, text="Chat", command=lambda: show_frame(chat_frame), width=120, height=28)
    chat_button.pack(pady=10, padx=10)

    # Botón para la opción del escáner de puertos
    scanner_button = CTkButton(menu_frame, text="Escáner de Puertos", command=lambda: show_frame(scanner_frame), width=120, height=28)
    scanner_button.pack(pady=10, padx=10)

    # Botón para la opción vacía
    empty_button = CTkButton(menu_frame, text="Opción Vacía", command=lambda: show_frame(empty_frame), width=120, height=28)
    empty_button.pack(pady=10, padx=10)

    # Mostrar la ventana de bienvenida al inicio
    show_frame(welcome_frame)

    thread = threading.Thread(target=receive_message, args=(client_socket, text_widget))
    thread.daemon = True
    thread.start()

    window.mainloop()
    client_socket.close()

if __name__ == '__main__':
    login_window()