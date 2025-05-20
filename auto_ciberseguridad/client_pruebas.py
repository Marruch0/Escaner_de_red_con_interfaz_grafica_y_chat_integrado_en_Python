#!/usr/bin/env python3
import socket
import threading
import ssl
from customtkinter import *
from PIL import Image, ImageTk


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
    window.geometry("600x400")  # Adjusted size to accommodate the menu

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

    # Función para cambiar entre frames
    def show_frame(frame_to_show):
        for frame in [welcome_frame, chat_frame, empty_frame]:
            frame.pack_forget()
        frame_to_show.pack(expand=True, fill="both")

    # Botón para la opción de chat
    chat_button = CTkButton(menu_frame, text="Chat", command=lambda: show_frame(chat_frame), width=120, height=28)
    chat_button.pack(pady=10, padx=10)

    # Botón para la opción vacía
    empty_button = CTkButton(menu_frame, text="Opción Vacía", command=lambda: show_frame(empty_frame), width=120, height=28)
    empty_button.pack(pady=10, padx=10)

    # Crear el frame del escáner de puertos
    scanner_frame = port_scanner_window(main_frame)


    # Botón para la opción del escáner de puertos
    scanner_button = CTkButton(menu_frame, text="Escáner de Puertos", command=lambda: show_frame(scanner_frame), width=120, height=28)
    scanner_button.pack(pady=10, padx=10)

    # Mostrar la ventana de bienvenida al inicio
    show_frame(welcome_frame)

    # Agregar el frame del escáner de puertos a la lista de frames
    def show_frame(frame_to_show):
        for frame in [welcome_frame, chat_frame, empty_frame, scanner_frame]:
            frame.pack_forget()
        frame_to_show.pack(expand=True, fill="both")


    thread = threading.Thread(target=receive_message, args=(client_socket, text_widget))
    thread.daemon = True
    thread.start()

    window.mainloop()
    client_socket.close()

def port_scanner_window(main_frame):
    def start_scan():
        target = target_entry.get()
        ports = ports_entry.get()
        if not target.strip() or not ports.strip():
            result_text.configure(state='normal')
            result_text.insert(END, "Error: Debes ingresar un objetivo y un rango de puertos.\n")
            result_text.configure(state='disabled')
            return

        def scan_ports():
            try:
                port_list = parse_ports(ports)
                for port in port_list:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    try:
                        s.connect((target, port))
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        response = s.recv(1024)
                        response = response.decode(errors='ignore').split('\n')
                        result_text.configure(state='normal')
                        result_text.insert(END, f"Puerto {port} está abierto.\n")
                        if response:
                            for line in response:
                                result_text.insert(END, f"{line}\n")
                        result_text.configure(state='disabled')
                        s.close()
                    except (socket.timeout, ConnectionRefusedError):
                        result_text.configure(state='normal')
                        result_text.insert(END, f"Puerto {port} está cerrado o no responde.\n")
                        result_text.configure(state='disabled')
                        s.close()
            except Exception as e:
                result_text.configure(state='normal')
                result_text.insert(END, f"Error: {str(e)}\n")
                result_text.configure(state='disabled')

        threading.Thread(target=scan_ports, daemon=True).start()

    # Crear el frame del escáner de puertos en el main_frame
    scanner_frame = CTkFrame(main_frame)
    
    # Etiqueta de título
    scanner_label = CTkLabel(scanner_frame, text="Escáner de Puertos", font=("Arial", 16))
    scanner_label.pack(pady=10)

    # Campo de entrada para el objetivo
    target_label = CTkLabel(scanner_frame, text="Objetivo (IP o dominio):")
    target_label.pack(pady=(5, 0))
    target_entry = CTkEntry(scanner_frame, width=200)
    target_entry.pack(pady=(0, 10))

    # Campo de entrada para el rango de puertos
    ports_label = CTkLabel(scanner_frame, text="Rango de Puertos (e.g., 20-80):")
    ports_label.pack(pady=(5, 0))
    ports_entry = CTkEntry(scanner_frame, width=200)
    ports_entry.pack(pady=(0, 10))

    # Botón para iniciar el escaneo
    scan_button = CTkButton(scanner_frame, text="Iniciar Escaneo", command=start_scan)
    scan_button.pack(pady=10)

    # Zona de resultados
    result_text = CTkTextbox(scanner_frame, height=10)
    result_text.pack(expand=True, fill="both", padx=10, pady=10)
    result_text.configure(state='disabled')

    return scanner_frame
    try:
        port_list = parse_ports(ports)
        for port in port_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((target, port))
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                response = s.recv(1024)
                response = response.decode(errors='ignore').split('\n')
                result_text.configure(state='normal')
                result_text.insert(END, f"Puerto {port} está abierto.\n")
                if response:
                    for line in response:
                        result_text.insert(END, f"{line}\n")
                result_text.configure(state='disabled')
                s.close()
            except (socket.timeout, ConnectionRefusedError):
                result_text.configure(state='normal')
                result_text.insert(END, f"Puerto {port} está cerrado o no responde.\n")
                result_text.configure(state='disabled')
                s.close()
    except Exception as e:
        result_text.configure(state='normal')
        result_text.insert(END, f"Error: {str(e)}\n")
        result_text.configure(state='disabled')

    threading.Thread(target=scan_ports, daemon=True).start()

    # Crear el frame del escáner de puertos en el main_frame
    scanner_frame = CTkFrame(main_frame)
    
    # Etiqueta de título
    scanner_label = CTkLabel(scanner_frame, text="Escáner de Puertos", font=("Arial", 16))
    scanner_label.pack(pady=10)

    # Campo de entrada para el objetivo
    target_label = CTkLabel(scanner_frame, text="Objetivo (IP o dominio):")
    target_label.pack(pady=(5, 0))
    target_entry = CTkEntry(scanner_frame, width=200)
    target_entry.pack(pady=(0, 10))

    # Campo de entrada para el rango de puertos
    ports_label = CTkLabel(scanner_frame, text="Rango de Puertos (e.g., 20-80):")
    ports_label.pack(pady=(5, 0))
    ports_entry = CTkEntry(scanner_frame, width=200)
    ports_entry.pack(pady=(0, 10))

    # Botón para iniciar el escaneo
    scan_button = CTkButton(scanner_frame, text="Iniciar Escaneo", command=start_scan)
    scan_button.pack(pady=10)

    # Zona de resultados
    result_text = CTkTextbox(scanner_frame, height=10)
    result_text.pack(expand=True, fill="both", padx=10, pady=10)
    result_text.configure(state='disabled')

    return scanner_frame

# Función para analizar el rango de puertos
def parse_ports(ports_str):
    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return range(start, end + 1)
    elif ',' in ports_str:
        return map(int, ports_str.split(','))
    else:
        return [int(ports_str)]

if __name__ == '__main__':
    login_window()
