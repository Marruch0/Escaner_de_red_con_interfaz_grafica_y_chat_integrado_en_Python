#!/usr/bin/env python3
import socket
import threading
import ssl
from customtkinter import *
from PIL import Image, ImageTk
import re
import datetime

# Lista de palabras soeces (para censura local)
PALABRAS_SOECES = [
    "mierda", "puta", "puto", "joder", "jodido", "cabrón", "cabron", "gilipollas", 
    "idiota", "imbécil", "imbecil", "cojones", "hostia", "coño", "polla", "capullo", 
    "hijo de puta", "hdp", "pendejo", "marica", "maricón", "maricon", "zorra", 
    "follar", "jodete", "cabrona", "maldito", "carajo", "pito", "chinga", "maldita",
    "pene"  # Añadido conforme a la imagen
]

# Función para censurar palabras soeces localmente
def censurar_mensaje(mensaje):
    mensaje_censurado = mensaje
    for palabra in PALABRAS_SOECES:
        patron = r'\b' + re.escape(palabra) + r'\b'
        mensaje_censurado = re.sub(patron, '*' * len(palabra), mensaje_censurado, flags=re.IGNORECASE)
    return mensaje_censurado

def send_message(client_socket, username, text_widget, entry_widget):
    message = entry_widget.get().strip()
    if not message:  # No enviar mensajes vacíos
        return
    
    # Enviar el mensaje original al servidor
    client_socket.sendall(f"[{username}] -> {message}".encode())
    
    # Censurar localmente el mensaje antes de mostrarlo
    mensaje_censurado = censurar_mensaje(message)
    
    # Mostrar el mensaje censurado localmente
    text_widget.configure(state='normal')
    text_widget.insert(END, f"[{username}] -> {mensaje_censurado}\n")
    text_widget.see(END)  # Auto-scroll al final
    text_widget.configure(state='disabled')
    
    # Limpiar el campo de entrada
    entry_widget.delete(0, END)
    
    # Opcional: Registrar el mensaje en un log local
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("chat_local.log", "a", encoding="utf-8") as log:
        if mensaje_censurado != message:
            log.write(f"[{timestamp}] {username}: {mensaje_censurado} (original: {message})\n")
        else:
            log.write(f"[{timestamp}] {username}: {message}\n")

def receive_message(client_socket, text_widget, username):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            
            # Comprobar si el mensaje es del usuario actual (para evitar duplicación)
            # Patrón para detectar mensajes propios que ya hemos mostrado
            if message.startswith(f"[{username}] -> "):
                # No mostrar los propios mensajes recibidos del servidor, ya los mostramos localmente
                continue
                
            text_widget.configure(state='normal')
            text_widget.insert(END, message)
            text_widget.see(END)  # Auto-scroll al final
            text_widget.configure(state='disabled')
        
        except Exception as e:
            print(f"Error recibiendo mensaje: {e}")
            break

def user_request(client_socket):
    client_socket.sendall("!usuarios".encode())

def exit_request(client_socket, username, window):
    try:
        client_socket.sendall(f"\n--El usuario [{username}] se ha desconectado\n".encode())
        client_socket.close()
    except:
        pass  # En caso de que la conexión ya esté cerrada
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
    try:
        image = Image.open("./logo.png")
        image = image.resize((100, 100))
        photo = ImageTk.PhotoImage(image)
        
        #Label para la imagen
        image_label = CTkLabel(login_frame, image=photo, text="")
        image_label.photo = photo #Esto es para hacer referencia a la imagen
        image_label.pack()
    except Exception as e:
        print(f"Error al cargar la imagen: {e}")

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

    # Mostrar la ventana de bienvenida al inicio
    show_frame(welcome_frame)

    # Iniciar el hilo de recepción de mensajes
    thread = threading.Thread(target=receive_message, args=(client_socket, text_widget, username))
    thread.daemon = True
    thread.start()

    window.mainloop()
    client_socket.close()

if __name__ == '__main__':
    login_window()