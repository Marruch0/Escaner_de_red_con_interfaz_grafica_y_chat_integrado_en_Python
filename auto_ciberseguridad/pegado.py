#!/usr/bin/env python3
import socket
import threading
import ssl
from customtkinter import *

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
    login.geometry("400x200")

    # Frame para el login
    login_frame = CTkFrame(login)
    login_frame.pack(expand=True, fill="both", padx=20, pady=20)

    # Etiqueta de título
    title_label = CTkLabel(login_frame, text="Iniciar Sesión", font=("Arial", 20))
    title_label.pack(pady=10)

    # Campo de entrada para el nombre de usuario
    username_label = CTkLabel(login_frame, text="Nombre de Usuario:")
    username_label.pack(pady=(10, 0))
    username_entry = CTkEntry(login_frame)
    username_entry.pack(pady=(0, 10), fill="x")

    # Etiqueta para mostrar errores
    error_label = CTkLabel(login_frame, text="", text_color="red")
    error_label.pack(pady=(5, 0))

    # Botón para iniciar sesión
    login_button = CTkButton(login_frame, text="Iniciar Sesión", command=start_chat)
    login_button.pack(pady=10)

    login.mainloop()

def client_program(username):
    host = '192.168.100.15'
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

    # Zona donde se muestran los mensajes y la barra de scroll
    messages_frame = CTkFrame(chat_frame)
    messages_frame.pack(side="top", expand=True, fill="both", padx=6, pady=(6, 2))

    text_widget = CTkTextbox(messages_frame)
    text_widget.pack(side="left", expand=True, fill="both")

    scrollbar = CTkScrollbar(messages_frame, command=text_widget.yview)
    scrollbar.pack(side="right", fill="y")
    text_widget.configure(yscrollcommand=scrollbar.set)
    text_widget.configure(state='disabled')  # Para evitar que se pueda editar

    # Contenedor inferior para la entrada de texto y botones
    input_frame = CTkFrame(chat_frame, fg_color="transparent")
    input_frame.pack(side="bottom", fill="x", padx=6, pady=(2, 2))

    entry_widget = CTkEntry(input_frame)
    entry_widget.bind("<Return>", lambda _: send_message(client_socket, username, text_widget, entry_widget))
    entry_widget.pack(side="left", fill="x", expand=True, padx=(0, 6))

    send_button = CTkButton(input_frame, text="Enviar", command=lambda: send_message(client_socket, username, text_widget, entry_widget), width=50, height=28)
    send_button.pack(side="right")

    # Botones de acciones ("Usuarios conectados" y "Salir")
    actions_frame = CTkFrame(chat_frame, fg_color="transparent")
    actions_frame.pack(side="bottom", fill="x", padx=6, pady=(2, 6))

    users_button = CTkButton(actions_frame, text="Usuarios conectados", command=lambda: user_request(client_socket), width=140, height=28)
    users_button.pack(side="left", padx=(0, 6))

    exit_button = CTkButton(actions_frame, text="Salir", command=lambda: exit_request(client_socket, username, window), width=100, height=28)
    exit_button.pack(side="left")

    chat_frame.pack(expand=True, fill="both")

    thread = threading.Thread(target=receive_message, args=(client_socket, text_widget))
    thread.daemon = True
    thread.start()

    window.mainloop()
    client_socket.close()

if __name__ == '__main__':
    login_window()
