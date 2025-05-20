#!/usr/bin/env python3
import socket
import threading
import ssl
import re
import datetime
import os
from customtkinter import *
from PIL import Image, ImageTk

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

def ventana_login():
    """Crea la ventana de inicio de sesión"""
    def iniciar_chat():
        username = campo_usuario.get()
        password = campo_password.get()
        
        if not username.strip() or not password.strip():
            label_error.configure(text="Usuario y contraseña son obligatorios")
            return
        
        try:
            # Conectar al servidor
            socket_cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_cliente = ssl._create_unverified_context().wrap_socket(socket_cliente, server_hostname='192.168.100.15')
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
                ventana_login.destroy()
                iniciar_cliente(username, socket_cliente, role)
            else:
                label_error.configure(text="Error de autenticación")
                socket_cliente.close()
                
        except Exception as e:
            label_error.configure(text=f"Error de conexión: {str(e)}")

    # Configuración
    host = 'localhost'
    port = 12345

    # Crear ventana
    ventana_login = CTk()
    ventana_login.title("Login - Chat")
    ventana_login.geometry("300x400")

    # Frame principal
    frame_login = CTkFrame(ventana_login, fg_color="transparent")
    frame_login.pack(side="left", fill="x", expand=True, padx=(0, 6))

    # Logo
    try:
        imagen = Image.open("./logo.png")
        imagen = imagen.resize((100, 100))
        logo = ImageTk.PhotoImage(imagen)
        
        label_imagen = CTkLabel(frame_login, image=logo, text="")
        label_imagen.photo = logo
        label_imagen.pack()
    except Exception as e:
        print(f"Error al cargar la imagen: {e}")

    # Título
    label_titulo = CTkLabel(frame_login, text="Iniciar Sesión", font=("Arial", 30))
    label_titulo.pack(pady=10)

    # Campo usuario
    label_usuario = CTkLabel(frame_login, text="Nombre de Usuario:")
    label_usuario.pack(pady=(5))
    campo_usuario = CTkEntry(frame_login, width=200)
    campo_usuario.pack(pady=(0))
    
    # Campo contraseña
    label_password = CTkLabel(frame_login, text="Contraseña:")
    label_password.pack(pady=(5))
    campo_password = CTkEntry(frame_login, width=200, show="*")
    campo_password.pack(pady=(0))
    campo_password.bind("<Return>", lambda _: iniciar_chat())

    # Mensaje de error
    label_error = CTkLabel(frame_login, text="", text_color="red")
    label_error.pack(pady=(5, 0))

    # Botón login
    boton_login = CTkButton(frame_login, text="Iniciar Sesión", command=iniciar_chat)
    boton_login.pack(pady=10)

    ventana_login.mainloop()

def crear_panel_admin(frame, socket, area_chat):
    """Crea el panel de administración"""
    
    # Panel principal (dos columnas)
    frame_principal = CTkFrame(frame)
    frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Columna izquierda
    columna_izq = CTkFrame(frame_principal)
    columna_izq.pack(side="left", fill="both", expand=True, padx=5, pady=5)
    
    # Panel de control
    panel = CTkFrame(columna_izq, fg_color="#1A1A1A")
    panel.pack(fill="both", expand=True, padx=5, pady=5)
    
    # Título
    titulo = CTkLabel(panel, text="Panel de Control", font=("Arial", 18, "bold"))
    titulo.pack(pady=(10, 5))
    
    # Panel de entrada
    panel_datos = CTkFrame(panel, fg_color="#1A1A1A")
    panel_datos.pack(fill="x", padx=10, pady=5)
    
    # Usuario objetivo
    label_usuario = CTkLabel(panel_datos, text="Usuario objetivo:", anchor="w")
    label_usuario.pack(pady=(5, 0), anchor="w")
    
    campo_usuario = CTkEntry(panel_datos, placeholder_text="Nombre de usuario", width=200)
    campo_usuario.pack(pady=5, fill="x")
    
    # Razón
    label_razon = CTkLabel(panel_datos, text="Razón (opcional):", anchor="w")
    label_razon.pack(pady=(5, 0), anchor="w")
    
    campo_razon = CTkEntry(panel_datos, placeholder_text="Razón de la acción", width=200)
    campo_razon.pack(pady=5, fill="x")
    
    # Contraseña
    label_password = CTkLabel(panel_datos, text="Contraseña (para nuevo usuario):", anchor="w")
    label_password.pack(pady=(5, 0), anchor="w")
    
    campo_password = CTkEntry(panel_datos, placeholder_text="Contraseña", width=200, show="*")
    campo_password.pack(pady=5, fill="x")
    
    # Opciones
    panel_opciones = CTkFrame(panel, fg_color="#1A1A1A")
    panel_opciones.pack(fill="x", padx=10, pady=5)
    
    # Crear como admin
    var_admin = IntVar(value=0)
    check_admin = CTkCheckBox(panel_opciones, text="Crear como administrador", variable=var_admin)
    check_admin.pack(pady=5, anchor="w")
    
    # Ban permanente
    var_permanente = IntVar(value=0)
    check_permanente = CTkCheckBox(panel_opciones, text="Baneo permanente", variable=var_permanente)
    check_permanente.pack(pady=5, anchor="w")
    
    # Tiempo de ban
    panel_tiempo = CTkFrame(panel, fg_color="#1A1A1A")
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
    
    label_tiempo = CTkLabel(panel_tiempo, text="Tiempo: 30 minutos", anchor="w")
    label_tiempo.pack(pady=(5, 0), anchor="w")
    
    slider_tiempo = CTkSlider(panel_tiempo, from_=5, to=1440, number_of_steps=100, command=actualizar_tiempo)
    slider_tiempo.pack(fill="x", pady=5)
    slider_tiempo.set(30)
    
    # Panel de botones
    panel_botones = CTkFrame(panel, fg_color="#1A1A1A")
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
            
        comando = f"/ban {usuario} {minutos}" + (f" {razon}" if razon else "")
        enviar_comando(comando)
        campo_razon.delete(0, END)
    
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
            
        comando = f"/adduser {usuario} {password}" + (" admin" if es_admin else "")
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
    fila1 = CTkFrame(panel_botones, fg_color="#1A1A1A")
    fila1.pack(fill="x", pady=5)
    
    boton_expulsar = CTkButton(fila1, text="Expulsar", command=expulsar, 
                         fg_color="#FF5733", hover_color="#D32F2F", width=100)
    boton_expulsar.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_ban = CTkButton(fila1, text="Banear", command=banear,
                    fg_color="#FF5733", hover_color="#D32F2F", width=100)
    boton_ban.pack(side="right", padx=2, fill="x", expand=True)
    
    # Botones - segunda fila
    fila2 = CTkFrame(panel_botones, fg_color="#1A1A1A")
    fila2.pack(fill="x", pady=5)
    
    boton_unban = CTkButton(fila2, text="Desbanear", command=desbanear, 
                      fg_color="#3498DB", hover_color="#2980B9", width=100)
    boton_unban.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_add = CTkButton(fila2, text="Añadir Usuario", command=añadir_usuario,
                    fg_color="#4CAF50", hover_color="#388E3C", width=100)
    boton_add.pack(side="right", padx=2, fill="x", expand=True)
    
    # Botones - tercera fila
    fila3 = CTkFrame(panel_botones, fg_color="#1A1A1A")
    fila3.pack(fill="x", pady=5)
    
    boton_eliminar = CTkButton(fila3, text="Eliminar Usuario", command=eliminar_usuario,
                         fg_color="#FF5733", hover_color="#D32F2F", width=100)
    boton_eliminar.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_logs = CTkButton(fila3, text="Ver Logs", command=ver_logs,
                     fg_color="#3498DB", hover_color="#2980B9", width=100)
    boton_logs.pack(side="right", padx=2, fill="x", expand=True)
    
    # Botones - cuarta fila
    fila4 = CTkFrame(panel_botones, fg_color="#1A1A1A")
    fila4.pack(fill="x", pady=5)
    
    boton_usuarios = CTkButton(fila4, text="Ver Usuarios", 
                         command=lambda: socket.sendall("/userlist".encode()), 
                         fg_color="#3498DB", hover_color="#2980B9", width=100)
    boton_usuarios.pack(side="left", padx=2, fill="x", expand=True)
    
    boton_baneados = CTkButton(fila4, text="Ver Baneados", 
                         command=lambda: socket.sendall("/banlist".encode()), 
                         fg_color="#3498DB", hover_color="#2980B9", width=100)
    boton_baneados.pack(side="right", padx=2, fill="x", expand=True)
    
    # Columna derecha - Resultados
    columna_der = CTkFrame(frame_principal)
    columna_der.pack(side="right", fill="both", expand=True, padx=5, pady=5)
    
    panel_resultado = CTkFrame(columna_der, fg_color="#1A1A1A")
    panel_resultado.pack(fill="both", expand=True, padx=5, pady=5)
    
    titulo_resultado = CTkLabel(panel_resultado, text="Resultados", font=("Arial", 18, "bold"))
    titulo_resultado.pack(pady=(10, 5))
    
    # Área de texto
    area_resultado = CTkTextbox(panel_resultado, font=("Consolas", 11))
    area_resultado.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Scroll mejorado
    area_resultado.bind("<MouseWheel>", lambda e: area_resultado.yview_scroll(int(-1*(e.delta/120)), "units"))
    
    # Contenido inicial
    area_resultado.insert("1.0", "Los resultados de las acciones aparecerán aquí.")
    area_resultado.configure(state="disabled")
    
    return area_resultado

def iniciar_cliente(username, socket, role):
    """Crea la ventana principal del cliente"""
    # Crear ventana
    ventana = CTk()
    ventana.title(f"CHAT - {username} ({role})")
    ventana.geometry("900x600")

    # Menú lateral
    menu = CTkFrame(ventana, width=150, fg_color="#2b2b2b")
    menu.pack(side="left", fill="y")

    # Panel principal
    panel_principal = CTkFrame(ventana)
    panel_principal.pack(side="right", expand=True, fill="both")

    # Panel de bienvenida
    panel_bienvenida = CTkFrame(panel_principal)
    label_bienvenida = CTkLabel(panel_bienvenida, text=f"Bienvenido al sistema de chat\n\nTu rol es: {role}", font=("Arial", 16))
    label_bienvenida.pack(expand=True)
    panel_bienvenida.pack(expand=True, fill="both")

    # Panel de chat
    panel_chat = CTkFrame(panel_principal)
    panel_chat.pack(expand=True, fill="both")

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
                       width=50, height=28)
    boton_enviar.pack(side="right")

    # Botones de acción
    panel_acciones = CTkFrame(panel_inferior, fg_color="transparent")
    panel_acciones.pack(anchor="center")

    boton_usuarios = CTkButton(panel_acciones, text="Usuarios conectados", command=lambda: solicitar_usuarios(socket), width=140, height=28)
    boton_usuarios.pack(side="left", padx=(0, 6))

    boton_salir = CTkButton(panel_acciones, text="Salir", command=lambda: salir(socket, username, ventana), width=100, height=28)
    boton_salir.pack(side="left")

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

    # Cambiar entre paneles
    def cambiar_panel(panel):
        global recibiendo_logs
        recibiendo_logs = False
        
        for p in [panel_bienvenida, panel_chat, panel_admin]:
            p.pack_forget()
        panel.pack(expand=True, fill="both")

    # Botones de navegación
    boton_inicio = CTkButton(menu, text="Inicio", command=lambda: cambiar_panel(panel_bienvenida), width=120, height=28)
    boton_inicio.pack(pady=10, padx=10)

    boton_chat = CTkButton(menu, text="Chat", command=lambda: cambiar_panel(panel_chat), width=120, height=28)
    boton_chat.pack(pady=10, padx=10)
    
    boton_admin = CTkButton(menu, text="Administración", command=lambda: cambiar_panel(panel_admin), width=120, height=28)
    boton_admin.pack(pady=10, padx=10)

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

    ventana.mainloop()
    socket.close()

# Punto de entrada
if __name__ == '__main__':
    ventana_login()