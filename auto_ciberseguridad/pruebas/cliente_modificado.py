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
    frame_logo.pack(side="top", fill="x", pady=(15, 20))
    
    # Intenta cargar el logo
    try:
        imagen = Image.open("./logo.png")
        imagen = imagen.resize((60, 60))
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

    # Función para cambiar entre paneles
    def cambiar_panel(panel):
        global recibiendo_logs
        recibiendo_logs = False
        
        for p in [panel_bienvenida, panel_chat, panel_admin]:
            p.pack_forget()
        panel.pack(expand=True, fill="both")
    
    # Frame central para botones principales
    frame_botones = CTkFrame(menu, fg_color="transparent")
    frame_botones.pack(side="top", fill="x", expand=True, padx=10)
    
    # Estilo de botón para el menú lateral
    boton_estilo = {
        "height": 35, 
        "corner_radius": 6, 
        "fg_color": color_boton_principal,
        "text_color": color_texto_claro,
        "hover_color": color_hover,
        "anchor": "center"
    }
    
    # Estilo para botones activos/destacados
    boton_estilo_activo = {
        "height": 35, 
        "corner_radius": 6, 
        "fg_color": color_acento,
        "text_color": color_texto_claro,
        "hover_color": "#5d4fd1",
        "anchor": "center"
    }
    
    # Espacio adicional en la parte superior
    espacio_superior = CTkFrame(frame_botones, height=10, fg_color="transparent")
    espacio_superior.pack(pady=10)
    
    # Botón Chat con icono (usando el estilo activo por ser la pestaña principal)
    boton_chat = CTkButton(
        frame_botones, 
        text="💬 Chat", 
        command=lambda: cambiar_panel(panel_chat),
        **boton_estilo_activo
    )
    boton_chat.pack(pady=(0, 10), fill="x")

    # Botón Admin con icono (usando el estilo normal)
    if role == "admin":
        boton_admin = CTkButton(
            frame_botones, 
            text="🛠️ Admin", 
            command=lambda: cambiar_panel(panel_admin), 
            **boton_estilo
        )
        boton_admin.pack(pady=(0, 10), fill="x")
    
    # Frame inferior para el nombre de usuario como texto
    frame_cuenta = CTkFrame(menu, fg_color="transparent")
    frame_cuenta.pack(side="bottom", fill="x", pady=15, padx=10)
    
    # Frame para el usuario con icono
    frame_usuario = CTkFrame(frame_cuenta, fg_color="transparent")
    frame_usuario.pack(fill="x")
    
    # Icono de usuario
    label_usuario_icon = CTkLabel(frame_usuario, text="👤", font=("Arial", 14), text_color=color_texto_claro)
    label_usuario_icon.pack(side="left", padx=(0, 5))
    
    # Nombre de usuario como texto normal
    label_usuario = CTkLabel(frame_usuario, text=username, font=("Arial", 12), text_color=color_texto_claro, anchor="w")
    label_usuario.pack(side="left", fill="x")
    
    # Agregar botón de salir con estilo de texto simple (único botón de salir)
    boton_salir_menu = CTkButton(
        frame_cuenta, 
        text="Salir", 
        command=lambda: salir(socket, username, ventana), 
        fg_color="transparent",
        hover_color=color_hover,
        text_color=color_texto_oscuro,
        height=25
    )
    boton_salir_menu.pack(fill="x", pady=(5, 0))

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

    # Mejorar la gestión de cierre
    def on_close():
        try:
            socket.sendall(f"\n--El usuario [{username}] se ha desconectado\n".encode())
            socket.close()
        except:
            pass
        ventana.quit()
        ventana.destroy()
    
    ventana.protocol("WM_DELETE_WINDOW", on_close)
    ventana.mainloop()
    socket.close()
# Punto de entrada
if __name__ == '__main__':
    ventana_login()