#!/usr/bin/env python3
import socket
import threading
import ssl
import re
import datetime
from user_manager import UserManager

# Inicializar el gestor de usuarios
user_manager = UserManager()

# Lista de palabras feas
PALABRAS_FEAS = [
    "mierda", "puta", "puto", "joder", "jodido", "cabrón", "cabron", "gilipollas", 
    "idiota", "imbécil", "imbecil", "cojones", "hostia", "coño", "polla", "capullo", 
    "hijo de puta", "hdp", "pendejo", "marica", "maricón", "maricon", "zorra", 
    "follar", "jodete", "cabrona", "maldito", "carajo", "pito", "chinga", "maldita",
    "pene"
]

# Control de sesiones únicas
usuarios_conectados = {}
usuarios_lock = threading.Lock()

def censurar_mensaje(mensaje):
    """Censura palabras feas"""
    for palabra in PALABRAS_FEAS:
        patron = r'\b' + re.escape(palabra) + r'\b'
        mensaje = re.sub(patron, '*' * len(palabra), mensaje, flags=re.IGNORECASE)
    return mensaje

def guardar_log(usuario, mensaje, original=None):
    """Guarda un mensaje en el log"""
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("chat_logs.txt", "a", encoding="utf-8") as f:
        if original and original != mensaje:
            f.write(f"[{ahora}] {usuario}: {mensaje} (original: {original})\n")
        else:
            f.write(f"[{ahora}] {usuario}: {mensaje}\n")

def gestionar_sesion(username, accion):
    """Gestiona el registro de sesiones"""
    with usuarios_lock:
        if accion == "registrar":
            if username in usuarios_conectados:
                return False
            usuarios_conectados[username] = datetime.datetime.now()
            return True
        elif accion == "eliminar":
            if username in usuarios_conectados:
                del usuarios_conectados[username]

def procesar_comando(cmd, partes, socket, username, sockets, usuarios, roles):
    """Procesa los comandos administrativos"""
    # Verificar permisos de administrador
    if roles[socket] != "admin":
        socket.sendall("ERROR: No tienes permisos de administrador\n".encode())
        return

    # Comando /kick
    if cmd == "/kick" and len(partes) >= 2:
        usuario_objetivo = partes[1]
        razon = partes[2] if len(partes) > 2 else "Sin razón especificada"
        
        # Buscar el socket del usuario
        socket_objetivo = None
        sockets_a_eliminar = []
        for s, nombre in list(usuarios.items()):
            if nombre == usuario_objetivo:
                socket_objetivo = s
                sockets_a_eliminar.append(s)
                break
        
        if not socket_objetivo:
            socket.sendall(f"ERROR: Usuario {usuario_objetivo} no encontrado\n".encode())
            return
            
        if roles.get(socket_objetivo) == "admin":
            socket.sendall("ERROR: No puedes expulsar a otro administrador\n".encode())
            return
        
        # Notificar y desconectar
        try:
            socket_objetivo.sendall(f"Has sido expulsado por {username}. Razón: {razon}\n".encode())
            gestionar_sesion(usuario_objetivo, "eliminar")
            socket_objetivo.close()
        except:
            pass
            
        # Limpiar datos
        for s in sockets_a_eliminar:
            if s in sockets:
                sockets.remove(s)
            if s in usuarios:
                del usuarios[s]
            if s in roles:
                del roles[s]
        
        # Notificar a todos
        for s in list(sockets):
            if s is not socket and s is not socket_objetivo:
                try:
                    s.sendall(f"El usuario {usuario_objetivo} ha sido expulsado por {username}\n".encode())
                except:
                    pass
        
        socket.sendall(f"Usuario {usuario_objetivo} expulsado correctamente\n".encode())
        guardar_log("SISTEMA", f"El usuario {usuario_objetivo} ha sido expulsado por {username}. Razón: {razon}")
    
    # Comando /ban
    elif cmd == "/ban" and len(partes) >= 3:
        usuario_objetivo = partes[1]
        
        try:
            duracion = int(partes[2])
            razon = partes[3] if len(partes) > 3 else "Sin razón especificada"
        except:
            socket.sendall("ERROR: La duración debe ser un número (minutos)\n".encode())
            return
        
        # Banear al usuario
        exito, mensaje = user_manager.ban_user(usuario_objetivo, duracion, razon, username)
        socket.sendall(f"{mensaje}\n".encode())
        
        if exito:
            # Desconectar si está online
            for s, nombre in list(usuarios.items()):
                if nombre == usuario_objetivo:
                    try:
                        s.sendall(f"Has sido bloqueado por {username} durante {duracion} minutos. Razón: {razon}\n".encode())
                        gestionar_sesion(usuario_objetivo, "eliminar")
                        s.close()
                        if s in sockets:
                            sockets.remove(s)
                        if s in usuarios:
                            del usuarios[s]
                        if s in roles:
                            del roles[s]
                    except:
                        pass
                    break
            
            # Notificar a todos
            for s in list(sockets):
                if s is not socket:
                    try:
                        s.sendall(f"El usuario {usuario_objetivo} ha sido bloqueado por {username} durante {duracion} minutos\n".encode())
                    except:
                        pass
            
            guardar_log("SISTEMA", f"El usuario {usuario_objetivo} ha sido bloqueado por {username} durante {duracion} minutos. Razón: {razon}")
    
    # Comando /unban
    elif cmd == "/unban" and len(partes) >= 2:
        usuario_objetivo = partes[1]
        exito, mensaje = user_manager.unban_user(usuario_objetivo)
        socket.sendall(f"{mensaje}\n".encode())
        
        if exito:
            guardar_log("SISTEMA", f"El usuario {usuario_objetivo} ha sido desbloqueado por {username}")
    
    # Comando /banlist
    elif cmd == "/banlist":
        usuarios_baneados = user_manager.get_banned_users()
        if usuarios_baneados:
            respuesta = "+ Lista de usuarios bloqueados:\n"
            for u, hasta, razon, por in usuarios_baneados:
                respuesta += f"- {u} (hasta {hasta.strftime('%Y-%m-%d %H:%M:%S')}), por {por}: {razon}\n"
        else:
            respuesta = "No hay usuarios bloqueados actualmente\n"
        socket.sendall(respuesta.encode())
    
    # Comando /userlist
    elif cmd == "/userlist":
        todos_usuarios = user_manager.get_all_users()
        if todos_usuarios:
            respuesta = "+ Lista de usuarios registrados:\n"
            for u, r in todos_usuarios:
                estado = " (conectado)" if u in usuarios_conectados else ""
                respuesta += f"- {u} ({r}){estado}\n"
        else:
            respuesta = "No hay usuarios registrados\n"
        socket.sendall(respuesta.encode())
    
    # Comando /adduser
    elif cmd == "/adduser" and len(partes) >= 3:
        nuevo_usuario = partes[1]
        nueva_contraseña = partes[2]
        nuevo_rol = "admin" if len(partes) > 3 and partes[3].lower() == "admin" else "user"
        
        exito, mensaje = user_manager.add_user(nuevo_usuario, nueva_contraseña, nuevo_rol)
        socket.sendall(f"{mensaje}\n".encode())
        
        if exito:
            guardar_log("SISTEMA", f"El usuario {username} ha creado un nuevo usuario: {nuevo_usuario} con rol {nuevo_rol}")
    
    # Comando /deluser
    elif cmd == "/deluser" and len(partes) >= 2:
        usuario_objetivo = partes[1]
        
        # Validaciones
        if usuario_objetivo == "admin":
            socket.sendall("ERROR: No se puede eliminar al usuario admin principal\n".encode())
            return
            
        if not user_manager.user_exists(usuario_objetivo):
            socket.sendall(f"ERROR: El usuario {usuario_objetivo} no existe\n".encode())
            return
            
        if user_manager.is_admin(usuario_objetivo):
            socket.sendall("ERROR: No puedes eliminar a otro administrador\n".encode())
            return
            
        # Eliminar al usuario
        if user_manager.delete_user(usuario_objetivo):
            socket.sendall(f"Usuario {usuario_objetivo} eliminado correctamente\n".encode())
            
            # Desconectar si está online
            for s, nombre in list(usuarios.items()):
                if nombre == usuario_objetivo:
                    try:
                        s.sendall(f"Tu cuenta ha sido eliminada por {username}\n".encode())
                        gestionar_sesion(usuario_objetivo, "eliminar")
                        s.close()
                        if s in sockets:
                            sockets.remove(s)
                        if s in usuarios:
                            del usuarios[s]
                        if s in roles:
                            del roles[s]
                    except:
                        pass
                    break
                    
            guardar_log("SISTEMA", f"El usuario {usuario_objetivo} ha sido eliminado por {username}")
        else:
            socket.sendall(f"ERROR: No se pudo eliminar al usuario {usuario_objetivo}\n".encode())
    
    # Comando /logs
    elif cmd == "/logs":
        try:
            # Procesar límite opcional de líneas
            limite = None
            if len(partes) > 1:
                try:
                    limite = int(partes[1])
                except:
                    socket.sendall("ERROR: El número de líneas debe ser un valor numérico\n".encode())
                    return
            
            # Leer y enviar logs
            try:
                with open("chat_logs.txt", "r", encoding="utf-8") as f:
                    lineas = f.readlines()
                    
                    if limite and limite > 0:
                        lineas = lineas[-limite:]
                    
                    respuesta = "=== LOGS DEL SERVIDOR ===\n"
                    respuesta += "".join(lineas)
                    if not lineas:
                        respuesta += "No hay entradas en el log.\n"
                    respuesta += "=== FIN DE LOS LOGS ===\n"
            except FileNotFoundError:
                respuesta = "=== LOGS DEL SERVIDOR ===\nNo se encontró el archivo de logs.\n=== FIN DE LOS LOGS ===\n"
            
            socket.sendall(respuesta.encode())
            guardar_log("SISTEMA", f"El usuario {username} ha consultado los logs del servidor")
            
        except Exception as e:
            socket.sendall(f"ERROR: No se pudieron obtener los logs: {e}\n".encode())
    
    
    # Comando /banreason
    elif cmd == "/banreason" and len(partes) >= 3:
        usuario_objetivo = partes[1]
        razon = partes[2] if len(partes) > 2 else "Sin razón especificada"
        
        # Comprobar si el usuario está baneado
        if not user_manager.is_banned(usuario_objetivo):
            socket.sendall(f"ERROR: El usuario {usuario_objetivo} no está bloqueado\n".encode())
            return
        
        # Actualizar la razón del baneo
        if user_manager.update_ban_reason(usuario_objetivo, razon):
            socket.sendall(f"Se ha actualizado la razón del bloqueo para {usuario_objetivo}\n".encode())
            guardar_log("SISTEMA", f"El usuario {username} ha actualizado la razón del bloqueo de {usuario_objetivo}: {razon}")
        else:
            socket.sendall(f"ERROR: No se pudo actualizar la razón del bloqueo para {usuario_objetivo}\n".encode())
            
    # Comando desconocido
    else:
        socket.sendall("ERROR: Comando desconocido. Usa /help para ver la lista de comandos\n".encode())

def client_thread(socket, sockets, usuarios, roles):
    """Maneja la conexión de un cliente"""
    username = None
    
    # Autenticación
    try:
        # Recibir credenciales
        credenciales = socket.recv(1024).decode().strip().split(':', 1)
        if len(credenciales) != 2:
            socket.sendall("ERROR: Formato incorrecto. Use 'username:password'".encode())
            socket.close()
            return
            
        username, password = credenciales
        
        # Verificar sesión única
        if not gestionar_sesion(username, "registrar"):
            socket.sendall("ERROR: Este usuario ya está conectado. Solo se permite una sesión a la vez.".encode())
            socket.close()
            return
        
        # Autenticar
        auth_ok, resultado = user_manager.authenticate(username, password)
        if not auth_ok:
            gestionar_sesion(username, "eliminar")
            socket.sendall(f"ERROR: {resultado}".encode())
            socket.close()
            return
            
        # Usuario autenticado
        role = resultado
        usuarios[socket] = username
        roles[socket] = role
        socket.sendall(f"AUTH_OK:{role}".encode())
        
    except Exception as e:
        print(f"[ERROR] Error en autenticación: {e}")
        if username:
            gestionar_sesion(username, "eliminar")
        try:
            socket.close()
        except:
            pass
        return
    
    # Usuario conectado
    print(f"El usuario [{username}] se ha conectado al chat con rol: {role}")
    guardar_log("SISTEMA", f"El usuario [{username}] se ha conectado al chat con rol: {role}")
    
    # Notificar a todos
    for s in sockets:
        if s is not socket:
            try:
                s.sendall(f"El usuario [{username}] se ha conectado al chat\n".encode())
            except:
                pass
    
    # Bucle principal de mensajes
    while True:
        try:
            mensaje = socket.recv(1024).decode()
            if not mensaje:
                break
            
            # Comandos administrativos
            if mensaje.startswith("/"):
                partes = mensaje.strip().split(' ', 2)
                comando = partes[0].lower()
                procesar_comando(comando, partes, socket, username, sockets, usuarios, roles)
                continue
            
            # Comando de listar usuarios
            if mensaje == "!usuarios":
                usuarios_online = "\n+ Listado de usuarios conectados:\n"
                for s, nombre in list(usuarios.items()):
                    rol = roles.get(s, "user")
                    usuarios_online += f"- {nombre} ({rol})\n"
                usuarios_online += "\n"
                socket.sendall(usuarios_online.encode())
                guardar_log(username, "solicitó lista de usuarios conectados")
                continue
            
            print(f"Mensaje de {username}: {mensaje}")
            
            # Procesar mensaje normal
            if "->" in mensaje:
                # Formato [usuario] -> mensaje
                emisor, contenido = mensaje.split("->", 1)
                mensaje_texto = contenido.strip()
                
                # Registrar y censurar
                guardar_log(username, mensaje_texto, mensaje_texto)
                mensaje_censurado = censurar_mensaje(mensaje_texto)
                mensaje_final = f"{emisor}-> {mensaje_censurado}\n"
                
                # Enviar a todos
                for s in list(sockets):
                    if s is not socket:
                        try:
                            s.sendall(mensaje_final.encode())
                        except:
                            pass
            else:
                # Mensaje sin formato especial
                guardar_log(username, mensaje, mensaje)
                mensaje_censurado = censurar_mensaje(mensaje)
                
                # Enviar a todos
                for s in list(sockets):
                    if s is not socket:
                        try:
                            s.sendall(f"{mensaje_censurado}\n".encode())
                        except:
                            pass
                
        except Exception as e:
            print(f"[ERROR] Error con cliente {username}: {e}")
            break
    
    # Desconexión
    if username:
        guardar_log("SISTEMA", f"El usuario [{username}] se ha desconectado del chat")
        print(f"El usuario [{username}] se ha desconectado del chat")
        gestionar_sesion(username, "eliminar")
    
    # Limpiar recursos
    try:
        socket.close()
        if socket in sockets:
            sockets.remove(socket)
        if socket in usuarios:
            del usuarios[socket]
        if socket in roles:
            del roles[socket]
    except:
        pass

def iniciar_servidor():
    """Inicia el servidor de chat"""
    host = '0.0.0.0'
    port = 12345

    # Configurar socket
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, port))
    
    # Configurar SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.key")
    servidor = context.wrap_socket(servidor, server_side=True)
    servidor.listen()

    print(f"\n---El servidor está en escucha en el puerto {port}---")
    guardar_log("SISTEMA", "Servidor iniciado")
    
    sockets = []
    usuarios = {}
    roles = {}

    # Bucle principal
    while True:
        try:
            socket_cliente, direccion = servidor.accept()
            sockets.append(socket_cliente)
            print(f"\n---Se ha conectado un cliente con la ip -> {direccion}")
            guardar_log("SISTEMA", f"Cliente conectado desde IP: {direccion[0]}:{direccion[1]}")

            # Crear hilo para el cliente
            hilo = threading.Thread(target=client_thread, args=(socket_cliente, sockets, usuarios, roles))
            hilo.daemon = True
            hilo.start()
        except Exception as e:
            print(f"[ERROR] Error en conexión entrante: {e}")

# Punto de entrada
if __name__ == '__main__':
    iniciar_servidor()