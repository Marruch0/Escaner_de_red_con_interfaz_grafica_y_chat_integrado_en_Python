#!/usr/bin/env python3

import socket
import threading
import ssl
import re
import datetime

# Lista de palabras soeces para entorno empresarial
PALABRAS_SOECES = [
    "mierda", "puta", "puto", "joder", "jodido", "cabrón", "cabron", "gilipollas", 
    "idiota", "imbécil", "imbecil", "cojones", "hostia", "coño", "polla", "capullo", 
    "hijo de puta", "hdp", "pendejo", "marica", "maricón", "maricon", "zorra", 
    "follar", "jodete", "cabrona", "maldito", "carajo", "pito", "chinga", "maldita"
]

# Función para censurar palabras soeces
def censurar_mensaje(mensaje):
    mensaje_censurado = mensaje
    for palabra in PALABRAS_SOECES:
        # Búsqueda insensible a mayúsculas y minúsculas con palabra completa
        patron = r'\b' + re.escape(palabra) + r'\b'
        # Reemplazar con asteriscos manteniendo la misma longitud
        mensaje_censurado = re.sub(patron, '*' * len(palabra), mensaje_censurado, flags=re.IGNORECASE)
    return mensaje_censurado

# Función para guardar logs
def guardar_log(username, mensaje, mensaje_original=None):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("chat_logs.txt", "a", encoding="utf-8") as log_file:
        if mensaje_original and mensaje_original != mensaje:
            log_file.write(f"[{timestamp}] {username}: {mensaje} (original: {mensaje_original})\n")
        else:
            log_file.write(f"[{timestamp}] {username}: {mensaje}\n")

def client_thread(client_socket, clients, usernames):
    username = client_socket.recv(1024).decode()
    usernames[client_socket] = username
    print(f"El usuario [{username}] se ha conectado al chat")
    
    # Guardar log de conexión
    guardar_log("SISTEMA", f"El usuario [{username}] se ha conectado al chat")

    for client in clients:
        if client is not client_socket:
            try:
                client.sendall(f"El usuario [{username}] se ha conectado al chat\n".encode())
            except Exception as e:
                print(f"[ERROR] No se pudo enviar al cliente: {e}")
                clients.remove(client)  # Elimina cliente que falló
                client.close()
    
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            
            if message == "!usuarios":
                client_socket.sendall(f"\n+ Listado de usuarios conectados:\n- {'\n- '.join(usernames.values())}\n\n".encode())
                guardar_log(username, "solicitó lista de usuarios conectados")
                continue
            
            # Formato esperado: "[username]: mensaje"
            if ":" in message:
                sender, content = message.split(":", 1)
                message_content = content.strip()
                
                # Guardar mensaje original en logs
                guardar_log(username, message_content, message_content)
                
                # Censurar el mensaje
                mensaje_censurado = censurar_mensaje(message_content)
                
                # Reconstruir el mensaje censurado
                message_to_send = f"{sender}: {mensaje_censurado}"
                
                for client in clients:
                    if client is not client_socket:
                        client.sendall(f"{message_to_send}\n".encode())
            else:
                # Si el mensaje no tiene el formato esperado, enviarlo tal cual
                guardar_log(username, message, message)
                mensaje_censurado = censurar_mensaje(message)
                
                for client in clients:
                    if client is not client_socket:
                        client.sendall(f"{mensaje_censurado}\n".encode())
                
        except Exception as e:
            print(f"[ERROR] Error en el manejo del cliente {username}: {e}")
            break
    
    # Guardar log de desconexión
    guardar_log("SISTEMA", f"El usuario [{username}] se ha desconectado del chat")
    print(f"El usuario [{username}] se ha desconectado del chat")
    
    client_socket.close()
    clients.remove(client_socket)
    del usernames[client_socket]

def server_program():
    host = '0.0.0.0'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.key")
    server_socket = context.wrap_socket(server_socket, server_side=True)
    server_socket.listen()

    print(f"\n---El servidor está en escucha---")
    guardar_log("SISTEMA", "Servidor iniciado")
    
    clients = []
    usernames = {}

    while True:
        client_socket, address = server_socket.accept()
        clients.append(client_socket)
        print(f"\n---Se ha conectado un cliente con la ip -> {address}")
        guardar_log("SISTEMA", f"Cliente conectado desde IP: {address[0]}:{address[1]}")

        thread = threading.Thread(target=client_thread, args=(client_socket, clients, usernames))
        thread.daemon = True
        thread.start()

    # server_socket.close() is unreachable because the loop is infinite.
    # To properly close the server, you would need a mechanism to break the loop.

if __name__ == '__main__':
    server_program()