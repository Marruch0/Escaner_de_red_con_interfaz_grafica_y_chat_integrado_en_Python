#!/usr/bin/env python3

import socket
import threading
import ssl

def client_thread(client_socket, clients, usernames):
    username = client_socket.recv(1024).decode()
    usernames[client_socket] = username
    print(f"El usuario [{username}] se ha conectado al chat")

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
                continue

            for client in clients:
                if client is not client_socket:
                    client.sendall(f"{message}\n".encode())
                
        except:
            break
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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) 
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.key")
    server_socket = context.wrap_socket(server_socket, server_side=True)
    server_socket.listen()

    print(f"\n---El servidor está en escucha---")
    
    clients = []
    usernames = {}

    while True:
        client_socket, address = server_socket.accept()
        clients.append(client_socket)
        print(f"\n---Se ha conectado un cliente con la ip -> {address}")

        thread = threading.Thread(target=client_thread, args=(client_socket, clients, usernames))
        thread.daemon = True
        thread.start()

    # server_socket.close() is unreachable because the loop is infinite.
    # To properly close the server, you would need a mechanism to break the loop.

if __name__ == '__main__':
    server_program()