#!/usr/bin/env python3
import socket
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

open_sockets = []

def def_handler(sig, frame):
    print(colored(f"Saliendo del programa...", 'yellow'))
    #Cerramos todos los socket e hilos
    for socket in open_sockets:
        socket.close()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler) #Ctrl+c

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Port Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target to scan(-t IP)")# Con esto le decimos que cuando usamos -t algo ese algo lo almacenamos en target
    parser.add_argument("-p", "--port", dest="port", required=True, help="Port range to scan(-p 0-1000)")
    options = parser.parse_args()
    
    return options.target, options.port


def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)#Le indicamos que se demore 1 segundo para ver si esta abierto o cerrado
    
    open_sockets.append(s)
    
    return s

def port_scanner(port, host):
    
    s = create_socket()
    try:
        #Jugamos con ex que es extendende que nos devuelve un codigo, un valor. El cual podremos usar
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")#Para poder simular los dos enter se usa el \r\n
        response = s.recv(1024)#Lo queremos en formato string y no en bytes e ignoreamos los caracteres exraños, seperamos con split y nos quedamos con el primer elemento
        response = response.decode(errors='ignore').split('\n')
        if response:
            print(colored(f"El puerto {port} esta abierto\n",'green'))
            for line in response:
                print(colored(f"{line}",'white'))

        else:
            print(colored(f"El puerto {port} esta abierto", 'green'))
        
        s.close()# Nos aseguramos que se cierra el socket
    
 
    except (socket.timeout, ConnectionRefusedError):#Entre parentesis ponemos todos los casos de excepciones que queramos que se acontezcan
        s.close()#En vez de pass hacemos esto para que no se quede ningun socket abierto

def scan_ports(ports, target):
    with ThreadPoolExecutor(max_workers=100) as executor: #Limitamos el numeor de hilos
        executor.map(lambda port: port_scanner(port, target), ports) #COn la funcion lamda nos aprovechamos de la sintaxis para obtener un unico argumento 
        #que seria port que es loq eu ma le pasa  a la funcion port scanner pero en ez pasarla directamerna  port scanner, recibimos el argumento en 
        #port para poder lalamar a portscanner y llamar a pport y target para no entrar en comflicto


    
def parse_ports(ports_str):
    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return range(start, end+1)#Hay que sumarle uno para que te cuente con el ultimo numero ya que si le pones del 0 al 7 te pondra del 1 al 6
    elif ',' in ports_str:
        return map(int, ports_str.split(','))
    #Hay que tener un iterable para un unico puerto
    else:
        return (int(ports_str),)#Importante la coma ya que sino NO iterare sobre el unico valor


def main():

    target, ports_str = get_arguments()
    ports = parse_ports(ports_str)
    scan_ports(ports, target)


if __name__ == '__main__':
    main()