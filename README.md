# Manual Usuario Técnico

**TFG: Escáner de red con interfaz gráfica y chat integrado en Python**  
**Autor:** Jesús Sánchez Sánchez  
**Grado:** ASIR  
**Fecha:** 09/06/

---

## Índice

- [Introducción](#introducción)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
  - [Clonar Repositorio](#clonar-repositorio)
  - [Instalar Dependencias](#instalar-dependencias)
  - [Configurar el servidor](#configurar-el-servidor)
  - [Configurar el cliente/herramienta](#configurar-el-clienteherramienta)
  - [Ejecutar la herramienta](#ejecutar-la-herramienta)
- [Uso de la herramienta](#uso-de-la-herramienta)
  - [Login](#login)
  - [Chat](#chat)
  - [Panel de Administrador](#panel-de-administrador)
  - [Escáner de puertos](#escáner-de-puertos)
  - [Escáner de puertos- Ejemplo](#escáner-de-puertos--ejemplo)
  - [Escáner de hosts](#escáner-de-hosts)
  - [Escáner de hosts-Ejemplo](#escáner-de-hosts-ejemplo)
  - [Configuración de la interfaz](#configuración-de-la-interfaz)
- [Terminología](#terminología)

---

## Introducción

Este manual está diseñado para dar al usuario una **guía detallada sobre cómo instalar, configurar y utilizar la herramienta** desarrollada para mi TFG.  
Esta herramienta tiene como **objetivo principal ofrecer** a usuarios técnicos y empresas **una herramienta que permita la comunicación y a la vez puedan realizar pruebas de escaneo de red mediante una interfaz gráfica** moderna e intuitiva para el usuario.

La herramienta incluye:

- **Interfaz gráfica:**
  - Diseñada para ser accesible para el usuario y poder interactuar fácilmente con la herramienta.
- **Login de usuario:**
  - Sistema diseñado para autenticar usuarios, **permitiendo**:
    - Asegurar quién tiene **privilegios de administrador**.
    - Identificar qué **usuarios** están **conectados** en todo momento.
    - Garantizar que **solo** haya **una sesión activa por usuario**.
- **Gestión de usuarios:**
  - **Permite a los administradores gestionar a los usuarios** y aplicarles restricciones, además de ver el **registro de las actividades** de la herramienta.
- **Chat seguro:**
  - Sistema de comunicación en **tiempo real con cifrado**, **censura de mensajes** inapropiados y **registros** por seguridad.
- **Escaneo de puertos:**
  - Permite **identificar puertos y servicios expuestos** en la red para evaluar posibles puntos de acceso y vulnerabilidades.
  - Proporciona **información sobre los puertos y servicios** asociados.
  - Incluye **opciones avanzadas** como:
    - **Modo sigiloso**: Realiza el escaneo de forma discreta para evitar la detección.
    - **Análisis de Banners**: Obtiene información adicional sobre los servicios en los puertos abiertos.
    - **Detección de Sistema Operativo**: Identifica el sistema operativo del objetivo.
    - **Ajuste de la velocidad** del escaneo: Permite ajustar la velocidad a la que se escanea para intentar evitar IDS/IPS o realizar escaneos rápidos pero ruidosos.
  - **Generación de gráfico** según los puertos abiertos, cerrados o filtrados.
- **Escáner de Hosts:**
  - **Detecta los dispositivos** conectados a una red, proporcionando:
    - Direcciones IP
    - Direcciones MAC
  - **Genera una topología de la red** para poder visualizar la estructura.
  - Permite configurar los tiempos de espera y el número de reintentos.

---

## Requisitos

- **Sistema Operativo:** Linux
- **Python:** Versión 3.10 o superior
- **Dependencias:**
  - **CustomTkinter**: Crear interfaces modernas, versión superior a Tkinter.
  - **Pillow**: Manipulación y procesado de imágenes.
  - **Matplotlib**: Creación de gráficos.
  - **Scapy**: Análisis y manipulación de paquetes de red.
  - **Networkx**: Creación de gráficos y topologías.
  - **SSL**: Conexiones seguras mediante SSL/TLS.
  - **Datetime**: Trabajar con fechas y horas.
  - **os**: Interactuar con el sistema operativo.
  - **re**: Expresiones regulares.
  - **Getpass**: Contraseñas ocultas en consola.
  - **Socket**: Soporte para comunicación en red mediante sockets.
  - **Time**: Medición de tiempos.
  - **Sys**: Acceso a variables y funciones del sistema operativo.
  - **Urllib.request**: Descargar recursos web.

---

## Instalación

### Clonar Repositorio

El primer paso será **clonar el repositorio de GitHub** utilizando el siguiente comando:

```bash
git clone <url>
```

### Instalar Dependencias

Ejecuta `requerido.sh` para instalar todas las **dependencias** necesarias:

```bash
bash requerido.sh
```

### Configurar el servidor

Asegúrate de que los certificados `server-cert.pem` y `server-key.key` estén en el mismo directorio que el script del servidor.  
Para iniciar el servidor utiliza:

```bash
sudo python3 servidor.py
```

La salida debe indicar que el servidor está en escucha:

![imagen](https://github.com/user-attachments/assets/24b6e21e-3076-4b01-9329-672521a0568c)


### Configurar el cliente/herramienta

Antes de ejecutar la herramienta **ajusta la dirección IP** del servidor (host) en el archivo `cliente.py`.  
Busca en el fichero la línea:

```
host = 192.168.56.10
```

Y cámbiala por la IP de tu servidor.  
- Para uso local, pon la IP `127.0.0.1`.
- Si hay más clientes, pon la IP del servidor o del equipo que va a actuar de servidor (por ejemplo, `192.168.56.1`).
- Si usas un servidor dedicado, pon su IP.

**Esta es la única configuración necesaria.**

### Ejecutar la herramienta

Ejecuta la herramienta con:

```bash
sudo python3 cliente.py
```

---

## Uso de la herramienta

### Login

Al ejecutar la herramienta verás un **login de sesión** donde debes introducir usuario y contraseña.  
**Por defecto** existe el usuario administrador:

- **Usuario:** admin
- **Contraseña:** admin123

![imagen](https://github.com/user-attachments/assets/d8b5339c-8958-42c7-8933-6e83be6720bc)

Tras el login, accedes directamente al chat y al menú lateral:

- Chat  
- Panel de Administrador  
- Escáner de puertos  
- Escáner de dispositivos  
- Nombre de usuario  
- Ajuste de zoom  
- Botón de salir  

![imagen](https://github.com/user-attachments/assets/a8cbd9ca-3a29-4cf0-85b9-3eab9b400b8b)

---

### Chat

La herramienta incluye un **chat**.  
Para enviar un mensaje escribe en la parte inferior y pulsa **"Enter"** o **"Enviar"**.

- Si se conecta un usuario, el chat avisará.
![imagen](https://github.com/user-attachments/assets/31427ed0-b758-428c-a4e0-f06cb511537a)
- Los mensajes aparecen en tiempo real.
![imagen](https://github.com/user-attachments/assets/01700fb1-9f71-4c1f-8e6a-23abd2756b10)
- Las palabras malsonantes serán censuradas automáticamente.
![imagen](https://github.com/user-attachments/assets/17946834-424a-4387-aa9d-bcd9545d7491)

Para ver los **usuarios conectados** pulsa el botón **"Usuarios conectados"** en la parte inferior.  
![imagen](https://github.com/user-attachments/assets/f13e1762-f580-43a2-bf90-446e010b22e1)
Aparecerá la lista de usuarios conectados.
![imagen](https://github.com/user-attachments/assets/b44fd7d4-bd15-4a3b-8484-ae0413334b66)


---

### Panel de Administrador

Si iniciaste sesión como **administrador**, tendrás acceso al botón de **Panel de administrador**.
![imagen](https://github.com/user-attachments/assets/a225637b-cc5b-4f2c-9197-0e4ee3fa4a85)

En el panel puedes:

- Introducir **Usuario objetivo** (exista o no).
- Especificar **Razón** del baneo (opcional).
- Escribir **Contraseña** (solo para crear usuario).
- Marcar **Checkbox** para crear nuevo administrador.
- Marcar **baneo permanente**.
- Elegir tiempo de baneo (mín. 5 min | máx. 24 h).
- Usar botones:
  - **Expulsar:** Expulsa al usuario.
  - **Banear:** Banea según tiempo elegido.
  - **Desbanear:** Quita el baneo.
  - **Añadir Usuario:** Crea nuevo usuario.
  - **Eliminar Usuario:** Elimina usuario.
  - **Ver logs:** Muestra logs de la herramienta.
  - **Ver Usuarios:** Diferencia entre user y admin, muestra quién está conectado.
  - **Ver Baneados:** Lista usuarios baneados, duración, por quién y razón.
![imagen](https://github.com/user-attachments/assets/ce33f9ee-b046-44bb-82d5-ac5a30f04cec)

---

### Escáner de puertos

Accede desde el menú lateral ("Escáner Puertos").  
Disponible para usuarios normales y administradores.
![imagen](https://github.com/user-attachments/assets/e192cb7c-a8e8-4558-b8e2-730a801794db)
Nos encontraremos con lo siguiente:
- **Ip Objetivo:** Dirección IP a escanear.
- **Puertos a escanear:**
  - **Todos los puertos:** Escaneo de los 65535 puertos.
  - **Rango específico:**
    - Rango con guion (80-90)
    - Puerto específico (80)
    - Puertos concretos separados por coma (80,90)

- **Opciones adicionales (checkbox):**
  - **Modo sigiloso:** Escaneo discreto
  - **Mostrar solo puertos abiertos:** Solo muestra abiertos (si no, muestra abiertos, cerrados, filtrados)
  - **Analizar Banners:** Más información de servicios
  - **Detectar sistema operativo:** Identifica SO
- **Velocidad de escaneo:**
  - **T0: Paranoid:** Muy lento, evade IDS
  - **T1: Sneaky:** Lento y sigiloso
  - **T2: Polite:** Moderado
  - **T3: Normal:** Equilibrio
  - **T4: Aggressive:** Rápido
  - **T5: Insane:** Muy rápido, puede perder información
![imagen](https://github.com/user-attachments/assets/d9a22ca1-12c3-4bc1-b5a0-08cb1c62cfa6)

---

### Escáner de puertos- Ejemplo

Ejemplo de escaneo:

- **Ip Objetivo:** 192.168.56.x
- **Puertos a escanear:** Puertos comunes
- **Opciones adicionales:** Todas activadas menos "mostrar solo puertos abiertos"
- **Velocidad de escaneo:** Normal

**Resultados:**
- **Resultado en texto**
![imagen](https://github.com/user-attachments/assets/34fb0fd8-b89d-4e46-83ef-69b6b3c643f5)
- **Gráfico**
![imagen](https://github.com/user-attachments/assets/acd4c38f-1728-4324-84c7-4e32cfef93c9)

---

### Escáner de hosts

Accede desde el menú lateral ("Escáner Hosts").  
Disponible para cualquier usuario.
![imagen](https://github.com/user-attachments/assets/b5eeed7f-740e-4f14-a9d5-5781263fad9a)
Nos encontramos con lo siguiente:
- **Red objetivo:** Dirección de red (ej. 192.168.56.0/24)
- **Interfaz de red:** Selecciona la interfaz mediante desplegable
- **Tiempo de espera:** Ajusta el timeout
- **Número de reintentos:** Intentos por host
- **Checkbox:** Generar diagrama de red
![imagen](https://github.com/user-attachments/assets/08a3c9cb-df70-4727-a935-306fc0d60e33)

---

### Escáner de hosts-Ejemplo

Escaneo en entorno controlado:

- **Red objetivo:** 192.168.56.0/24
- **Interfaz de red:** vboxnet0: 192.168.56.x
- **Tiempo de espera:** Predeterminado
- **Número de reintentos:** Predeterminado
- **Topología de red:** Activado

**Resultados:**
- **En texto**
![imagen](https://github.com/user-attachments/assets/8e9f387d-e9df-464b-ab25-7a8ec23cb862)

- **Topología de red**
![imagen](https://github.com/user-attachments/assets/a5584858-9981-4c87-a400-55edf08b6860)

---

### Configuración de la interfaz

Puedes **ajustar el zoom** de la interfaz para ver los resultados correctamente, pulsando los botones "+" o "-" en el menú lateral.
![imagen](https://github.com/user-attachments/assets/d3a47781-7b3e-43bb-b708-67c830157feb)


---

## Terminología

- **Interfaz gráfica:** Permite interactuar con la herramienta de forma visual y sencilla.
- **Login de usuario:** Sistema de autenticación que permite controlar el acceso y las sesiones activas.
- **Gestión de usuarios:** Crear, eliminar y restringir usuarios.
- **Chat seguro:** Comunicación en tiempo real cifrada, con censura automática y registro.
- **Escaneo de puertos:** Detecta puertos abiertos, cerrados o filtrados y los servicios asociados.
- **Modo sigiloso:** Escaneo sin completar la conexión, más discreto y difícil de detectar.
- **Análisis de banners:** Extrae información adicional de servicios en puertos abiertos.
- **Detección de sistema operativo:** Identifica el SO según las respuestas recibidas.
- **Velocidad de escaneo:** Ajusta la rapidez del escaneo para evadir detección o acelerar resultados.
- **Escáner de hosts:** Detecta dispositivos en una red, mostrando IP, MAC y la topología.
- **Topología de red:** Visualiza cómo están conectados los dispositivos en la red.
- **Logs:** Registro de actividades de usuarios y herramienta.
- **SSL/TLS:** Protocolos para cifrar comunicaciones entre cliente y servidor.

---
