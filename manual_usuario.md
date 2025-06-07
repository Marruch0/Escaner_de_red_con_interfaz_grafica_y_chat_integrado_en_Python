# Manual de Usuario Técnico

## Introducción
Este manual está diseñado para proporcionar una guía exhaustiva y detallada sobre cómo instalar, configurar y utilizar la aplicación desarrollada como parte del Trabajo de Fin de Grado (TFG). La aplicación tiene como objetivo principal ofrecer herramientas avanzadas de ciberseguridad a través de una interfaz gráfica intuitiva y fácil de usar. Las funcionalidades incluyen:

1. **Gestión de usuarios y administración:**
   - Permite a los administradores gestionar usuarios, aplicar restricciones y supervisar actividades.

2. **Escaneo de puertos y análisis de red:**
   - Identifica servicios abiertos en dispositivos de la red para evaluar posibles puntos de acceso o vulnerabilidades.
   - Proporciona información detallada sobre los puertos abiertos y los servicios asociados.
   - Incluye opciones avanzadas como:
     - **Modo sigiloso:** Realiza escaneos discretos para evitar detección.
     - **Análisis de banners:** Obtén información adicional sobre los servicios en los puertos abiertos.
     - **Detección de sistema operativo:** Identifica el sistema operativo del host objetivo.

3. **Escáner de hosts:**
   - Detecta dispositivos conectados a la red, proporcionando detalles como:
     - Direcciones IP.
     - Direcciones MAC.
     - Estado de actividad (activo/inactivo).
   - Genera gráficos de topología de red para visualizar la estructura de la red.
   - Permite configurar opciones avanzadas como:
     - **Interfaz de red:** Selección de la interfaz a utilizar.
     - **Tiempo de espera:** Ajuste del tiempo de espera para respuestas.
     - **Número de reintentos:** Configuración de intentos por host.

4. **Generación de topologías de red:**
   - Crea diagramas visuales que representan la estructura de la red, facilitando la identificación de dispositivos y conexiones.

5. **Análisis de vulnerabilidades:**
   - Identifica posibles vulnerabilidades en los dispositivos escaneados, proporcionando información detallada para su mitigación.

6. **Registro y auditoría:**
   - Mantiene un registro detallado de todas las actividades realizadas en la aplicación, incluyendo logs de chat, escaneos y acciones administrativas.

7. **Configuración personalizada:**
   - Permite ajustar parámetros avanzados para adaptarse a diferentes entornos de red y necesidades específicas.

8. **Chat seguro:**
   - Ofrece un sistema de comunicación en tiempo real con medidas de seguridad integradas, como la censura de mensajes inapropiados y el registro de logs.

9. **Inicio de Sesión:**
   - Proporciona un sistema de autenticación para garantizar que solo usuarios autorizados puedan acceder a la aplicación.
   - Los usuarios deben ingresar su nombre de usuario y contraseña para iniciar sesión.
   - Incluye medidas de seguridad para proteger las credenciales de los usuarios.

10. **Interfaz gráfica:**
    - Diseñada para ser intuitiva y accesible, permite a los usuarios interactuar fácilmente con todas las funcionalidades de la aplicación.

Este documento está diseñado para usuarios técnicos que deseen implementar y operar la aplicación en un entorno de red. Se incluyen instrucciones detalladas para cada funcionalidad, así como soluciones a problemas comunes y referencias útiles.

---

## Requisitos del Sistema

### Hardware
Para garantizar un rendimiento óptimo, se recomienda cumplir con los siguientes requisitos mínimos:
- **Procesador:** Intel Core i3 o superior.
- **Memoria RAM:** 4 GB mínimo (8 GB recomendado).
- **Espacio en disco:** Al menos 500 MB de espacio libre.

### Software
La aplicación está diseñada para ejecutarse en sistemas basados en Linux. A continuación, se detallan los requisitos de software:
- **Sistema Operativo:** Linux (probado en distribuciones basadas en Debian).
- **Python:** Versión 3.10 o superior.
- **Dependencias adicionales:**
  - `customtkinter`: Biblioteca para crear interfaces gráficas modernas y personalizables con soporte para temas oscuros.
  - `Pillow`: Librería para la manipulación y procesamiento de imágenes.
  - `matplotlib`: Herramienta para la creación de gráficos y visualizaciones avanzadas.
  - `scapy`: Framework para el análisis y manipulación de paquetes de red.
  - `networkx`: Biblioteca para la creación, manipulación y estudio de grafos y redes complejas.
  - `ssl`: Proporciona soporte para conexiones seguras mediante el protocolo SSL/TLS.
  - `datetime`: Módulo para trabajar con fechas y horas.
  - `os`: Proporciona funciones para interactuar con el sistema operativo, como manejo de archivos y directorios.
  - `re`: Módulo para trabajar con expresiones regulares, útil para búsquedas y validaciones de texto.
  - `getpass`: Permite manejar contraseñas de forma segura sin mostrarlas en la consola.
  - `socket`: Proporciona soporte para la comunicación en red mediante sockets.
  - `time`: Herramientas para medir y gestionar tiempos y retrasos.
  - `sys`: Permite interactuar con el sistema operativo y acceder a variables y funciones específicas del entorno de ejecución.
  - `urllib.request`: Módulo para realizar solicitudes HTTP y descargar recursos desde la web.

---

## Instalación

### Paso 1: Clonar el Repositorio
El primer paso para instalar la aplicación es clonar el repositorio en tu máquina local. Esto se puede hacer utilizando el siguiente comando:
```sh
git clone <URL_DEL_REPOSITORIO>
```

### Paso 2: Instalar Dependencias
Una vez clonado el repositorio, navega al directorio del proyecto y ejecuta el siguiente comando para instalar todas las dependencias necesarias:
```sh
pip install -r requerido.sh
```

### Paso 3: Configurar el Servidor
1. Asegúrate de que los certificados `server-cert.pem` y `server-key.key` están en el directorio correcto.
2. Inicia el servidor ejecutando el siguiente comando:
   ```sh
   python3 servidor_modificado.py
   ```

### Paso 4: Configurar el Host
Antes de ejecutar el cliente, es necesario ajustar la dirección IP del host en el código del cliente para que coincida con la dirección IP del servidor. Esto se puede hacer editando el archivo `cliente_modificado.py`:

1. Abre el archivo `cliente_modificado.py` en un editor de texto.
2. Busca la sección donde se define la variable `host`:
   ```python
   host = '192.168.56.10'  # Dirección IP del servidor
   ```
3. Cambia el valor de `host` para que coincida con la dirección IP del servidor en tu red.
4. Guarda los cambios y cierra el archivo.

### Paso 5: Ejecutar el Cliente
Una vez configurado el host, puedes iniciar el cliente utilizando el siguiente comando:
```sh
python3 cliente_modificado.py
```

---

## Uso de la Aplicación

### 1. **Inicio de Sesión**
- Al abrir el cliente, se mostrará una ventana de inicio de sesión.
- Introduce tu nombre de usuario y contraseña.
- Haz clic en el botón **Login** para acceder al sistema.

### 2. **Panel de Administración**
El panel de administración permite gestionar usuarios y realizar acciones administrativas. A continuación, se describen las funcionalidades principales:

#### Funcionalidades Principales
- **Expulsar Usuario:**
  - Introduce el nombre del usuario en el campo correspondiente.
  - Haz clic en el botón "Expulsar" para desconectar al usuario del servidor.

- **Banear Usuario:**
  - Configura el tiempo de baneo utilizando el deslizador.
  - Haz clic en el botón "Banear" para aplicar el baneo.
  - Si seleccionas "Baneo permanente", el usuario será baneado indefinidamente.

- **Añadir Usuario:**
  - Introduce el nombre y la contraseña del nuevo usuario.
  - Selecciona si será administrador marcando la casilla correspondiente.
  - Haz clic en "Añadir Usuario".

- **Eliminar Usuario:**
  - Introduce el nombre del usuario a eliminar.
  - Haz clic en "Eliminar Usuario".

- **Visualización de Logs:**
  - Haz clic en "Ver Logs" para obtener un registro detallado de las acciones realizadas en el servidor.

- **Ver Usuarios:**
  - Haz clic en "Ver Usuarios" para obtener una lista de los usuarios registrados.

- **Ver Usuarios Baneados:**
  - Haz clic en "Ver Baneados" para obtener una lista de los usuarios baneados.

### 3. **Escaneo de Puertos**
La aplicación incluye un módulo para realizar escaneos de puertos en redes específicas. Sigue estos pasos:

#### Configuración del Escáner de Puertos
1. Ejecuta el script `escaner_puertos.py`.
2. Introduce la dirección IP o rango de IPs que deseas escanear.
3. Selecciona el rango de puertos a escanear (por ejemplo, 1-65535).
4. Configura las opciones avanzadas:
   - **Modo sigiloso:** Activa esta opción para realizar un escaneo más discreto.
   - **Mostrar solo puertos abiertos:** Filtra los resultados para mostrar únicamente los puertos abiertos.
   - **Analizar banners:** Obtén información adicional sobre los servicios en los puertos abiertos.
   - **Detectar sistema operativo:** Intenta identificar el sistema operativo del host objetivo.
5. Haz clic en "Iniciar Escaneo".

#### Resultados del Escaneo
- Los resultados se almacenan en el directorio `resultados_scan/`.
- Incluyen un archivo de texto con los puertos abiertos y un diagrama de topología de red generado automáticamente.

### 4. **Panel de Escáner de Hosts**
El escáner de hosts permite identificar dispositivos conectados a la red. Sigue estos pasos:

#### Uso del Escáner de Hosts
1. Ejecuta el script `hosts_prueba.py`.
2. Introduce la dirección IP o rango de IPs que deseas analizar.
3. Configura las opciones avanzadas:
   - **Interfaz de red:** Selecciona la interfaz de red a utilizar.
   - **Tiempo de espera:** Ajusta el tiempo de espera para las respuestas.
   - **Número de reintentos:** Configura cuántos intentos realizar por host.
4. Haz clic en "Escanear Hosts".

#### Resultados del Escaneo
- Los resultados incluyen una lista de dispositivos detectados, su dirección IP, su dirección MAC y su estado (activo/inactivo).
- Los datos se presentan en una tabla interactiva dentro de la interfaz gráfica.
- Se genera un gráfico de topología de red con iconos representativos para cada tipo de dispositivo.

### 5. **Chat Seguro**
El sistema incluye un módulo de chat seguro para la comunicación entre usuarios. Sigue estos pasos:

#### Uso del Chat
1. **Enviar Mensajes:**
   - Escribe tu mensaje en el campo de entrada.
   - Haz clic en el botón "Enviar" o presiona Enter para enviar el mensaje.

2. **Recepción de Mensajes:**
   - Los mensajes enviados por otros usuarios aparecerán automáticamente en el área de chat.

3. **Censura de Mensajes:**
   - El sistema censura automáticamente palabras ofensivas o inapropiadas.

4. **Logs del Chat:**
   - Todos los mensajes se registran en el archivo `chat_logs.txt` para auditoría.

---

## Capturas de Pantalla

### Ventana de Inicio de Sesión
![Ventana de Inicio de Sesión](ChatGPT%20Image%2026%20may%202025,%2020_30_48.png)

### Panel de Administración
![Panel de Administración](pruebas%20copy/logo.png)

### Resultados del Escaneo de Puertos
![Resultados del Escaneo](resultados_scan/topologia_red_20250520_212102.png)

---

## Solución de Problemas

### Problemas Comunes

1. **Error de conexión al servidor:**
   - Verifica que el servidor está en ejecución.
   - Asegúrate de que el cliente y el servidor están en la misma red.

2. **Dependencias no instaladas:**
   - Ejecuta nuevamente el comando:
     ```sh
     pip install -r requerido.sh
     ```

3. **Problemas con el escaneo de puertos:**
   - Asegúrate de que `nmap` está instalado en el sistema:
     ```sh
     sudo apt install nmap
     ```

4. **Errores en la interfaz gráfica:**
   - Verifica que `customtkinter` está correctamente instalado.

---

## Contacto
Para cualquier duda o problema, contacta con el desarrollador en: [correo@example.com](mailto:correo@example.com).

---

## Apéndice

### Estructura del Proyecto
El proyecto está organizado de la siguiente manera:
- **`servidor_modificado.py:`** Contiene la lógica del servidor.
- **`cliente_modificado.py:`** Contiene la lógica del cliente.
- **`escaner_puertos.py:`** Script para realizar escaneos de puertos.
- **`hosts_prueba.py:`** Script para escanear hosts en la red.
- **`resultados_scan/`** Directorio donde se almacenan los resultados de los escaneos.

### Comandos del Servidor
- **`/kick <usuario>`:** Expulsa a un usuario.
- **`/ban <usuario> <tiempo>`:** Banea a un usuario por un tiempo específico.
- **`/unban <usuario>`:** Desbanea a un usuario.
- **`/adduser <usuario> <contraseña>`:** Añade un nuevo usuario.
- **`/deluser <usuario>`:** Elimina un usuario.
- **`/logs:`** Muestra los logs del servidor.

### Notas Adicionales
- Asegúrate de realizar copias de seguridad periódicas de los archivos de configuración y logs.
- Utiliza herramientas de monitoreo para garantizar la estabilidad del servidor.

---

## Referencias
- Documentación oficial de Python: [https://docs.python.org/3/](https://docs.python.org/3/)
- Documentación de `nmap`: [https://nmap.org/](https://nmap.org/)