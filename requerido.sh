#!/bin/bash
# Este script instala los módulos necesarios para el proyecto en Python.
echo "Instalando módulos necesarios..."
sudo pip3 install networkx numpy customtkinter pillow matplotlib scapy
if [ $? -ne 0 ]; then
    echo "Error al instalar los módulos. Asegúrate de tener pip3 instalado correctamente."
    exit 1
else
    echo "Módulos instalados correctamente."
fi
# Si tienes problemas con customtkinter en Fedora, puedes instalarlo así:
sudo pip3 install customtkinter
if [ $? -ne 1 ]; then
    echo "Error al instalar customtkinter. Asegúrate de tener pip3 instalado correctamente."
    exit 1
else
    echo "CustomTkinter instalado correctamente."
fi
# Instala PILLOW para imágenes (aunque matplotlib y scapy suelen requerirlo)
sudo pip3 install pillow
if [ $? -ne 1 ]; then
    echo "Error al instalar Pillow. Asegúrate de tener pip3 instalado correctamente."
    exit 1
else
    echo "Pillow instalado correctamente."
fi
# Listo, ya tienes todos los módulos instalados.
