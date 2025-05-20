#!/bin/bash

# Configuramos puertos abiertos, cerrados y filtrados correctamente
echo "Configurando los puertos..."

# Abrir múltiples puertos usando netcat
nc -lkp 8080 &
nc -lkp 8081 &
nc -lkp 8082 &
nc -lkp 3000 &

# Cerrado: Simplemente no exponemos el puerto
# Por ejemplo, 3001 está cerrado.

# Filtrado: Usamos iptables para bloquear completamente el tráfico hacia estos puertos
iptables -A INPUT -p tcp --dport 9090 -j DROP
iptables -A INPUT -p tcp --dport 8083 -j DROP

# Aseguramos que las reglas de iptables estén activas
iptables-save > /etc/iptables/rules.v4

# Dejamos el contenedor en ejecución esperando conexiones
echo "Puertos configurados:"
echo "Abiertos: 8080, 8081, 8082, 3000"
echo "Cerrados: 3001"
echo "Filtrados: 9090, 8083"
tail -f /dev/null