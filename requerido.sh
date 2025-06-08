#!/bin/bash

# Este script instala todas las dependencias necesarias para cliente.py, servidor.py y user_manager.py

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Función para mostrar mensajes con colores
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[ÉXITO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_installing() {
    echo -e "${CYAN}[INSTALANDO]${NC} $1"
}

# Función para verificar si un comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Variable global para el comando pip
PIP_CMD=""

# Función para determinar el comando pip a usar
setup_pip_command() {
    if command_exists sudo; then
        # Verificar si podemos usar sudo sin contraseña
        if sudo -n true 2>/dev/null; then
            PIP_CMD="sudo pip3"
            log_info "Usando sudo pip3 para instalaciones"
        else
            log_warning "sudo requiere contraseña, se te pedirá durante la instalación"
            PIP_CMD="sudo pip3"
        fi
    else
        # No hay sudo disponible, intentar con pip3 normal
        PIP_CMD="pip3"
        log_warning "sudo no disponible, usando pip3 normal (algunas instalaciones pueden fallar)"
    fi
}

# Función para instalar un paquete con manejo de errores
install_package() {
    local package="$1"
    local description="$2"
    
    log_installing "Instalando $description ($package)..."
    
    # Usar el comando pip determinado anteriormente
    if $PIP_CMD install "$package" --user 2>/dev/null || $PIP_CMD install "$package"; then
        log_success "$description instalado correctamente"
        return 0
    else
        log_error "Error al instalar $description ($package)"
        return 1
    fi
}

# Banner de inicio
echo "======================================================================"
echo -e "${CYAN}    INSTALADOR DE DEPENDENCIAS - PROYECTO CHAT + ESCÁNER RED${NC}"
echo "======================================================================"
echo ""

# Verificar prerrequisitos del sistema
log_info "Verificando prerrequisitos del sistema..."

# Verificar Python 3
if ! command_exists python3; then
    log_error "Python 3 no está instalado. Por favor, instala Python 3 primero."
    exit 1
else
    python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
    log_success "Python 3 encontrado (versión: $python_version)"
fi

# Verificar pip3
if ! command_exists pip3; then
    log_error "pip3 no está instalado. Por favor, instala pip3 primero."
    log_info "En sistemas basados en Debian/Ubuntu: sudo apt install python3-pip"
    log_info "En sistemas basados en RedHat/Fedora: sudo yum install python3-pip"
    exit 1
else
    log_success "pip3 encontrado"
fi

# Verificar si tenemos permisos de sudo
setup_pip_command

# Crear y activar entorno virtual automáticamente si no se detecta
log_info "Verificando entorno virtual de Python..."
if [ -z "$VIRTUAL_ENV" ]; then
    log_warning "No se detectó un entorno virtual de Python. Creando uno automáticamente..."
    python3 -m venv venv
    if [ $? -eq 0 ]; then
        log_success "Entorno virtual creado exitosamente. Activando..."
        source venv/bin/activate
        log_success "Entorno virtual activado: $(pwd)/venv"
    else
        log_error "Error al crear el entorno virtual. Por favor, verifica tu instalación de Python."
        exit 1
    fi
else
    log_success "Entorno virtual detectado: $VIRTUAL_ENV"
fi

# Verificar permisos de escritura en el directorio actual
log_info "Verificando permisos de escritura en el directorio actual..."
if [ ! -w . ]; then
    log_error "No tienes permisos de escritura en el directorio actual."
    log_info "Por favor, ejecuta este script desde un directorio donde tengas permisos de escritura."
    exit 1
else
    log_success "Permisos de escritura verificados."
fi

echo ""
log_info "Iniciando instalación de dependencias Python..."
echo ""

# Lista de dependencias con descripciones
#Array asciativo(Nunca lo habia visto)
declare -A packages=(
    ["networkx"]="NetworkX - Análisis y visualización de grafos de red"
    ["numpy"]="NumPy - Computación científica y arrays multidimensionales"
    ["customtkinter"]="CustomTkinter - Interfaz gráfica moderna con temas oscuros"
    ["pillow"]="Pillow - Manipulación y procesamiento de imágenes"
    ["matplotlib"]="Matplotlib - Generación de gráficos y visualizaciones"
    ["scapy"]="Scapy - Manipulación y análisis de paquetes de red"
)

# Contador de instalaciones exitosas y fallidas
successful_installs=0
failed_installs=0
failed_packages=()

# Instalar cada paquete
for package in "${!packages[@]}"; do
    description="${packages[$package]}"
    
    if install_package "$package" "$description"; then
        ((successful_installs++))
    else
        ((failed_installs++))
        failed_packages+=("$package")
    fi
    echo ""
done

# Verificar instalaciones específicas que podrían necesitar configuración adicional
echo "======================================================================"
log_info "Verificando instalaciones específicas..."
echo ""

# Verificar CustomTkinter (problema común en algunas distribuciones)
log_info "Verificando CustomTkinter..."
if python3 -c "import customtkinter" 2>/dev/null; then
    log_success "CustomTkinter se importa correctamente"
else
    log_warning "CustomTkinter no se puede importar, intentando reinstalación..."
    if install_package "customtkinter" "CustomTkinter (reinstalación)"; then
        ((successful_installs++))
    else
        log_error "No se pudo reinstalar CustomTkinter"
        failed_packages+=("customtkinter")
        ((failed_installs++))
    fi
fi
echo ""

# Verificar Scapy (puede necesitar permisos especiales)
log_info "Verificando Scapy..."
if python3 -c "from scapy.all import *" 2>/dev/null; then
    log_success "Scapy se importa correctamente"
else
    log_warning "Scapy puede tener problemas de permisos. Esto es normal."
    log_info "Scapy necesita permisos de administrador para algunas funciones de red."
fi
echo ""

# Verificar dependencias de sistema para Scapy (opcional)
log_info "Verificando herramientas de red del sistema..."
if command_exists nmap; then
    log_success "nmap encontrado (útil para escaneo de red)"
else
    log_warning "nmap no encontrado (opcional pero recomendado)"
    log_info "Para instalar: sudo apt install nmap (Debian/Ubuntu) o sudo yum install nmap (RedHat/Fedora)"
fi

if command_exists tcpdump; then
    log_success "tcpdump encontrado (útil para captura de paquetes)"
else
    log_warning "tcpdump no encontrado (opcional pero recomendado)"
    log_info "Para instalar: sudo apt install tcpdump (Debian/Ubuntu) o sudo yum install tcpdump (RedHat/Fedora)"
fi

# Verificar si el entorno está gestionado externamente
log_info "Verificando entorno de Python gestionado externamente..."
if python3 -m ensurepip --version 2>/dev/null; then
    log_success "El entorno de Python permite instalaciones con pip."
else
    log_warning "El entorno de Python está gestionado externamente. Usando apt para instalar dependencias del sistema."
    log_info "Instalando dependencias con apt..."
    sudo apt update
    sudo apt install -y python3-pip python3-venv python3-numpy python3-matplotlib python3-scapy
    log_success "Dependencias instaladas con apt."
    exit 0
fi

# Resumen final
echo ""
echo "======================================================================"
echo -e "${CYAN}                        RESUMEN DE INSTALACIÓN${NC}"
echo "======================================================================"

if [ $failed_installs -eq 0 ]; then
    log_success "¡Todas las dependencias se instalaron correctamente!"
    log_success "Paquetes instalados exitosamente: $successful_installs"
    echo ""
    log_info "Tu sistema está listo para ejecutar:"
    echo "  • cliente.py - Cliente de chat con escáner de red"
    echo "  • servidor.py - Servidor de chat"
    echo "  • user_manager.py - Gestor de usuarios"
    echo ""
    log_info "Para ejecutar el servidor: python3 servidor.py"
    log_info "Para ejecutar el cliente: python3 cliente.py"
else
    log_warning "Instalación completada con algunos errores"
    log_success "Paquetes instalados exitosamente: $successful_installs"
    log_error "Paquetes que fallaron: $failed_installs"
    echo ""
    log_error "Los siguientes paquetes no se pudieron instalar:"
    for pkg in "${failed_packages[@]}"; do
        echo "  • $pkg"
    done
    echo ""
    log_info "Puedes intentar instalar los paquetes fallidos manualmente:"
    for pkg in "${failed_packages[@]}"; do
        echo "  sudo pip3 install $pkg"
    done
fi

echo ""
echo "======================================================================"
log_info "Notas importantes:"
echo "• Algunas funciones de red requieren permisos de administrador"
echo "• El escáner de red funciona mejor con herramientas como nmap instaladas"
echo "• Para problemas con CustomTkinter, verifica que tengas una versión actualizada de Python"
echo "• Si experimentas problemas con SSL, asegúrate de tener los certificados requeridos"
echo "======================================================================"

# Código de salida basado en el resultado
if [ $failed_installs -eq 0 ]; then
    exit 0
else
    exit 1
fi
