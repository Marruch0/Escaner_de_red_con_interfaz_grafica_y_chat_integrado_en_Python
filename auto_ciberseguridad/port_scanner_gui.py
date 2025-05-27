#!/usr/bin/env python3
import socket, threading, re, os, time, platform, datetime, getpass
import sys
import importlib.util
from customtkinter import *
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Importar el módulo de escáner existente
spec = importlib.util.spec_from_file_location("scanner_module", "./escaner.py")
scanner_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner_module)

class PortScannerGUI:
    def __init__(self, parent_frame):
        # Definir colores - usar misma paleta que la interfaz principal
        self.color_fondo = "#1E202F"
        self.color_panel = "#252836"
        self.color_boton = "#6C5CE7"
        self.color_hover = "#5d4fd1"
        self.color_texto_claro = "#E4E6F3"
        self.color_texto_oscuro = "#8A8D9F"
        
        # Colores de acción
        self.color_danger = "#F25757"
        self.color_danger_hover = "#D32F2F"
        self.color_success = "#4CAF50"
        self.color_success_hover = "#388E3C"
        
        # Panel principal (dos columnas)
        self.frame_principal = CTkFrame(parent_frame, fg_color=self.color_fondo)
        self.frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Columna izquierda - Configuración
        self.columna_izq = CTkFrame(self.frame_principal, fg_color=self.color_fondo)
        self.columna_izq.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Panel de configuración
        self.panel_config = CTkFrame(self.columna_izq, fg_color=self.color_panel)
        self.panel_config.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Título
        self.titulo = CTkLabel(self.panel_config, text="Configuración del Escáner", 
                             font=("Arial", 18, "bold"), text_color=self.color_texto_claro)
        self.titulo.pack(pady=(10, 5))
        
        # Panel de entrada
        self.panel_datos = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_datos.pack(fill="x", padx=10, pady=5)
        
        # IP objetivo
        self.label_ip = CTkLabel(self.panel_datos, text="IP objetivo:", anchor="w", 
                               text_color=self.color_texto_claro)
        self.label_ip.pack(pady=(5, 0), anchor="w")
        
        self.campo_ip = CTkEntry(self.panel_datos, placeholder_text="Ej: 192.168.1.1", width=200)
        self.campo_ip.pack(pady=5, fill="x")
        
        # Opciones de puertos
        self.label_puertos = CTkLabel(self.panel_datos, text="Puertos a escanear:", 
                                    anchor="w", text_color=self.color_texto_claro)
        self.label_puertos.pack(pady=(5, 0), anchor="w")
        
        # Variables para las opciones
        self.option_var = IntVar(value=3)  # Default: puertos comunes
        
        # Opciones con RadioButtons
        self.radio_todos = CTkRadioButton(self.panel_datos, text="Todos los puertos (0-65535)", 
                                         variable=self.option_var, value=1, 
                                         text_color=self.color_texto_claro,
                                         fg_color=self.color_boton, hover_color=self.color_hover)
        self.radio_todos.pack(pady=5, anchor="w")
        
        self.radio_rango = CTkRadioButton(self.panel_datos, text="Rango específico", 
                                        variable=self.option_var, value=2,
                                        text_color=self.color_texto_claro,
                                        fg_color=self.color_boton, hover_color=self.color_hover)
        self.radio_rango.pack(pady=5, anchor="w")
        
        # Campo para rango específico
        self.campo_rango = CTkEntry(self.panel_datos, placeholder_text="Ej: 80,443 o 8080-8085", width=200)
        self.campo_rango.pack(pady=5, fill="x")
        
        self.radio_comunes = CTkRadioButton(self.panel_datos, text="Puertos comunes", 
                                          variable=self.option_var, value=3,
                                          text_color=self.color_texto_claro,
                                          fg_color=self.color_boton, hover_color=self.color_hover)
        self.radio_comunes.pack(pady=5, anchor="w")
        
        # Opciones adicionales
        self.panel_opciones = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_opciones.pack(fill="x", padx=10, pady=5)
        
        self.label_opciones = CTkLabel(self.panel_opciones, text="Opciones adicionales:", 
                                     anchor="w", text_color=self.color_texto_claro)
        self.label_opciones.pack(pady=(5, 0), anchor="w")
        
        # Variables para checkboxes
        self.var_stealth = IntVar(value=0)
        self.var_only_open = IntVar(value=1)
        self.var_vulns = IntVar(value=1)
        
        # Checkboxes
        self.check_stealth = CTkCheckBox(self.panel_opciones, text="Modo sigiloso (half-open)", 
                                       variable=self.var_stealth, 
                                       text_color=self.color_texto_claro,
                                       fg_color=self.color_boton, hover_color=self.color_hover)
        self.check_stealth.pack(pady=5, anchor="w")
        
        self.check_only_open = CTkCheckBox(self.panel_opciones, text="Mostrar solo puertos abiertos", 
                                         variable=self.var_only_open,
                                         text_color=self.color_texto_claro,
                                         fg_color=self.color_boton, hover_color=self.color_hover)
        self.check_only_open.pack(pady=5, anchor="w")
        
        self.check_vulns = CTkCheckBox(self.panel_opciones, text="Analizar vulnerabilidades", 
                                     variable=self.var_vulns,
                                     text_color=self.color_texto_claro,
                                     fg_color=self.color_boton, hover_color=self.color_hover)
        self.check_vulns.pack(pady=5, anchor="w")
        
        # Nivel de temporización
        self.panel_tiempo = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_tiempo.pack(fill="x", padx=10, pady=5)
        
        self.label_timing = CTkLabel(self.panel_tiempo, text="Nivel de temporización:", 
                                   anchor="w", text_color=self.color_texto_claro)
        self.label_timing.pack(pady=(5, 0), anchor="w")
        
        self.nivel_texto = CTkLabel(self.panel_tiempo, text="T3: Normal - Equilibrio entre velocidad y precisión", 
                                 anchor="w", text_color=self.color_texto_claro)
        self.nivel_texto.pack(pady=(5, 0), anchor="w")
        
        def actualizar_nivel(valor):
            nivel = int(float(valor))
            descripciones = {
                0: "T0: Paranoid - Muy lento, ideal para evadir IDS",
                1: "T1: Sneaky - Lento y sigiloso",
                2: "T2: Polite - Moderado, menor carga en la red",
                3: "T3: Normal - Equilibrio entre velocidad y precisión",
                4: "T4: Aggressive - Rápido, asume buena conectividad",
                5: "T5: Insane - Muy rápido, puede perder información"
            }
            self.nivel_texto.configure(text=descripciones[nivel])
        
        self.slider_timing = CTkSlider(self.panel_tiempo, from_=0, to=5, number_of_steps=5, 
                                   command=actualizar_nivel,
                                   progress_color=self.color_boton, button_color=self.color_boton, 
                                   button_hover_color=self.color_hover)
        self.slider_timing.pack(fill="x", pady=5)
        self.slider_timing.set(3)  # Default: T3
        
        # Botones
        self.panel_botones = CTkFrame(self.panel_config, fg_color=self.color_panel)
        self.panel_botones.pack(fill="x", padx=10, pady=10)
        
        self.boton_escanear = CTkButton(self.panel_botones, text="Iniciar Escaneo", 
                                      command=self.iniciar_escaneo,
                                      fg_color=self.color_success, 
                                      hover_color=self.color_success_hover,
                                      height=40, font=("Arial", 14, "bold"))
        self.boton_escanear.pack(fill="x", pady=10)
        
        # Columna derecha - Resultados
        self.columna_der = CTkFrame(self.frame_principal, fg_color=self.color_fondo)
        self.columna_der.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        self.panel_resultado = CTkFrame(self.columna_der, fg_color=self.color_panel)
        self.panel_resultado.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.titulo_resultado = CTkLabel(self.panel_resultado, text="Resultados del Escaneo", 
                                       font=("Arial", 18, "bold"), text_color=self.color_texto_claro)
        self.titulo_resultado.pack(pady=(10, 5))
        
        # Notebook (pestañas) para organizar resultados
        self.tab_view = CTkTabview(self.panel_resultado, fg_color=self.color_panel, 
                                 segmented_button_fg_color=self.color_boton,
                                 segmented_button_selected_color=self.color_hover,
                                 segmented_button_unselected_color=self.color_panel,
                                 segmented_button_selected_hover_color=self.color_hover)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Crear pestañas
        self.tab_view.add("Puertos")
        self.tab_view.add("Gráfico")
        self.tab_view.add("Vulnerabilidades")
        
        # Pestaña 1: Puertos
        self.area_puertos = CTkTextbox(self.tab_view.tab("Puertos"), font=("Consolas", 11), 
                                     text_color=self.color_texto_claro)
        self.area_puertos.pack(fill="both", expand=True, padx=5, pady=5)
        self.area_puertos.insert("1.0", "Los resultados del escaneo aparecerán aquí.")
        self.area_puertos.configure(state="disabled")
        
        # Pestaña 2: Gráfico
        self.frame_grafico = CTkFrame(self.tab_view.tab("Gráfico"), fg_color=self.color_panel)
        self.frame_grafico.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Espacio para gráfico matplotlib
        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.fig.patch.set_facecolor(self.color_panel)
        self.ax.set_facecolor(self.color_panel)
        self.ax.text(0.5, 0.5, "Ejecute un escaneo para ver el gráfico", 
                    ha='center', va='center', color=self.color_texto_claro, fontsize=12)
        self.ax.axis('off')
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.frame_grafico)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Pestaña 3: Vulnerabilidades
        self.area_vulnerabilidades = CTkTextbox(self.tab_view.tab("Vulnerabilidades"), 
                                             font=("Consolas", 11), text_color=self.color_texto_claro)
        self.area_vulnerabilidades.pack(fill="both", expand=True, padx=5, pady=5)
        self.area_vulnerabilidades.insert("1.0", "El análisis de vulnerabilidades aparecerá aquí si está activado.")
        self.area_vulnerabilidades.configure(state="disabled")
        
        # Estado del escaneo
        self.frame_estado = CTkFrame(self.panel_resultado, fg_color=self.color_panel, height=30)
        self.frame_estado.pack(fill="x", padx=10, pady=(5, 10))
        
        self.label_estado = CTkLabel(self.frame_estado, text="Listo para escanear", 
                                   text_color=self.color_texto_claro)
        self.label_estado.pack(side="left", padx=10)
        
        self.progress_bar = CTkProgressBar(self.frame_estado, width=150, 
                                        progress_color=self.color_boton)
        self.progress_bar.pack(side="right", padx=10)
        self.progress_bar.set(0)
        
        # Variable para el hilo de escaneo
        self.scan_thread = None
        self.stop_event = threading.Event()

    def update_estado(self, mensaje, progreso=None):
        """Actualiza el estado del escaneo en la interfaz"""
        self.label_estado.configure(text=mensaje)
        if progreso is not None:
            self.progress_bar.set(progreso)

    def mostrar_resultados(self, results, os_detected, total_time):
        """Muestra los resultados del escaneo en la interfaz"""
        # Actualizar pestaña de puertos
        self.area_puertos.configure(state='normal')
        self.area_puertos.delete("1.0", END)
        
        if results:
            texto = f"=== Resultados del Escaneo ===\n\n"
            for port, status, service, banner in results:
                texto += f"Puerto {port}: {status} ({service})\n"
                if banner != "N/A":
                    texto += f"  Banner: {banner}\n"
            
            texto += f"\nSistema operativo detectado: {os_detected}\n"
            texto += f"Tiempo total de escaneo: {total_time:.2f} segundos"
        else:
            texto = "No se encontraron puertos abiertos en el rango especificado."
        
        self.area_puertos.insert("1.0", texto)
        self.area_puertos.configure(state='disabled')
        
        # Actualizar gráfico
        if results:
            self.generar_grafico(results)
    
    def generar_grafico(self, results):
        """Genera y muestra el gráfico de resultados"""
        statuses = [s for _, s, _, _ in results]
        counts = {
            "Abiertos": statuses.count("Abierto"), 
            "Cerrados": statuses.count("Cerrado"), 
            "Filtrados": statuses.count("Filtrado")
        }
        
        labels, sizes, colors = [], [], []
        if counts["Abiertos"]: 
            labels.append("Abiertos")
            sizes.append(counts["Abiertos"])
            colors.append("green")
        if counts["Cerrados"]: 
            labels.append("Cerrados")
            sizes.append(counts["Cerrados"])
            colors.append("red")
        if counts["Filtrados"]: 
            labels.append("Filtrados")
            sizes.append(counts["Filtrados"])
            colors.append("yellow")
        
        self.ax.clear()
        if sizes:
            self.ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
            self.ax.set_title("Estado de los puertos", color=self.color_texto_claro)
            self.ax.axis("equal")
        else:
            self.ax.text(0.5, 0.5, "No hay datos para mostrar", 
                       ha='center', va='center', color=self.color_texto_claro, fontsize=12)
            self.ax.axis('off')
        
        self.fig.patch.set_facecolor(self.color_panel)
        self.ax.set_facecolor(self.color_panel)
        for text in self.ax.texts:
            text.set_color(self.color_texto_claro)
        
        self.canvas.draw()
    
    def mostrar_vulnerabilidades(self, vulns):
        """Muestra las vulnerabilidades encontradas"""
        self.area_vulnerabilidades.configure(state='normal')
        self.area_vulnerabilidades.delete("1.0", END)
        
        if vulns:
            texto = "=== Vulnerabilidades Detectadas ===\n\n"
            for port, service, version, cve_id, desc, cvss in vulns:
                texto += f"Puerto {port}: {service} versión {version}\n"
                texto += f"  CVE: {cve_id}\n"
                texto += f"  Descripción: {desc}\n"
                texto += f"  Puntuación CVSS: {cvss}\n\n"
        else:
            texto = "No se encontraron vulnerabilidades conocidas en los servicios detectados."
        
        self.area_vulnerabilidades.insert("1.0", texto)
        self.area_vulnerabilidades.configure(state='disabled')
    
    def iniciar_escaneo(self):
        """Inicia el escaneo de puertos en un hilo separado"""
        # Validar la IP
        ip = self.campo_ip.get().strip()
        if not ip:
            self.mostrar_error("Por favor, introduce una dirección IP válida.")
            return
        
        # Determinar los puertos según la opción seleccionada
        option = self.option_var.get()
        if option == 1:  # Todos los puertos
            ports = range(0, 65536)
            rango_str = "0-65535"
        elif option == 2:  # Rango específico
            port_range = self.campo_rango.get().strip()
            if not port_range:
                self.mostrar_error("Por favor, introduce un rango de puertos válido.")
                return
            
            try:
                ports = set()
                for item in port_range.split(","):
                    if "-" in item:
                        start, end = map(int, item.split("-"))
                        ports.update(range(start, end + 1))
                    else:
                        ports.add(int(item))
                ports = sorted(ports)
                rango_str = port_range
            except ValueError:
                self.mostrar_error("Formato de rango de puertos inválido.")
                return
        elif option == 3:  # Puertos comunes
            ports = scanner_module.COMMON_PORTS.keys()
            rango_str = "Puertos comunes"
        
        # Obtener otras opciones
        stealth = bool(self.var_stealth.get())
        show_only_open = bool(self.var_only_open.get())
        analyze_vulns = bool(self.var_vulns.get())
        timing_level = int(self.slider_timing.get())
        
        # Desactivar botón de escaneo durante el proceso
        self.boton_escanear.configure(state="disabled", text="Escaneando...")
        self.update_estado("Iniciando escaneo...", 0.1)
        
        # Reiniciar evento de parada
        self.stop_event.clear()
        
        # Función para ejecutar en un hilo separado
        def run_scan():
            try:
                # Registrar inicio
                start_time = time.time()
                scanner_module.log_escaneo(ip, rango_str, stealth, timing_level)
                
                # Actualizar interfaz
                self.update_estado(f"Escaneando {ip}, nivel T{timing_level}...", 0.3)
                
                # Ejecutar escaneo
                results = scanner_module.scan_ports(
                    ip, ports, stealth=stealth, 
                    show_only_open=show_only_open, 
                    timing_level=timing_level
                )
                
                if self.stop_event.is_set():
                    return
                
                # Detectar sistema operativo
                self.update_estado("Detectando sistema operativo...", 0.7)
                os_detected = scanner_module.os_fingerprinting(
                    ip, scanner_module.TIMING_TEMPLATES[timing_level]["timeout"]
                )
                
                # Calcular tiempo total
                end_time = time.time()
                total_time = end_time - start_time
                
                # Mostrar resultados en la interfaz
                self.update_estado("Procesando resultados...", 0.8)
                self.mostrar_resultados(results, os_detected, total_time)
                
                # Analizar vulnerabilidades si está activado
                if analyze_vulns and results:
                    self.update_estado("Analizando vulnerabilidades...", 0.9)
                    vulns = scanner_module.analyze_vulnerabilities(results)
                    self.mostrar_vulnerabilidades(vulns)
                
                # Finalizar
                self.update_estado(f"Escaneo completado en {total_time:.2f} segundos", 1)
                
            except Exception as e:
                self.mostrar_error(f"Error durante el escaneo: {str(e)}")
            finally:
                # Reactivar botón de escaneo
                self.boton_escanear.configure(state="normal", text="Iniciar Escaneo")
        
        # Iniciar hilo
        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def mostrar_error(self, mensaje):
        """Muestra un mensaje de error"""
        self.update_estado(f"Error: {mensaje}", 0)
        self.boton_escanear.configure(state="normal", text="Iniciar Escaneo")

# Esta función será llamada desde la interfaz principal
def añadir_escaner_puertos(frame):
    """Crea la interfaz del escáner de puertos"""
    return PortScannerGUI(frame)