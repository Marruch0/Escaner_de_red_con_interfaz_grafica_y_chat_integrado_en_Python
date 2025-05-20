#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog, messagebox

class SimpleTextEditor:
    def __init__(self, root):
        self.root = root
        self.text_area = tk.Text(self.root)
        self.text_area.pack(fill=tk.BOTH, expand=1)#Si ponemos both veremos que la y no se expande totalemente por eso tenemos que jugar con expand=1
        self.current_open_file = ''


    def quit_confirm(self):
        if messagebox.askokcancel("Salir", "¿Seguro que quieres salir?"): # Cuando hacemos esto al puslsar aceptar nos devuelve true
            self.root.destroy()#Esto lo hacemos para salir de la ventana ya que estamos destryuendo la vetana en este caso la principal

    def open_file(self):
        filename =filedialog.askopenfilename()
        if filename:
            self.text_area.delete("1.0", tk.END)#Con esto le decimos que queremos borrar el texto desde el principio hasta el final para limpiar antes de abrir un archivo
            with open(filename, 'r') as file:
                self.text_area.insert("1.0", file.read())#de esta manera le decimos que insterte el archivo al principio del todo
            self.current_open_file = filename

    def new_file(self):
        self.text_area.delete("1.0", tk.END)
        self.current_open_file = ''

    def save_file(self):
        if not self.current_open_file:
            new_file_path = filedialog.asksaveasfilename()
            if new_file_path:
                self.current_open_file = new_file_path
            else:
                return
        with open(self.current_open_file, 'w') as file:
            file.write(self.text_area.get("1.0", tk.END))


root = tk.Tk()
root.title("Bloc de notas")
root.geometry("600x400")


editor = SimpleTextEditor(root)


menu_bar = tk.Menu(root)
menu_options = tk.Menu(menu_bar, tearoff=0)

menu_options.add_command(label="Nuevo", command=editor.new_file)
menu_options.add_command(label="Abrir", command=editor.open_file)
menu_options.add_command(label="Guardar", command=editor.save_file)
menu_options.add_command(label="Salir", command=editor.quit_confirm)

root.config(menu=menu_bar)
menu_bar.add_cascade(label="Archivo", menu=menu_options)



root.mainloop()