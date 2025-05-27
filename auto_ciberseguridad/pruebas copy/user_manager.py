#!/usr/bin/env python3
import os
from datetime import datetime, timedelta

class UserManager:
    def __init__(self, users_file="chat_users.txt", banned_file="banned_users.txt"):
        self.users_file = users_file
        self.banned_file = banned_file
        
        # Crear archivos si no existen
        if not os.path.exists(users_file):
            with open(users_file, "w") as f:
                f.write("admin|admin123|admin\n")
        if not os.path.exists(banned_file):
            open(banned_file, "w").close()
    
    def _read_users(self):
        users = {}
        try:
            with open(self.users_file, "r") as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split("|")
                        if len(parts) >= 3:
                            users[parts[0]] = {"password": parts[1], "role": parts[2]}
        except Exception as e:
            print(f"Error al leer usuarios: {e}")
        return users
    
    def _write_users(self, users):
        try:
            with open(self.users_file, "w") as f:
                for username, data in users.items():
                    f.write(f"{username}|{data['password']}|{data['role']}\n")
            return True
        except:
            return False
    
    def _read_banned(self):
        banned = {}
        now = datetime.now()
        need_update = False
        
        try:
            with open(self.banned_file, "r") as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split("|")
                        if len(parts) >= 4:
                            username = parts[0]
                            until = datetime.fromisoformat(parts[1])
                            reason = parts[2]
                            by = parts[3]
                            
                            if until > now:  # Solo bans activos
                                banned[username] = {"until": until, "reason": reason, "by": by}
                            else:
                                need_update = True  # Hay bans expirados
        except Exception as e:
            print(f"Error leyendo bans: {e}")
        
        # Limpiar expirados si es necesario
        if need_update:
            self._write_banned(banned)
            
        return banned
    
    def _write_banned(self, banned):
        try:
            with open(self.banned_file, "w") as f:
                for username, data in banned.items():
                    f.write(f"{username}|{data['until'].isoformat()}|{data['reason']}|{data['by']}\n")
            return True
        except:
            return False
    
    def add_user(self, username, password, role="user"):
        users = self._read_users()
        
        if username in users:
            return False, "El usuario ya existe"
        
        users[username] = {"password": password, "role": role}
        if self._write_users(users):
            return True, "Usuario creado correctamente"
        else:
            return False, "Error al crear el usuario"
    
    def authenticate(self, username, password):
        users = self._read_users()
        
        if username not in users:
            return False, "El usuario no existe"
        
        # Verificar si está baneado
        banned = self._read_banned()
        if username in banned:
            ban_info = banned[username]
            return False, f"Usuario bloqueado hasta {ban_info['until'].strftime('%Y-%m-%d %H:%M:%S')}. Razón: {ban_info['reason']}"
        
        # Verificar contraseña
        if users[username]["password"] == password:
            return True, users[username]["role"]
        else:
            return False, "Contraseña incorrecta"
    
    def user_exists(self, username):
        return username in self._read_users()
    
    def is_admin(self, username):
        users = self._read_users()
        return username in users and users[username]["role"] == "admin"
    
    def ban_user(self, username, duration_minutes, reason, banned_by):
        users = self._read_users()
        
        if username not in users:
            return False, "El usuario no existe"
        
        if self.is_admin(username):
            return False, "No se puede bloquear a un administrador"
        
        banned = self._read_banned()
        banned_until = datetime.now() + timedelta(minutes=int(duration_minutes))
        
        banned[username] = {
            "until": banned_until,
            "reason": reason,
            "by": banned_by
        }
        
        if self._write_banned(banned):
            return True, f"Usuario {username} bloqueado por {duration_minutes} minutos"
        else:
            return False, "Error al bloquear al usuario"
    
    def unban_user(self, username):
        banned = self._read_banned()
        
        if username not in banned:
            return False, f"El usuario {username} no está bloqueado"
        
        del banned[username]
        
        if self._write_banned(banned):
            return True, f"Usuario {username} desbloqueado"
        else:
            return False, "Error al desbloquear al usuario"
    
    def get_all_users(self):
        users = self._read_users()
        return [(username, data["role"]) for username, data in users.items()]
    
    def get_banned_users(self):
        banned = self._read_banned()
        return [(username, data["until"], data["reason"], data["by"]) for username, data in banned.items()]
    
    def delete_user(self, username):
        users = self._read_users()
        
        if username not in users:
            return False
        
        if username == "admin" or (users[username]["role"] == "admin" and 
                                  sum(1 for u, d in users.items() if d["role"] == "admin") <= 1):
            return False
        
        # Eliminar usuario
        del users[username]
        
        # Eliminar cualquier baneo
        banned = self._read_banned()
        if username in banned:
            del banned[username]
            self._write_banned(banned)
        
        return self._write_users(users)
    
    def update_ban_reason(self, username, new_reason):
        """Actualiza la razón del baneo de un usuario sin cambiar otros parámetros"""
        banned = self._read_banned()
        
        if username not in banned:
            return False, "El usuario no está bloqueado"
        
        # Mantener los demás valores pero actualizando la razón
        banned[username]["reason"] = new_reason
        
        if self._write_banned(banned):
            return True, f"Razón de bloqueo actualizada para {username}"
        else:
            return False, "Error al actualizar la razón de bloqueo"
    
    def is_banned(self, username):
        """Verifica si un usuario está baneado"""
        banned = self._read_banned()
        return username in banned