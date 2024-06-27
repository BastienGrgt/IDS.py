#!/usr/bin/env python3

import platform
import time
from datetime import datetime
import subprocess
import os
import filecmp
from pathlib import Path

# Configuration des chemins et des intervalles de vérification
home_directory = "/home"
root_directory = "/root"
backup_suffix = ".bak"
ssh_log_path = "/var/log/auth.log"
check_interval = 10
blacklisted_ips = ["192.168.1.100", "10.0.0.2", "172.20.10.2", "192.168.19.1"]  # Ajoutez ici les adresses IP à blacklister

# Dictionnaires pour stocker l'état des détections
user_states = {}
detected_connections = {}
previous_group_members = {}
detected_lines = set()

def detect_os():
    """Détecte le système d'exploitation en cours d'utilisation."""
    os_info = platform.system() + " " + platform.release()
    return os_info

def get_current_users():
    """Lit le fichier /etc/passwd et extrait les noms d'utilisateur."""
    with open('/etc/passwd', 'r') as file:
        users = {line.split(':')[0]: 'système' if '/usr' in line else 'normal' for line in file.readlines()}
    return users

def get_current_groups():
    """Lit le fichier /etc/group et extrait les informations des groupes."""
    with open('/etc/group', 'r') as file:
        groups = {}
        for line in file:
            parts = line.strip().split(':')
            group_name = parts[0]
            members = parts[-1].split(',')
            if members == ['']:
                members = []  # Si la liste des membres est vide
            groups[group_name] = set(members)
        return groups

def get_shadow_file_contents():
    """Lit le contenu du fichier /etc/shadow."""
    with open('/etc/shadow', 'r') as file:
        return file.read()

def copy_initial_state(source_path, backup_path):
    """Copie le fichier source dans un emplacement de sauvegarde."""
    subprocess.run(['cp', source_path, backup_path])

def detect_password_change(previous_shadow_content, current_shadow_content):
    """Détecte les changements dans le fichier /etc/shadow."""
    previous_lines = previous_shadow_content.split('\n')
    current_lines = current_shadow_content.split('\n')

    previous_users = {line.split(':')[0] for line in previous_lines if line.strip()}
    current_users = {line.split(':')[0] for line in current_lines if line.strip()}

    changed_users = previous_users.intersection(current_users)
    for user in changed_users:
        previous_entry = [entry for entry in previous_lines if entry.startswith(user)]
        current_entry = [entry for entry in current_lines if entry.startswith(user)]
        if previous_entry and current_entry and previous_entry[0] != current_entry[0]:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Changement de mot de passe pour l'utilisateur: {user}\n")
            notify_password_change(user)

def detect_group_membership_change(previous_groups, current_groups, previous_group_members):
    """Détecte les changements dans les membres des groupes."""
    for group, current_members in current_groups.items():
        previous_members = previous_groups.get(group, set())
        new_members = current_members - previous_members
        if new_members:
            if group in previous_group_members:
                if new_members != previous_group_members[group]:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Nouveaux membres détectés dans le groupe '{group}': {new_members}\n")
                    previous_group_members[group] = new_members
                    notify_group_members(group, new_members)
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Nouveau groupe détecté: {group} (Membres: {', '.join(current_members)})\n")
                previous_group_members[group] = current_members

def detect_tty_logins(previous_tty_content):
    """Détecte les connexions tty récentes dans les journaux système."""
    command = "last"
    output = subprocess.check_output(command, shell=True, text=True).strip()
    if output:
        current_tty_content = output.split('\n')
        new_logins = set(current_tty_content) - set(previous_tty_content)
        if new_logins:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Nouvelles connexions tty détectées:")
            for entry in new_logins:
                print(entry)
            print()  # Saut de ligne
        return current_tty_content

def notify_password_change(user):
    """Envoyer une notification pour le changement de mot de passe."""
    pass

def notify_group_members(group, members):
    """Envoyer une notification pour les nouveaux membres du groupe."""
    pass

# Créer une copie du fichier authorized_keys pour un utilisateur spécifique
def create_backup(authorized_keys_path, backup_path):
    try:
        os.system(f"cp {authorized_keys_path} {backup_path}")
    except Exception as e:
        print(f"Erreur lors de la création de la copie de sauvegarde: {e}")

# Vérifier les modifications dans le fichier authorized_keys pour un utilisateur spécifique
def check_for_changes(authorized_keys_path, backup_path, user):
    if os.path.exists(authorized_keys_path):
        if os.path.exists(backup_path):
            if not filecmp.cmp(authorized_keys_path, backup_path):
                if not user_states[user]:
                    print(f"Nouvelle clé SSH détectée dans authorized_keys pour l'utilisateur {user}!")
                    user_states[user] = True
        else:
            print(f"Aucune copie de sauvegarde trouvée pour {user}. Création de la copie de sauvegarde...")
            create_backup(authorized_keys_path, backup_path)

# Vérifier les fichiers authorized_keys pour tous les utilisateurs
def check_all_users():
    users_directories = [Path(home_directory).glob('*'), Path(root_directory).glob('*')]

    for directories in users_directories:
        for user_dir in directories:
            ssh_dir = user_dir / ".ssh"
            authorized_keys_path = ssh_dir / "authorized_keys"
            backup_path = authorized_keys_path.with_suffix(authorized_keys_path.suffix + backup_suffix)

            user = user_dir.name

            if user not in user_states:
                user_states[user] = False

            check_for_changes(str(authorized_keys_path), str(backup_path), user)

# Vérifier si une adresse IP est blacklistée
def is_blacklisted(ip):
    return ip in blacklisted_ips

# Lire les nouvelles connexions SSH dans le journal
def read_ssh_connections():
    try:
        output = subprocess.check_output(["tail", "-n", "10", ssh_log_path]).decode("utf-8")
        lines = output.strip().split("\n")
        for line in lines:
            if "Accepted password for" in line:
                timestamp = line[:24]
                if timestamp not in detected_connections:
                    detected_connections[timestamp] = True
                    print("Connexion SSH détectée :", timestamp, line)
                ip_index = line.find("from") + 5
                ip = line[ip_index:].split()[0]
                print(f"Adresse IP détectée : {ip}")
                if is_blacklisted(ip):
                    print(f"Connexion SSH détectée depuis une adresse IP blacklistée : {ip}")
    except Exception as e:
        print(f"Erreur lors de la lecture du journal système : {e}")

# Fonction pour lire le journal système
def read_syslog():
    try:
        output = subprocess.check_output(['grep', 'Failed password', ssh_log_path]).decode('utf-8')
        lines = output.strip().split('\n')
        for line in lines:
            if line not in detected_lines:
                print("Tentative de brute force détectée :", line)
                detected_lines.add(line)
    except subprocess.CalledProcessError:
        print("Erreur lors de la lecture du journal système")

if __name__ == "__main__":
    os_info = detect_os()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Système d'exploitation détecté: {os_info}\n")

    # Initialisations
    previous_users = get_current_users()
    previous_groups = get_current_groups()
    previous_shadow_content = get_shadow_file_contents()
    previous_group_members = {group: members for group, members in previous_groups.items()}
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Utilisateurs actuellement sur le système:")
    for user, type_ in previous_users.items():
        print(f"{user} ({type_})")
    print()  # Saut de ligne
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Groupes actuellement sur le système:")
    for group, members in previous_groups.items():
        print(f"{group} (Membres: {', '.join(members)})")
    print()  # Saut de ligne

    # Copie initiale de /etc/shadow pour le suivi des changements
    copy_initial_state('/etc/shadow', '/tmp/shadow_backup')
    previous_tty_content = subprocess.check_output("last", shell=True, text=True).strip().split("\n")

    # Créer une copie de sauvegarde initiale des fichiers authorized_keys
    check_all_users()

    try:
        while True:
            # Vérification des changements dans /etc/shadow
            current_shadow_content = get_shadow_file_contents()
            if current_shadow_content != previous_shadow_content:
                detect_password_change(previous_shadow_content, current_shadow_content)
                previous_shadow_content = current_shadow_content

            # Vérification des changements dans les membres des groupes
            current_groups = get_current_groups()
            detect_group_membership_change(previous_groups, current_groups, previous_group_members)
            previous_groups = current_groups

            # Vérification des connexions TTY
            previous_tty_content = detect_tty_logins(previous_tty_content)

            # Vérification des fichiers authorized_keys
            check_all_users()

            # Lire les nouvelles connexions SSH dans le journal
            read_ssh_connections()

            # Lire les tentatives de brute force
            read_syslog()

            time.sleep(check_interval)
    except KeyboardInterrupt:
        print("^C")



