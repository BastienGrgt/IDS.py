Surveillance de Système et de Sécurité
Ce programme Python est conçu pour surveiller divers aspects de la sécurité et de l'activité système sur des systèmes Linux. Il fournit des mécanismes de détection pour divers événements critiques et peut être utilisé pour renforcer la sécurité et la surveillance des systèmes.

Compatibilité et Prérequis
Compatibilité
Le programme est compatible avec les systèmes d'exploitation Linux. Il a été testé et fonctionne sur les distributions suivantes :

Ubuntu 20.04 LTS

Services Requis
Pour le bon fonctionnement du programme, les services suivants doivent être activés et fonctionnels sur le système :

SSH: Pour détecter les connexions SSH et les tentatives de connexion.
syslog: Pour la lecture des journaux système.

Instructions
Configuration de l'environnement virtuel (venv)
Assurez-vous d'avoir Python 3 installé sur votre système.


Droits d'exécution


chmod +x ids.py

Commande d'exécution
./ids.py



Fonctionnalités de Détection
Le programme fournit plusieurs mécanismes de détection pour surveiller l'activité système et renforcer la sécurité. Voici les principales fonctionnalités de détection :

1. Changements de Mot de Passe
Explication :
Le programme détecte les changements de mots de passe pour les utilisateurs du système en surveillant le fichier /etc/shadow.

Test et Résultat :
Commande pour Tester :
sudo passwd nom_utilisateur


2. Nouveaux Membres de Groupe
Explication :
Le programme détecte l'ajout de nouveaux membres à des groupes du système en surveillant le fichier /etc/group.

Test et Résultat :
Commande pour Tester :
Ajoutez un nouveau membre à un groupe existant avec la commande suivante :
sudo usermod -aG nom_groupe nom_utilisateur


3. Nouvelles Connexions SSH
Explication :
Le programme surveille les journaux système pour détecter les nouvelles connexions SSH établies sur le système.

Test et Résultat :
Commande pour Tester :
Connectez-vous au système via SSH à partir d'un autre appareil avec la commande suivante :
ssh nom_utilisateur@adresse_ip


4. Tentatives de Brute Force SSH
Explication :
Le programme recherche les tentatives de connexion SSH échouées dans les journaux système, indiquant des attaques de force brute potentielles.

Test et Résultat :
Commande pour Tester :
Tentez de vous connecter au système via SSH en utilisant des identifiants incorrects :
ssh nom_utilisateur@adresse_ip


