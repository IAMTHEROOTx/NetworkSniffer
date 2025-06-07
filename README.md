# Sniffer IP Multiplateforme en Python

Ce projet est un **sniffer réseau en Python** compatible Windows et Linux. Il permet de capturer et d’analyser les paquets IP bruts, en extrayant des informations clés comme l’adresse IP source, destination, TTL, version IP, etc.

## ⚙️ Fonctionnalités

- Détection automatique du système d’exploitation (Windows/Linux)
- Capture de paquets IP bruts via sockets bas-niveau
- Analyse de l’en-tête IP (IP Header)
- Affichage en temps réel des informations des paquets interceptés

## 🖥️ Compatibilité

- ✅ Windows
- ✅ Linux  
- ❌ macOS (non pris en charge)

## 🛠️ Installation

```bash
git clone https://github.com/votre-utilisateur/NetworkSniffer.git
cd NetworkSniffer
```
## Sous Linux

**Lancer le script avec les droits root :**

```bash
sudo python3 Sniffer.py
```
## Sous Windows

**Exécuter avec les droits administrateur dans un terminal :**

```bash
python sniffer.py
```
📄 Exemple de sortie
yaml
```bash
==== Nouveau paquet ====
Version IP: 4
IHL (Header Length): 20 bytes
TTL: 64
Protocol: 6
Source IP: 192.168.0.105
Destination IP: 172.217.22.14
========================
```

**⚠️ Avertissement
Ce script utilise des raw sockets et doit être lancé avec les droits administrateur/root.
Utiliser un sniffer réseau peut être interdit ou restreint selon votre environnement (entreprise, réseau public). Utilisez ce script uniquement à des fins éducatives et légales.**

📁 Fichiers
sniffer.py : Le script principal

Aucun module externe requis (utilise uniquement la bibliothèque standard de Python)

✍️ Auteur
GitHub : IAMTHEROOTx

Projet open-source, contributions bienvenues !
