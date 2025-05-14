# Tiny - HackMyVM (Hard)
 
![Tiny.png](Tiny.png)

## Übersicht

*   **VM:** Tiny
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Tiny)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 8. Dezember 2023
*   **Original-Writeup:** https://alientec1908.github.io/Tiny_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Tiny"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration einer WordPress-Seite (Port 80) und eines tinyproxy (Port 8888). Eine Subdomain `wish.tiny.hmv` wurde entdeckt, die eine SQL-Injection-Schwachstelle im `username`-Parameter eines Formulars aufwies. Mittels `sqlmap` wurden Passwort-Hashes der WordPress-Benutzer `admin` und `umeko` aus der `wordpressdb` extrahiert. Der Hash von `umeko` wurde geknackt (`fuckit!`). Als `umeko` wurde im WordPress-Backend über ein Shortcode-Plugin PHP-Code ausgeführt, um eine Reverse Shell als `www-data` zu erhalten. Als `www-data` wurde die Konfiguration von tinyproxy ausgelesen, die auf einen Upstream-Dienst auf `localhost:1111` hinwies. Eine Anfrage an diesen Upstream (umgeleitet durch den tinyproxy via `socat`) offenbarte Basic-Auth-Credentials (`root:Q2X4]5Vjs`) für einen Dienst auf `localhost:8000`, der einen privaten SSH-Schlüssel für den Benutzer `vic` auslieferte. Mit diesem Schlüssel gelang der SSH-Login als `vic`. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung einer `sudo`-Regel, die `vic` erlaubte, `/usr/bin/python3 /opt/car.py` mit beliebigen Argumenten als `root` auszuführen. Durch eine spezielle Argumentenkette wurde die `os.system`-Funktion aufgerufen, um eine Root-Shell zu starten.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nmap`
*   `nikto`
*   `dirb`
*   `gobuster`
*   `wpscan`
*   `wfuzz`
*   `sqlmap` (impliziert)
*   `john` (John the Ripper)
*   `searchsploit` (impliziert)
*   `python` (python3)
*   `msfconsole`
*   `meterpreter`
*   `nc` (netcat)
*   `head`
*   `sudo`
*   `ls`
*   `cd`
*   `find`
*   `getcap`
*   `cat`
*   `grep`
*   `tinyproxy` (Service)
*   `socat`
*   `curl`
*   `ssh`
*   `cp`
*   `chmod`
*   `id`
*   `bash`
*   `zsh` (lokal)
*   Standard Linux-Befehle (`export`, `stty`, `reset`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Tiny" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.118`). Eintrag von `tiny.hmv` in `/etc/hosts`.
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH), 80 (HTTP - Apache/WordPress 6.4.2), 8888 (HTTP Proxy - tinyproxy 1.11.1).
    *   `nikto`, `dirb`, `gobuster` auf Port 80 bestätigten WordPress und fanden Standardpfade.
    *   `wpscan` identifizierte die Benutzer `admin` und `umeko`. Ein Brute-Force auf `umeko` wurde abgebrochen.
    *   `wfuzz` zur VHost-Enumeration fand `wish.tiny.hmv`.

2.  **SQL Injection & Hash Cracking:**
    *   Auf `wish.tiny.hmv` wurde ein Formular gefunden. Eine POST-Anfrage mit einem Apostroph im `username`-Parameter (`username=admin'`) führte zu einem 500er Fehler, was auf SQLi hindeutete.
    *   Ausnutzung der SQLi (impliziert mit `sqlmap`) auf `wish.tiny.hmv` zum Auslesen der `wordpressdb`. Die Tabelle `wp_users` enthielt die phpass-Hashes für `admin` (`$P$Bwfek...`) und `umeko` (`$P$Bvgq8...`).
    *   `john` mit `rockyou.txt` knackte den Hash für `umeko`: Passwort `fuckit!`. Der `admin`-Hash wurde nicht geknackt.

3.  **Initial Access (WordPress RCE zu `www-data`):**
    *   Login in das WordPress-Backend (`/wp-admin/`) als `umeko:fuckit!`.
    *   Ausnutzung eines (nicht namentlich genannten) Shortcode-Plugins zum Ausführen von PHP-Code.
    *   Einfügen eines PHP-Reverse-Shell-Payloads (`[php] <?php ...reverse_shell_code... ?> [/php]`) in einen neuen Post/Seite.
    *   Nach dem Veröffentlichen und Aufrufen des Posts wurde eine Reverse Shell als `www-data` auf dem Listener des Angreifers (Port 4444) etabliert.

4.  **Privilege Escalation (von `www-data` zu `vic` via Proxy & SSH Key Leak):**
    *   `www-data` konnte `wp-config.php` lesen: DB-User `wordpressuser`, Passwort `6rt443RKhwTXjWDe`.
    *   `www-data` hatte keine `sudo`-Rechte. SUID/Capabilities waren Standard.
    *   Lesen von `/etc/tinyproxy/tinyproxy.conf` als `www-data` zeigte eine `Upstream http localhost:1111`-Direktive und `Allow 127.0.0.1`.
    *   `socat -v tcp-listen:1111 tcp:localhost:8000` wurde als `www-data` gestartet, um Anfragen an den Upstream-Dienst (Port 1111) an einen lokalen Dienst auf Port 8000 weiterzuleiten.
    *   Eine (implizit von einem anderen Prozess gesendete) Anfrage, die durch den tinyproxy (Port 8888) ging und an `localhost:1111` (socat) weitergeleitet wurde, zielte auf `http://127.0.0.1:8000/id_rsa` und enthielt Basic Auth Credentials `root:Q2X4]5Vjs` (Base64: `cm9vdDpRMlg0XQ0V2pz`).
    *   Der Dienst auf Port 8000 (Nginx) lieferte daraufhin einen privaten SSH-Schlüssel (vermutlich für `vic`).
    *   Erfolgreicher SSH-Login als `vic` mit dem extrahierten privaten Schlüssel.
    *   User-Flag `7d9b0f6638734dbb10545f446c04a42b` in `/home/vic/user.txt` gelesen.

5.  **Privilege Escalation (von `vic` zu `root` via `sudo python3`):**
    *   `sudo -l` als `vic` zeigte: `(ALL : ALL) NPASSWD: /usr/bin/python3 /opt/car.py*`.
    *   Ausnutzung dieser Regel durch Übergabe spezieller Argumente an Python3:
        `sudo /usr/bin/python3 /opt/car.py __init__.__globals__.random._os.system /bin/bash`
    *   Dies führte `os.system('/bin/bash')` als `root` aus und gewährte eine Root-Shell.
    *   Root-Flag `0785ded6dbb7e73959924ad06152eabc` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **SQL Injection:** Ermöglichte das Auslesen von WordPress-Benutzer-Hashes aus einer anderen Datenbank.
*   **WordPress RCE (unsicheres Shortcode Plugin):** Erlaubte die Ausführung von PHP-Code nach dem Admin-Login.
*   **Fehlkonfigurierter Proxy (tinyproxy) mit Upstream:** Enthüllte einen internen Dienst.
*   **Informationsleck durch internen Dienst:** Ein Dienst auf `localhost:8000` lieferte einen privaten SSH-Schlüssel nach Basic-Authentifizierung (Credentials ebenfalls geleakt/abgefangen).
*   **Unsichere `sudo`-Regel (Python-Interpreter mit Argumenten):** Erlaubte die Ausführung beliebiger Python-Befehle und somit die Eskalation zu Root durch Zugriff auf `os.system`.
*   **Passwort-Cracking (phpass):** Knacken von WordPress-Passwort-Hashes.

## Flags

*   **User Flag (`/home/vic/user.txt`):** `7d9b0f6638734dbb10545f446c04a42b`
*   **Root Flag (`/root/root.txt`):** `0785ded6dbb7e73959924ad06152eabc`

## Tags

`HackMyVM`, `Tiny`, `Hard`, `SQL Injection`, `WordPress RCE`, `tinyproxy`, `socat`, `SSH Key Leak`, `sudo Exploitation`, `Python`, `Privilege Escalation`, `Linux`, `Web`
