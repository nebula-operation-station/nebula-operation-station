# Netzwerk

IP-Adressverwaltung (IPAM), Netzwerkerkennung (Discovery), die
Verkehrskarte und das Registrieren von Netzwerkgeräten (Cisco-CBS-Switches,
Palo-Alto-PAN-OS-Firewalls). Referenz: Admin-Handbuch
[9.7 bis 9.9](../../admin/guide.md#97-network-ipam) und
[ADR 0010](../../adr/0010-network-devices.md) für Netzwerkgeräte.

Nebula verwaltet nie DHCP oder DNS, und es ändert in diesem Release nichts
an Switches oder Firewalls.

<a id="add-a-network-to-ipam"></a>

## Ein Netzwerk im IPAM anlegen

**Ziel:** Nebula kennt ein Subnetz, sein VLAN, das Gateway und die
Adresspools.

**Schritte:**

1. *Network* (`/network`) → **Add network** (Netzwerk hinzufügen).
2. Geben Sie das Präfix (zum Beispiel `192.168.10.0/24`), VLAN, Gateway und
   Pools wie `servers 192.168.10.10-192.168.10.49` ein.
3. **Save network** (Netzwerk speichern).

**Erwartetes Ergebnis:** Die Netzwerkseite (`/network/n/<id>`) zeigt bei
Netzwerken bis /22 jede Adresse als Raster; größere Netzwerke und IPv6
listen nur belegte Adressen. Jede Adresse hat einen Status: ASSIGNED (ein
Asset oder der Endpunkt eines verwalteten Hosts), RESERVED, EXCLUDED,
DISCOVERED (von der Discovery gesehen, von niemandem belegt) oder CONFLICT
(zwei Ansprüche oder eine abweichende MAC).

<a id="find-a-free-ip-address"></a>

## Eine freie IP-Adresse finden

**Ziel:** eine Adresse für ein neues Gerät auswählen.

**Schritte:** Öffnen Sie die Netzwerkseite (`/network/n/<id>`). Sie schlägt
freie Adressen des ganzen Netzwerks oder eines Pools vor, die die Discovery
seit 30 Tagen nicht gesehen hat.

**Erwartetes Ergebnis:** eine Liste von Vorschlägen. Behandeln Sie sie als
Vorschläge, nicht als Garantie: Ein ausgeschaltetes Gerät wird nicht
gesehen.

<a id="record-a-device-asset-in-ipam"></a>

## Ein Gerät (Asset) im IPAM erfassen

**Ziel:** NAS, Drucker, Switches und andere Geräte im IPAM führen, egal ob
Nebula sie verwaltet oder nicht.

**Schritte:** *Network* → **Add asset** (Asset hinzufügen), Name, Art,
Adressen und MAC eingeben, **Save asset** (Asset speichern). Um aus einem
Asset einen verwalteten Host zu machen, öffnen Sie es (`/network/a/<id>`) →
**Add to managed hosts** (zu verwalteten Hosts hinzufügen): Das
Inventarformular öffnet sich mit seinen Werten, und der neue Host wird mit
dem Asset verknüpft. Melden Sie ihn dann wie unter [Hosts](hosts.md)
beschrieben an.

**Erwartetes Ergebnis:** Die Adressen des Assets erscheinen als ASSIGNED.

<a id="scan-a-network-with-discovery"></a>

## Ein Netzwerk mit der Discovery scannen

**Ziel:** Geräte in einem angelegten Netzwerk finden.

**Voraussetzungen:** Das Netzwerk existiert im IPAM; `nmap` ist auf der
Nebula-Maschine installiert (`sudo apt install nmap`).

**Schritte:**

1. *Network → Discovery* (`/network/discovery`).
2. Wählen Sie Ziele innerhalb eines bekannten Netzwerks (höchstens ein /16
   bei IPv4, /112 bei IPv6) und eine Scan-Art: Host-Erkennung, ausgewählte
   Ports, Diensterkennung (Top-100-Ports mit Versionen), alle TCP-Ports oder
   ein eigener Scan aus festen Optionen. Freie Nmap-Argumente gibt es nicht.
3. **Queue scan** (Scan einreihen): jetzt, einmalig oder alle N Stunden
   (mindestens eine). Es gibt keinen Standardzeitplan.
4. Öffnen Sie den Scan (`/network/discovery/<id>`), wenn er fertig ist.
   Jeder Host ist NEW, EXISTING (gleiche MAC wie ein Asset), POSSIBLE MATCH
   (gleiche Adresse, keine MAC zum Vergleichen, typisch über VPNs) oder
   CONFLICT.
5. Wählen Sie Hosts aus und **Import selected** (Auswahl importieren). Neue
   Hosts werden zu Assets mit der Art unknown; setzen Sie die Art danach.

**Erwartetes Ergebnis:** Importierte Geräte erscheinen als Assets; jeder
gesehene Host fließt außerdem in den Adressstatus ein.

**Häufige Fehler:**

- „Discovery shows as not installed“: `discovery_dir` fehlt oder ist falsch
  in `server.json`, oder die Spool-Verzeichnisse fehlen. Führen Sie
  `install.sh` erneut aus.
- `nmap is not installed (install the nmap package on the Nebula machine)`:
  `sudo apt install nmap`.
- Ergebnisse kommen nie an: Prüfen Sie
  `systemctl status nebula-discovery.path` und die Rechte der
  Spool-Verzeichnisse (Admin-Handbuch
  [15](../../admin/guide.md#15-troubleshooting)).
- Konflikte werden nie importiert. Namen und Banner kommen aus dem Netzwerk
  und können falsch sein.

<a id="see-who-talks-to-whom-on-the-traffic-map"></a>

## Auf der Verkehrskarte sehen, wer mit wem spricht

**Ziel:** ein Graph der Verbindungen zwischen verwalteten Hosts, Assets und
Netzwerken.

**Voraussetzungen:** eine Lese-Lease, die die eingebaute Leseaktion
`net.facts` enthält (siehe
[Nur-Lese-Prüfungen nach Zeitplan ausführen](patching-and-services.md#run-read-only-checks-on-a-schedule-read-lease)).

**Schritte:**

1. *Operations → Read leases → New read lease* (`/leases/new`), `net.facts`
   einschließen, 7 oder 30 Tage, freigeben.
2. Öffnen Sie *Traffic map* (Verkehrskarte) in der Seitenleiste
   (`/traffic`). Wählen Sie das Zeitfenster (1 h, 24 h, 7 d oder 21 d).
3. Klicken Sie auf einen Knoten, um seine wichtigsten Verbindungen zu sehen.
   Der Reiter *Connections* eines Hosts (`/hosts/<id>/connections`) oder
   Assets (`/network/a/<id>/connections`) listet die Verbindungen einzeln
   auf.

**Erwartetes Ergebnis:** Kanten mit Byte-Zählern erscheinen nach den ersten
Läufen von `net.facts`.

**Hinweise:** Byte-Zähler aus Socket-Momentaufnahmen sind Untergrenzen.
Prozessnamen werden nie erfasst (`net.facts` führt `ss` ohne `-p` aus,
daher ist keine sudo-Regel nötig). Verbindungen zu Gegenstellen außerhalb
des Inventars werden als nicht zugeordnet gezählt, aber nicht gezeichnet.
Die Aufbewahrung beträgt standardmäßig 21 Tage
(`"traffic": {"retention_days": N}` in `server.json`, 1 bis 21).
Netzwerkkarten von Proxmox-Gästen kommen über den PVE-Collector;
Netzwerksensoren und DNS-Quellen sind **Geplant** (ADR 0009).

<a id="what-works-for-network-devices-today"></a>

## Was heute für Netzwerkgeräte funktioniert

| Funktion | Status |
| --- | --- |
| CBS-Switch oder PAN-OS-Firewall registrieren, SSH-Hostkey oder TLS-Zertifikat pinnen, Lese-Zugangsdaten im Vault speichern | Verfügbar: `nebula netdev` |
| Zugangsdaten rotieren, neu pinnen, sperren, entsperren, entfernen, auflisten | Verfügbar: `nebula netdev` |
| Geräteseiten (`/netdev`, `/netdev/<id>`) | Verfügbar; sie zeigen nur gespeicherte Gerätedaten |
| Gerätedaten lesen (Version, VLANs, Interfaces, MAC-Tabelle, LLDP, PAN-OS-Regeln) | **Geplant** (ADR 0010, Tickets ND-13/ND-14): Der Executor antwortet "device reads are not implemented yet (ND-14)" |
| SSH-Public-Key-Login für CBS (`nos-read` mit einem Schlüssel, den der Executor hält) | **Geplant** (ADR 0010 D2, bevorzugte Methode); heute ist die CBS-Lese-Zugangsinformation ein Passwort |
| Jede Änderung an einem Gerät (VLANs, Ports, Regeln) | **Geplant** für Phase 2a, erst nachdem Phase 1 gelaufen ist (ADR 0010 Q3); alles auf dem eigenen Pfad von NOS bleibt abgelehnt |
| Cisco CBS220 | Nicht unterstützt (keine SSH-CLI); führen Sie es als IPAM-Asset |

Sie können Geräte schon jetzt registrieren: Pins und Zugangsdaten bleiben
erhalten und werden verwendet, sobald das Lesen verfügbar ist.

<a id="create-the-nos-read-account-on-a-cisco-cbs-switch"></a>

## Das Konto `nos-read` auf einem Cisco-CBS-Switch anlegen

**Ziel:** ein eigenes lokales Konto mit minimalen Rechten für Nebula auf
einem CBS350 (oder CBS250 mit SSH-CLI).

**Voraussetzungen:** Admin-Zugang zur Switch-CLI; SSH-Server auf dem Switch
aktiviert; die Management-Adresse des Switches ist privat und von der
Nebula-Maschine erreichbar.

Die folgenden Befehle sind **Cisco-Syntax auf dem Switch**, keine
Nebula-Befehle. ADR 0010 markiert einige dieser Herstellerdetails als
*verify* (zu prüfen; der Labortest ND-03 ist noch offen). Prüfen Sie sie
anhand des CLI-Handbuchs Ihrer Firmware.

**Schritte (Passwort-Login, das, was Nebula heute speichert):**

1. Legen Sie einen eigenen lokalen Benutzer `nos-read` mit der niedrigsten
   Berechtigungsstufe an, die noch `show running-config` ausführen kann (CBS
   kennt die Stufen 1, 7 und 15; Phase 1 verwendet eine Stufe **unter 15**).
   Verwenden Sie ein langes Zufallspasswort.
2. Stellen Sie sicher, dass der Switch das SSH-Passwort selbst verwendet und
   innerhalb der Sitzung nicht erneut fragt: Aktivieren Sie die
   SSH-Passwortauthentifizierung (`ip ssh password-auth`). Siehe die
   Auto-Login-Fallstricke weiter unten.
3. Notieren Sie den Fingerprint des SSH-Hostkeys von der Switch-Konsole
   (`show crypto key mypubkey rsa` oder das Gegenstück für Ihre Firmware),
   um ihn beim Registrieren des Switches zu vergleichen.

**SSH-Public-Key-Login (geplant, von ADR 0010 D2 bevorzugt):** Der
Schlüssel des Benutzers wird unter `crypto key pubkey-chain ssh`
eingetragen, eine **`key-string row`** pro Zeile des Base64-Schlüsselinhalts:

```
configure terminal
ip ssh pubkey-auth auto-login
crypto key pubkey-chain ssh
 user-key nos-read rsa
  key-string row AAAAB3NzaC1yc2EAAAADAQABAAABgQC...
  key-string row ...rest of the base64 body...
  key-string row
 exit
exit
```

Fügen Sie nur den Base64-Inhalt ein (kein Präfix `ssh-rsa`, kein
Kommentar), aufgeteilt in Zeilen, die der Switch akzeptiert, und schließen
Sie mit einer leeren `key-string row` ab. Nebula hat noch keinen Befehl,
der einen Geräteschlüssel ausgibt; dieser Block steht hier, damit Sie
wissen, wie die Switch-Seite aussehen wird.

**Erwartetes Ergebnis:** Ein SSH-Login als `nos-read` von der Adresse der
Nebula-Maschine landet direkt am Switch-Prompt (`switch01>` oder
`switch01#`), ohne zweite Abfrage `User Name:`.

<a id="avoid-cbs-auto-login-and-prompt-pitfalls"></a>

## Fallstricke bei CBS-Auto-Login und Prompt vermeiden

**Ziel:** Die Switch-Sitzung sieht genau so aus, wie der Sitzungstreiber
von Nebula es erwartet, damit Lesevorgänge nicht abbrechen.

Der CBS-Treiber von Nebula öffnet eine interaktive SSH-Sitzung, wartet auf
einen erkannten Prompt, sendet einen erlaubten Befehl und liest bis zum
nächsten Prompt. Er **beantwortet nie** eine Frage. Jeder der folgenden
Punkte führt dazu, dass er die Sitzung als Fehler abbricht:

- **Ein zweiter Login innerhalb der Sitzung.** Viele CBS-Konfigurationen
  akzeptieren den SSH-Login und zeigen dann ihre eigene Abfrage
  `User Name:` / `Password:`. Der Treiber behandelt Prompts mit
  `user name`, `username`, `password` und `login` als unerwartet und hält
  an. Abhilfe: `ip ssh password-auth` für Passwort-Logins oder
  `ip ssh pubkey-auth auto-login` für Schlüssel-Logins, damit die
  SSH-Authentifizierung der einzige Login ist.
- **`auto-login` ohne passenden Schlüssel.** Beim Public-Key-Login
  überspringt `auto-login` die zusätzliche Abfrage nur, wenn der Schlüssel
  in `key-string row` passt. Eine falsche oder abgeschnittene Zeile lässt
  den Switch auf die Abfrage `User Name:` zurückfallen, und der Treiber
  bricht ab.
- **Ein ungewöhnlicher Hostname.** Der Prompt muss ein Hostname aus bis zu
  58 Buchstaben, Ziffern, `.`, `_` oder `-` sein, der mit einem Buchstaben
  oder einer Ziffer beginnt, gefolgt von `>` oder `#`. Leerzeichen oder
  andere Zeichen im Hostnamen machen den Prompt unerkennbar. Prompts im
  Konfigurationsmodus (`switch01(config)#`) werden nie akzeptiert.
- **Interaktive Banner.** Ein Login-Banner oder MOTD, dessen Text
  `Press any key`, `(y/n)` oder `[confirm]` enthält oder dessen letzte
  Zeile auf `:` oder `?` endet, sieht aus wie ein Prompt, der auf Eingabe
  wartet. Halten Sie Banner als schlichten Text. Ein geändertes Banner gilt
  ebenfalls als Fehler.
- **Seitenweise Ausgabe (Paging).** Der Treiber schaltet das Paging mit
  `terminal datadump` ab; ein Prompt `--More--` bricht den Lesevorgang ab.
- **Schlüsseltypen.** Nebula akzeptiert RSA nur als `rsa-sha2-512` mit einer
  Mindestschlüssellänge (Spec 08). Ein Switch, der nur `ssh-rsa` (SHA-1)
  oder einen kleinen RSA-Schlüssel anbietet, wird **nicht unterstützt**; es
  gibt keine Algorithmus-Ausnahme (ADR 0010 Q1b).
- **Neu erzeugter Hostkey.** Nach `crypto key generate rsa` auf dem Switch
  passt der Pin nicht mehr, und Nebula sperrt das Gerät. Vergleichen Sie den
  neuen Fingerprint auf der Konsole und führen Sie dann
  `nebula netdev repin <device-id>` aus.

<a id="create-the-nos-read-administrator-on-a-pan-os-firewall"></a>

## Den Administrator `nos-read` auf einer PAN-OS-Firewall anlegen

**Ziel:** ein API-Schlüssel für einen Administrator mit reinen Leserechten,
ohne Web-Oberfläche und ohne CLI.

**Voraussetzungen:** Admin-Zugang zur Web-Oberfläche der Firewall; die
Management-Schnittstelle ist nur über eine interne Adresse erreichbar.

Die folgenden Schritte erfolgen **auf der Firewall**. ADR 0010 markiert die
genauen Rollenoptionen als *verify* (zu prüfen); prüfen Sie sie anhand des
PAN-OS Administrator's Guide Ihres Releases.

**Schritte:**

1. *Device → Admin Roles → Add*: ein eigenes Admin-Role-Profil, zum
   Beispiel `nos-read-role`. Deaktivieren Sie **Web UI** und **Command
   Line**. Erlauben Sie unter **XML API** nur die Leseoperationen, die
   Nebula braucht (Konfiguration lesen, operative Abfragen); deaktivieren
   Sie Commit, Import und Export. Wenn Ihr Release den Konfigurationszugriff
   über die XML API nicht auf Lesen beschränken kann, verwenden Sie
   stattdessen die dynamische Rolle *Superuser (read-only)* und
   deaktivieren Web-Oberfläche und CLI über ein Authentifizierungsprofil.
2. *Device → Administrators → Add*: Benutzer `nos-read` mit diesem
   Rollenprofil und einem langen Zufallspasswort.
3. Commit.
4. Erzeugen Sie den API-Schlüssel einmalig von **Ihrem eigenen
   Arbeitsplatzrechner** aus (nicht von der Nebula-Maschine) mit der
   XML-API-Anfrage `type=keygen`; senden Sie das Passwort im POST-Body,
   nie in der URL. Zum Beispiel:

   ```
   curl --cacert fw-mgmt-ca.pem -X POST 'https://<firewall-mgmt-ip>/api/' \
     -d type=keygen -d user=nos-read --data-urlencode password@-
   ```

   Tippen Sie das Passwort ein, drücken Sie Strg-D (Ctrl-D) und kopieren Sie
   den Schlüssel aus dem Element `<key>` der Antwort.
5. Optional: Legen Sie auf der Firewall eine Lebensdauer für den
   API-Schlüssel fest; das eigene Ablaufdatum von Nebula gilt zusätzlich.

**Erwartetes Ergebnis:** ein API-Schlüssel für `nos-read`. Nebula speichert
nie das Kontopasswort, nur den Schlüssel.

<a id="register-a-network-device-with-nebula"></a>

## Ein Netzwerkgerät bei Nebula registrieren

**Ziel:** Der Executor kennt das Gerät, gepinnt auf seinen SSH-Hostkey
(CBS) oder sein TLS-Zertifikat (PAN-OS), mit der Lese-Zugangsinformation in
seinem Vault.

**Voraussetzungen:** das Konto `nos-read` (Abschnitte oben); Executor
entsperrt (`nebula unlock`); ein Admin-Login mit Terminal auf der
Nebula-Maschine.

**Schritte:**

1. Sehen Sie sich zuerst den Fingerprint an (es werden keine Zugangsdaten
   gesendet):

   ```
   nebula netdev probe --family cbs --endpoint 192.168.1.2
   nebula netdev probe --family panos --endpoint 192.168.1.1
   ```

   `--port N` überschreibt den Standard (22 für `cbs`, 443 für `panos`).
2. Registrieren Sie es:

   ```
   nebula netdev add sw-core --family cbs --endpoint 192.168.1.2 \
     --label "Core switch" --username nos-read
   ```

   Vergleichen Sie den angezeigten Fingerprint mit der Gerätekonsole,
   tippen Sie `yes` und geben Sie dann an der Eingabeaufforderung die
   Lese-Zugangsinformation ein (CBS: das Passwort; PAN-OS: den
   API-Schlüssel). Sie wird nie als Argument oder aus der Umgebung
   angenommen. `--no-credential` registriert nur; setzen Sie die
   Zugangsinformation später mit `nebula netdev credential set sw-core`.
3. Prüfen: `nebula netdev list` (nur Metadaten, nie Secrets) und die
   Geräteseite `/netdev/sw-core`.

**Erwartetes Ergebnis:** Das Gerät wird mit seinem Pin aufgeführt.

**Häufige Fehler:**

- Der Endpunkt wird abgelehnt: Er muss eine private Adresse sein (oder ein
  Name, der bei der Registrierung zu einer solchen aufgelöst wird).
  Öffentliche, Loopback-, Link-Local-, Multicast- und unspezifizierte
  Adressen werden bei der Registrierung und bei jedem Verbindungsaufbau
  abgelehnt.
- `stdin is not a terminal`: Das `yes` muss an einem Terminal eingetippt
  werden; ein per Pipe übergebenes `yes` wird abgelehnt. Für die
  skriptgesteuerte Eingabe von Zugangsdaten verwenden Sie `--secret-fd N`
  (Deskriptor 3 oder höher), zum Beispiel
  `nebula netdev credential rotate sw-core --secret-fd 3 3< keyfile`.
- Der Vault ist gesperrt: zuerst `nebula unlock`.

<a id="rotate-block-or-remove-a-network-device"></a>

## Ein Netzwerkgerät rotieren, sperren oder entfernen

**Schritte:**

```
nebula netdev credential rotate fw-01          # asks for the new password or API key
nebula netdev block fw-01 --reason "maintenance"
nebula netdev unblock fw-01
nebula netdev repin fw-01                      # after a host key or certificate change
nebula netdev remove fw-01
```

`unblock`, `repin` und `remove` verlangen ein eingetipptes `yes` an einem
Terminal.

**Erwartetes Ergebnis:** `nebula netdev list` zeigt den neuen Zustand. Löschen
Sie nach einer Rotation des PAN-OS-Schlüssels den alten API-Schlüssel auf
der Firewall (oder lassen Sie seine Lebensdauer ablaufen).
