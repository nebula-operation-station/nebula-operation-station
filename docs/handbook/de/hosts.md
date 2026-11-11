# Hosts

Verwaltete Hosts hinzufügen und Nebula einen gepinnten, eingeschränkten
SSH-Login auf ihnen geben. Referenz: Admin-Leitfaden
[7](../../admin/guide.md#7-adding-and-enrolling-hosts)
und [17.2](../../admin/guide.md#172-the-nebula-cli).

Die Aufnahme (Enrollment) eines Hosts hat vier Schritte: ins Inventar
aufnehmen, das Enrollment-Skript auf ihm ausführen, seinen Host-Schlüssel
pinnen, den Login testen.

<a id="add-a-host-to-the-inventory"></a>

## Einen Host zum Inventar hinzufügen

**Ziel:** Der Host erscheint mit seinen Endpunkten im Inventar.

**Voraussetzungen:** an der Weboberfläche angemeldet.

**Schritte:**

1. *Inventory* (`/inventory`, Inventar) → **Add host** (`/inventory/new`,
   Host hinzufügen).
2. Füllen Sie die ID (zum Beispiel `web-01`) aus, die Endpunkte in der
   Reihenfolge, in der Nebula sie versuchen soll, die Umgebung (DEV, QA oder
   PROD; wird von gestuften Rollouts genutzt), die Kritikalität, Tags und
   Gruppen.
3. Speichern.

Ein Endpunkt ist eine IP-Adresse oder ein DNS-Name, optional mit Port:
`192.168.0.21`, `web-01.lan:2222`, `[fd00::21]:22`. Tragen Sie mehrere
Endpunkte ein (zum Beispiel zuerst LAN, dann VPN); bei einem TCP-Fehler
weicht Nebula auf den nächsten aus.

**Erwartetes Ergebnis:** Der Host steht unter *Inventory*, noch ohne
gepinnten Schlüssel.

**Hinweis:** Die Kritikalität im Inventar-Formular dient nur der Anzeige.
Die Kritikalität, die bestimmt, wie stark eine Freigabe sein muss, wird auf
dem Executor gesetzt (siehe
[Die Kritikalität des Hosts setzen](#set-the-hosts-criticality-on-the-executor)).

<a id="import-many-hosts-from-a-csv-file"></a>

## Viele Hosts aus einer CSV-Datei importieren

**Ziel:** viele Hosts auf einmal hinzufügen.

**Voraussetzungen:** eine UTF-8-CSV-Datei mit Kopfzeile.

**Schritte:**

1. *Inventory → Import CSV* (`/inventory/import`, CSV importieren).
2. Laden Sie die Datei hoch und ordnen Sie ihre Spalten den Feldern `id`,
   `display_name`, `environment`, `criticality`, `tags` und `endpoint1` …
   `endpoint16` zu.
3. Prüfen Sie die Vorschau: Jede fehlerhafte Zeile wird mit ihren Problemen
   angezeigt und nicht importiert.
4. **Import selected rows** (ausgewählte Zeilen importieren).

**Grenzen:** höchstens 5 MiB, 10.000 Datenzeilen, 64 Spalten, 1 KiB pro Zelle
und 16 Endpunkte pro Host. Eine größere Datei wird abgelehnt, nie gekürzt.

**Erwartetes Ergebnis:** Die gültigen Zeilen erscheinen im Inventar. Nehmen
Sie die Hosts wie unten beschrieben auf.

<a id="run-the-enrollment-script-on-a-new-host"></a>

## Das Enrollment-Skript auf einem neuen Host ausführen

**Ziel:** Der Host hat einen eingeschränkten Benutzer `nebula` mit dem
öffentlichen Schlüssel des Executors und einer sudo-Regel.

**Voraussetzungen:**

- Auf dem Host läuft Debian 12, Ubuntu 22.04/24.04 oder Proxmox VE, mit
  OpenSSH, `sudo` und systemd.
- Sie kennen die Adressen, **von** denen sich die Nebula-Maschine verbindet
  (LAN-Adresse, VPN-Adresse, …).
- Der Executor läuft und ist entsperrt (die CLI fragt den Executor nach dem
  öffentlichen Schlüssel der Zugangsdaten und bettet ihn in das Skript ein).

**Schritte:**

1. Auf der Nebula-Maschine:

   ```
   nebula host enroll-script --from 192.168.0.10,100.64.0.10 > enroll.sh
   ```

   Optionen: `--user NAME` (Standard `nebula`), `--key REF` (Standard
   `nebula-default`), `--no-sudo` (keine sudo-Regel: Nur Read-only-Aktionen
   funktionieren).
2. **Lesen Sie das Skript.**
3. Kopieren Sie es auf den Host und führen Sie es dort als root aus, zum
   Beispiel `sudo sh enroll.sh`.

**Was es auf dem Host tut:** Es legt den Benutzer an, installiert den
Schlüssel mit
`from="…",no-agent-forwarding,no-port-forwarding,no-X11-forwarding`, legt
`/etc/sudoers.d/nebula` an (NOPASSWD, mit `visudo` geprüft; damit ist der
Benutzer faktisch root) sowie `/etc/tmpfiles.d/nebula.conf`. Nutzt sshd
`AllowUsers` oder `AllowGroups`, legt es `/etc/ssh/sshd_config.d/10-nebula.conf`
an und lädt sshd nach `sshd -t` neu. Details: Admin-Leitfaden
[7.1](../../admin/guide.md#71-the-enrollment-script).

**Erwartetes Ergebnis:** Das Skript endet ohne Fehler; `id nebula`
funktioniert auf dem Host.

**Häufige Fehler:**

- Das Skript meldet einen `Match`-Block, einen Eintrag
  `DenyUsers`/`DenyGroups` oder ein fehlendes `Include` für
  `sshd_config.d`: Fügen Sie die ausgegebene Zeile selbst hinzu.
- fail2ban sperrt die Nebula-Maschine später: Tragen Sie ihre Adressen (als
  IPs) auf dem Host in `ignoreip` ein.

**Kommt noch:** Ein Enrollment in einem Schritt, das Skript, Schlüssel-Pin
und Test zusammenfasst, ist geplant. Es ist nicht in diesem Release; nutzen
Sie die Schritte auf dieser Seite.

<a id="pin-host-keys-for-many-hosts-in-the-web-ui"></a>

## Host-Schlüssel für viele Hosts in der Weboberfläche pinnen

**Ziel:** Der Executor kennt den SSH-Host-Schlüssel jedes Hosts, damit eine
Maschine dazwischen erkannt wird.

**Voraussetzungen:** Das Enrollment-Skript lief auf den Hosts; eine offene
privilegierte Sitzung; Zugang zur Konsole jedes Hosts, um Fingerabdrücke zu
vergleichen.

**Schritte:**

1. Auf der Konsole jedes Hosts:
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
2. *Inventory → Enroll hosts* (`/inventory/enroll`, Hosts aufnehmen) listet
   die Hosts ohne gepinnten Schlüssel.
3. Wählen Sie Hosts aus, wählen Sie Endpunkt und SSH-Benutzer, dann **Read
   host keys** (Host-Schlüssel lesen). Der Executor verbindet sich und zeigt
   den erhaltenen Schlüssel (es werden keine Zugangsdaten gesendet).
4. Vergleichen Sie jeden Fingerabdruck mit der Ausgabe auf der Konsole, setzen
   Sie das Häkchen zur Bestätigung und wählen Sie **Enroll with security key**
   (mit Sicherheitsschlüssel aufnehmen).

**Erwartetes Ergebnis:** Die Tabelle zeigt jeden Host als gepinnt und ob der
Test-Login funktioniert hat (daran sehen Sie, ob das Enrollment-Skript lief).

**Hinweis:** So gepinnte Hosts zählen als HIGH, bis Sie ihre Kritikalität auf
dem Executor setzen (nächste Abschnitte).

<a id="pin-a-host-key-on-the-command-line"></a>

## Einen Host-Schlüssel auf der Kommandozeile pinnen

**Ziel:** einen Host von der Nebula-Maschine aus pinnen und optional im
selben Schritt seine Kritikalität setzen.

**Voraussetzungen:** Das Enrollment-Skript lief; Sie haben den Fingerabdruck
auf der Konsole des Hosts verglichen.

**Schritte:**

```
nebula host probe 192.168.0.21                 # shows the key, sends no credential
nebula host pin --criticality MEDIUM web-01 192.168.0.21 100.64.0.21
```

Weitere Optionen von `host pin`: `--user U` (Standard `nebula`), `--key REF`
(Standard `nebula-default`), `--known-hosts FILE` (den Schlüssel aus einer
vertrauenswürdigen `known_hosts`-Datei übernehmen, statt zu proben).

**Erwartetes Ergebnis:** `nebula host keys` listet den Pin;
`nebula host list` zeigt den Kritikalitätseintrag.

<a id="test-the-login-to-a-host"></a>

## Den Login auf einem Host testen

**Ziel:** bestätigen, dass sich Nebula mit seinem Schlüssel anmelden kann.

**Voraussetzungen:** Host gepinnt; Executor entsperrt.

**Schritte:**

```
nebula host test web-01 192.168.0.21
```

**Erwartetes Ergebnis:** Der Login gelingt. Führen Sie danach *Check
updates* auf dem Host aus (siehe [Patchen und Dienste](patching-and-services.md)),
um seinen Update-Status zu füllen.

**Häufige Fehler:** Die Authentifizierung schlägt fehl, wenn das
Enrollment-Skript nicht lief, `--from` die Adresse nicht enthielt, von der
sich Nebula verbindet, oder `AllowUsers`/`AllowGroups` von sshd den Benutzer
noch ausschließt. Ein Ergebnis `network_unreachable` heißt, dass kein
Endpunkt geantwortet hat; prüfen Sie Routing und Host-Firewall.

<a id="set-the-hosts-criticality-on-the-executor"></a>

## Die Kritikalität des Hosts auf dem Executor setzen

**Ziel:** Der Executor wendet für diesen Host das richtige Mindestrisiko an.

**Voraussetzungen:** Host gepinnt.

**Schritte:**

```
nebula host criticality web-01 MEDIUM
nebula host list
```

Die Stufe ist `LOW`, `MEDIUM`, `HIGH` oder `CRITICAL`. Sie können sie auch an
einen bestimmten Schlüssel binden:
`nebula host criticality HOST SHA256:FINGERPRINT LEVEL`.

**Erwartetes Ergebnis:** `nebula host list` zeigt den Eintrag.

**Warum das wichtig ist:** Der Executor nimmt das Höchste aus dem Risiko des
Skripts, den Befunden des Safety Scanners und der Kritikalität des Hosts.
Ein Host ohne Eintrag zählt als **HIGH**. Dann braucht jede Aktion auf ihm
einen Sicherheitsschlüssel mit Benutzerverifikation, und geplante Prüfungen
(die nur LOW akzeptieren) werden abgelehnt. Siehe Admin-Leitfaden
[17.3](../../admin/guide.md#173-risk-classes).

<a id="re-pin-a-host-whose-key-changed"></a>

## Einen Host neu pinnen, dessen Schlüssel sich geändert hat

**Ziel:** einen neu installierten Host wieder in Betrieb nehmen, ohne den
Schlüssel eines Angreifers zu akzeptieren.

**Voraussetzungen:** Konsolenzugang zum Host; Ihr Sicherheitsschlüssel.

**Schritte:**

1. Auf der Konsole des Hosts:
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
2. Dashboard → **Re-pin…** (neu pinnen) neben dem blockierten Host. Es zeigt
   den gepinnten und den vorgelegten Schlüssel.
3. Vergleichen, den Vergleich bestätigen und **Re-pin with security key**
   (mit Sicherheitsschlüssel neu pinnen; mit Benutzerverifikation).

Stattdessen auf der Kommandozeile: `nebula host unpin web-01`, dann erneut
`nebula host pin …`.

**Erwartetes Ergebnis:** Der Host ist nicht mehr blockiert; seine
Kritikalität bleibt erhalten (beim Weg über die Weboberfläche).

Pinnen Sie **nie** neu, ohne auf der Konsole zu vergleichen: Ein geänderter
Schlüssel ist genau das, wonach eine Maschine dazwischen aussieht.

<a id="enroll-a-host-reachable-over-a-vpn-netbird-wireguard-tailscale"></a>

## Einen über VPN erreichbaren Host aufnehmen (NetBird, WireGuard, Tailscale)

**Ziel:** einen Host verwalten, den Nebula nur oder auch über ein VPN
erreicht.

**Voraussetzungen:** Die Nebula-Maschine ist selbst Mitglied des VPN
(außerhalb von Nebula eingerichtet) und hat eine VPN-Adresse, zum Beispiel
`100.64.0.10`.

**Schritte:**

1. Erzeugen Sie das Skript mit **jeder** Quelladresse, die die
   Nebula-Maschine nutzen kann, LAN und VPN:
   `nebula host enroll-script --from 192.168.0.10,100.64.0.10 > enroll.sh`.
2. Führen Sie es auf dem Host als root aus.
3. Geben Sie dem Host im Inventar seine Endpunkte in der bevorzugten
   Reihenfolge, zum Beispiel `192.168.0.21`, dann `100.64.0.21`.
4. Pinnen Sie mit allen Endpunkten:
   `nebula host pin --criticality MEDIUM web-01 192.168.0.21 100.64.0.21`.
5. Testen Sie jeden Endpunkt: `nebula host test web-01 100.64.0.21`.

**Erwartetes Ergebnis:** Der Host funktioniert über beide Wege; Nebula weicht
auf den VPN-Endpunkt aus, wenn der LAN-Endpunkt nicht antwortet.

**Häufige Fehler:** Der Login über das VPN wird abgelehnt, weil die
VPN-Quelladresse in `--from` fehlte (die `from="…"`-Einschränkung des
Schlüssels und das sshd-Drop-in nutzen sie). Führen Sie das
Enrollment-Skript mit der vollständigen Liste erneut aus.

<a id="remove-a-host-from-nebula"></a>

## Einen Host aus Nebula entfernen

**Ziel:** Nebula hat keinen Zugang mehr zum Host.

**Schritte:**

1. Entfernen Sie auf dem Host die Schlüsselzeile des Benutzers `nebula` aus
   `~nebula/.ssh/authorized_keys` (oder den Benutzer: `userdel -r nebula`),
   `/etc/sudoers.d/nebula`, `/etc/tmpfiles.d/nebula.conf`,
   `/var/lib/nebula/jobs` und, falls das Enrollment sie angelegt hat,
   `/etc/ssh/sshd_config.d/10-nebula.conf` (danach sshd neu laden).
2. Auf der Nebula-Maschine:

   ```
   nebula host unpin web-01
   nebula host clear web-01
   ```

3. Löschen Sie den Host im Inventar (Host-Seite → **Delete host**, Host
   löschen).

**Erwartetes Ergebnis:** `nebula host keys` und `nebula host list` zeigen den
Host nicht mehr. Read Leases, die ihn abdeckten, laufen für ihn nicht mehr.
