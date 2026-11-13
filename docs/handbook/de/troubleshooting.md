# Fehlerbehebung

Zuerst das Symptom, dann die Lösung. Die vollständige Fehlertabelle steht im
Admin-Handbuch in Abschnitt [15](../../admin/guide.md#15-troubleshooting),
Logs und Zustand in Abschnitt
[14](../../admin/guide.md#14-monitoring-and-logs).

Drei Befehle beantworten die meisten Fragen:

```
nebula status
systemctl status nebula-executor nebula-server nebula-discovery.path nebula-discovery.timer
journalctl -u nebula-executor -u nebula-server -u nebula-discovery
```

<a id="nothing-runs-after-a-reboot-or-upgrade"></a>

## Nach einem Neustart oder Upgrade läuft nichts

**Symptom:** Operationen bleiben ausstehend oder schlagen fehl; das
Dashboard meldet, dass der Executor gesperrt ist; Sie haben die
Benachrichtigung "found locked after a restart" erhalten.

**Ursache:** Der Executor startet immer gesperrt. Die SSH-Schlüssel und der
Vault liegen erst im Speicher, wenn ein Admin auf der Maschine entsperrt.

**Lösung:** `nebula unlock` auf der Nebula-Maschine. Genehmigte
Lese-Leases laufen weiter. Ausstehende Vorschläge von vor dem Neustart
wurden verworfen und müssen neu geplant werden.

<a id="nebula-says-permission-denied-or-peer-uid-holds-no-role"></a>

## `nebula` meldet permission denied oder "peer UID holds no role"

**Symptom:** `nebula: … permission denied` am Socket, oder
`peercred: peer UID holds no role`.

**Ursache:** Ihr Login ist noch nicht in der Gruppe `nebula-rpc` oder nicht
in den `-admin-users` des Executors.

**Lösung:** Melden Sie sich nach `install.sh` ab und wieder an; prüfen Sie
`id`. Um einen Admin hinzuzufügen, führen Sie `install.sh` erneut mit der
vollständigen `--admin-users`-Liste aus (oder bearbeiten Sie Ihre
`20-local.conf`, Admin-Handbuch
[6.2](../../admin/guide.md#62-executor-flags)).

<a id="nebula-this-needs-a-terminal"></a>

## `nebula: this needs a terminal`

**Ursache:** `unlock` und andere Passphrase-Abfragen lesen von einem
Terminal, nie aus einer Pipe.

**Lösung:** Führen Sie den Befehl in einer interaktiven Shell aus. In
Containern verwenden Sie
`docker compose exec -u nebula-admin executor nebula unlock` ohne `-T`.

<a id="unlock-fails-because-of-a-key-file"></a>

## Entsperren scheitert an einer Schlüsseldatei

**Symptom:** `keyring: … is not passphrase-protected`, `has mode …`,
`is owned by uid …` oder eine falsche Passphrase.

**Lösung:** Jede Datei in `/var/lib/nebula/executor/keys/` muss im
OpenSSH-Format mit Passphrase vorliegen, Modus 0600 haben, `nebula-executor`
gehören, und alle müssen dieselbe Passphrase haben. Einen alten PEM-Schlüssel
wandeln Sie mit `ssh-keygen -p -o -f FILE` um.

<a id="login-or-approval-fails-in-the-browser"></a>

## Anmeldung oder Genehmigung scheitert im Browser

**Symptom:** Die Abfrage des Sicherheitsschlüssels scheitert oder die
Anfrage wird abgelehnt.

**Ursache:** Sie sind nicht genau auf `https://<rp-id>`, oder der Reverse
Proxy verändert `Host` oder `Origin`.

**Lösung:** Verwenden Sie die Adresse der RP ID. Prüfen Sie, dass der Proxy
die Header unverändert weitergibt und dass `public_origin` in
`/etc/nebula/server.json` den Wert `https://<rp-id>` hat.

<a id="the-server-does-not-start"></a>

## Der Server startet nicht

**Symptom:** `serverconfig: invalid config: …` oder
`… contains notification secrets and is readable or writable by others`.

**Lösung:** Die erste Meldung listet jedes Problem auf (Origin in
Kleinbuchstaben mit `https://` und ohne Pfad, absolute Pfade, unbekannte
Schlüssel, …); beheben Sie alle. Für die zweite Meldung:
`sudo chmod o-rwx /etc/nebula/server.json`. Referenz der Schlüssel:
Admin-Handbuch [6.1](../../admin/guide.md#61-etcnebulaserverjson).

<a id="a-host-is-unreachable-or-the-result-is-network_unreachable"></a>

## Ein Host ist UNREACHABLE oder das Ergebnis ist `network_unreachable`

**Ursache:** Kein Endpunkt des Hosts hat geantwortet; es wurde nichts
gesendet.

**Lösung:** Prüfen Sie die Endpunkte im Inventar, das Routing (VPN aktiv?)
und die Host-Firewall, dann `nebula host test HOST ENDPOINT`. Reine
Leseaktionen werden nach 20 Sekunden und nach 1 Minute automatisch
wiederholt; andere Aktionen planen Sie neu. Läuft fail2ban auf dem Host,
tragen Sie die IPs der Nebula-Maschine in `ignoreip` ein.

<a id="a-host-is-blocked-after-a-host-key-change"></a>

## Ein Host ist nach einem Host-Key-Wechsel gesperrt

**Ursache:** Der Host hat einen anderen SSH-Host-Key vorgelegt
(Neuinstallation oder ein Angriff).

**Lösung:** Vergleichen Sie den neuen Fingerabdruck an der Konsole des Hosts
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), dann Dashboard →
**Re-pin…** (neu pinnen). Siehe
[Hosts](hosts.md#re-pin-a-host-whose-key-changed). Pinnen Sie nie neu ohne
den Vergleich an der Konsole.

<a id="an-update-fails-with-precheck_failed"></a>

## Ein Update scheitert mit `precheck_failed`

**Ursache:** Eine Vorprüfung ist fehlgeschlagen, und es wurde nichts
installiert: Speicherplatz auf `/` oder `/var`, kaputter `dpkg`-Zustand,
apt-Sperre durch einen anderen apt-Lauf oder eine schreibgeschützte Platte.

**Lösung:** Lesen Sie den Grund auf der Seite der Operation, beheben Sie ihn
auf dem Host und planen Sie neu.

<a id="a-reboot-ends-with-host_not_returned"></a>

## Ein Neustart endet mit `host_not_returned`

**Ursache:** Der Host ist nicht innerhalb von 20 Minuten mit einer neuen
Boot-ID zurückgekommen.

**Lösung:** Prüfen Sie seine Konsole (hängendes fsck, Bootloader, Netzwerk).

<a id="every-action-asks-for-a-security-key-with-user-verification"></a>

## Jede Aktion verlangt einen Sicherheitsschlüssel mit Benutzerverifikation

**Ursache:** Die Aktion gilt als HIGH: Das Skript ist nicht vertrauenswürdig
(eingebaute Skripte sind nach Installation oder Upgrade nicht
vertrauenswürdig), für den Host gibt es auf dem Executor keinen Eintrag zur
Kritikalität, oder der Safety Scanner hat sie hochgestuft.

**Lösung:** `nebula artifact trust-builtins` (oder je Aktion
`nebula artifact trust`) und `nebula host criticality HOST LEVEL`. Siehe
Admin-Handbuch [17.3](../../admin/guide.md#173-risk-classes).

<a id="a-read-lease-or-schedule-is-refused"></a>

## Ein Lese-Lease oder Zeitplan wird abgelehnt

**Ursache:** Der Executor akzeptiert nur Aktionen, die er auf jedem
gewählten Host als LOW einstuft und die auf der Lese-Allowlist stehen.

**Lösung:** Stufen Sie das eingebaute Skript als vertrauenswürdig auf LOW ein
und hinterlegen Sie die Kritikalität jedes Hosts
(`nebula host pin --criticality` oder `nebula host criticality`).
`package.refresh`, `docker.logs` und Aktionen mit Secrets können nie per
Lease freigegeben werden.

<a id="a-runbook-with-secrets-fails-with-vault_locked-or-secret_unavailable"></a>

## Ein Runbook mit Secrets scheitert mit `vault_locked` oder `secret_unavailable`

**Lösung:** `vault_locked`: `nebula unlock` (der Vault öffnet sich mit den
Schlüsseln). `secret_unavailable: no vault secret …`: `nebula secret list`,
dann `nebula secret set ID` oder ein anderes Secret wählen.

<a id="docker-actions-say-no-docker-or-fail-with-permissions"></a>

## Docker-Aktionen melden "no Docker" oder scheitern an Berechtigungen

**Ursache:** Docker fehlt, oder der SSH-Benutzer ist weder in der Gruppe
`docker` noch darf er `sudo -n` ausführen.

**Lösung:** Installieren Sie Docker, oder nehmen Sie den Host mit sudo auf
(ohne `--no-sudo`).

<a id="discovery-shows-as-not-installed-or-results-never-arrive"></a>

## Discovery wird als nicht installiert angezeigt oder Ergebnisse kommen nie an

**Lösung:**

- Nicht installiert: `discovery_dir` in `server.json` ist falsch oder die
  Spool-Verzeichnisse fehlen; führen Sie `install.sh` erneut aus.
- `nmap is not installed …`: `sudo apt install nmap`.
- Keine Ergebnisse: `systemctl status nebula-discovery.path`; die
  Spool-Modi müssen 2750 sein (`jobs/` `nebula-server:nebula-discovery`,
  `results/` umgekehrt).

<a id="proxmox-pages-are-empty-or-show-unavailable"></a>

## Proxmox-Seiten sind leer oder zeigen `unavailable`

**Lösung:** Prüfen Sie in dieser Reihenfolge: `nebula pve remote list`
(Remote `active`?), `systemctl status nebula-pve-collector`, ein genehmigtes
Lese-Lease auf `/pve/<id>` (**Request read lease** oder **Renew read
lease**, also Lese-Lease anfordern oder verlängern) und
`journalctl -u nebula-executor` auf `read_grant_does_not_cover`.
Vollständige Tabelle:
[Proxmox-Fehlerbehebung](../../operator/proxmox.md#troubleshooting).

<a id="a-network-device-shows-no-data"></a>

## Ein Netzwerkgerät zeigt keine Daten

**Ursache:** Das Auslesen von Gerätedaten ist in diesem Release nicht
implementiert; der Executor antwortet "device reads are not implemented yet
(ND-14)".

**Lösung:** Keine nötig. Registrierung, Pins und Zugangsdaten bleiben
erhalten, bis das Auslesen kommt (ADR 0010). Siehe
[Netzwerk](network.md#what-works-for-network-devices-today).

<a id="vulnerability-findings-never-appear"></a>

## Schwachstellen-Funde erscheinen nie

**Ursache:** Der Inventar-Export ist in diesem Release noch leer, daher wird
jeder Fund mit "subject not in the run's inventory snapshot" abgelehnt.

**Lösung:** Auf Ihrer Seite noch keine. Prüfen Sie, dass Hermes die API
erreicht (`401` = falsches Token, `403` = falsche Quelladresse oder falscher
Scope, beides als `audit`-Zeilen in `journalctl -u nebula-server`). Siehe
[Schwachstellen](vulnerabilities.md#what-works-in-this-release).

<a id="a-batch-member-stays-refused-with-batch_host_busy"></a>

## Ein Batch-Mitglied bleibt mit `batch_host_busy` abgelehnt

**Ursache:** Ein früherer Batch-Lauf läuft auf diesem Host möglicherweise
noch, oder seine Sperre ist nach 24 Stunden abgelaufen.

**Lösung:** Folgen Sie "Held batch targets" im Admin-Handbuch
[9.2](../../admin/guide.md#92-rollouts-in-stages): Executor stoppen, mit
`sudo -u nebula-executor nebula-executor batch-holds list` prüfen und erst
nach Prüfung des Hosts wieder freigeben. Bearbeiten Sie
`batch-held-targets.json` nie von Hand.

<a id="backup-or-restore-refuses-to-run"></a>

## Backup oder Restore verweigert die Ausführung

**Lösung:**

- `run this with sudo`: `sudo nebula backup` aus Ihrem Admin-Login, nicht
  aus einer Root-Shell.
- `install.sh`: no pre-upgrade backup: Tragen Sie einen Empfänger in
  `/etc/nebula/backup-recipients` ein.
- Restore: schema newer than this binary: Installieren Sie zuerst die
  Nebula-Version, mit der das Backup erstellt wurde.

<a id="the-executor-does-not-start"></a>

## Der Executor startet nicht

**Symptom:** `-admin-users is required`, `root cannot be an admin user`,
`admin user … must not be the server user` oder
`executor.db is missing but executor.db.installed says one existed`.

**Lösung:** Korrigieren Sie die Admin-Liste und führen Sie `install.sh`
erneut aus. Fehlt die Datenbank, stellen Sie ein Backup wieder her
(`sudo nebula restore`). Entfernen Sie die in der Meldung genannte
Markierungsdatei nur, wenn Sie bewusst leer starten wollen.

<a id="after-an-i1-integrity-alarm"></a>

## Nach einem I1-Integritätsalarm

**Symptom:** `nebula integrity status` zeigt einen offenen I1-Befund, oder
`nebula unlock` wird abgelehnt.

**Bedeutung:** NOS hat festgestellt, dass die eigenen Dateien auf der
NOS-Maschine von der signierten Liste des installierten Releases abweichen,
dass eine erfasste Datei fehlt oder dass ein nicht gelistetes
`/usr/bin/nebula*`-Programm existiert. Eine geänderte oder fehlende
NOS-Binärdatei, Systemd-Unit, eingebaute Modul-Datei oder ein Root-Schlüssel
sowie ein nicht gelistetes Programm sperrt den Executor. Eine geänderte
Web-Datei wird vom Server abgelehnt. Eine geänderte Konfigurationsdatei ist
ein Befund ohne Sperre. Eine unvollständige Prüfung wird nie als sauber
gemeldet.

**Was gesperrt ist:** Solange ein sperrender Befund offen ist, lehnt der
Executor `nebula unlock` sowie jede Mutation und jeden Read-Grant-Dispatch ab.

**Was nicht passiert:** NOS löscht, stellt wieder her oder rollt keine Datei
zurück. Die Sperre entzieht nur Berechtigungen. Die Dateien zu reparieren ist
Ihre Aufgabe.

**Lösung:**

1. `nebula integrity status` zeigt die Sperre, den letzten Lauf und die
   offenen Befunde mit ihren IDs.
2. Offline prüfen, auf einer anderen Maschine oder von schreibgeschütztem
   Boot-Medium, bei dem die NOS-Platte an anderer Stelle eingehängt ist, gegen
   Release-Dateien, die Sie dort geholt und geprüft haben:

   ```
   nebula integrity verify --offline RELEASE-DIR --root MOUNT --version X.Y.Z --flavour FLAVOUR
   ```

   Beide Pfade müssen absolut sein. `--version` ist die Version, die diese
   Maschine laufen soll. Exit-Status 0 bedeutet sauber, 5 bedeutet
   Abweichungen gefunden, 6 bedeutet unvollständige Prüfung. Behandeln Sie
   6 nie als sauber.
   Verwenden Sie ein `nebula` von der anderen Maschine oder dem Boot-Medium,
   aus den geprüften Release-Dateien, nie `MOUNT/usr/bin/nebula` oder ein
   anderes Programm von der geprüften Platte: ein ersetztes Programm kann
   „sauber“ melden.
3. NOS aus dem Paket neu installieren oder ein neues signiertes Release
   einspielen.
4. Für jeden offenen Befund `nebula integrity ack FINDING` ausführen. Es
   zeigt den Befund, fragt nach der Eingabe `yes` und quittiert nur diesen
   einen Befund. Eine spätere Prüfung, die dieselbe Abweichung findet, sperrt
   erneut. Solange andere sperrende Befunde offen sind, bleiben Entsperren und
   Dispatch abgelehnt.

**Grenze:** Der UI-Text lautet wörtlich: „NOS checks cannot detect a root
compromise of the NOS machine; see ADR 0015“. Auf Deutsch: NOS-Prüfungen
können eine Root-Kompromittierung der NOS-Maschine nicht erkennen; siehe
ADR 0015. Die Entsperr-Sperre entzieht nur Berechtigungen; sie hilft nicht,
wenn der Executor selbst die ersetzte Binärdatei ist. Nur die Offline-Prüfung
in Schritt 2 hängt nicht von der Software auf der NOS-Maschine ab; deshalb ist
sie die Prüfung, die nach jedem I1-Alarm laufen sollte.

**Verteilung:** GitHub ist nur ein Verteilweg, nie ein Vertrauensanker.
Release-Dateien werden erst vertraut, wenn `release-manifest.json.sig` gegen
die in den NOS-Binärdateien eingebauten Root-Public-Keys geprüft ist.
