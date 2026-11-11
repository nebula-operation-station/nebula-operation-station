# Sicherung, Wiederherstellung und Upgrades

Verschlüsselte Sicherungen, ihre Wiederherstellung und Upgrades, ohne den
Weg zurück zu verlieren. Referenz: Admin-Handbuch
[12](../../admin/guide.md#12-backup-and-restore)
und [13](../../admin/guide.md#13-upgrades).

<a id="create-the-backup-key-once"></a>

## Den Sicherungsschlüssel anlegen (einmalig)

**Ziel:** Sicherungen werden für einen Schlüssel verschlüsselt, der nicht
auf der Nebula-Maschine liegt.

**Voraussetzungen:** [age](https://age-encryption.org) auf einer Maschine,
die Sie sicher aufbewahren (nicht die Nebula-Maschine).

**Schritte:**

1. Auf der sicheren Maschine: `age-keygen -o nebula-backup.key`. Der Befehl
   gibt den öffentlichen Schlüssel aus (`age1…`).
2. Auf der Nebula-Maschine diesen öffentlichen Schlüssel in
   `/etc/nebula/backup-recipients` eintragen (ein Empfänger pro Zeile;
   mehrere sind erlaubt).
3. `nebula-backup.key` offline aufbewahren, zum Beispiel in Ihrem
   Passwortmanager.

**Erwartetes Ergebnis:** `sudo nebula backup` funktioniert (nächster
Abschnitt).

<a id="back-up-nebula"></a>

## Nebula sichern

**Ziel:** ein mit age verschlüsseltes Archiv von allem außer Passphrasen
und Klartext-Secrets.

**Voraussetzungen:** Sicherungsempfänger eingetragen; ein Admin-Login mit
`sudo` (keine Root-Shell).

**Schritte:**

```
sudo nebula backup
```

`--out FILE` schreibt an einen anderen Ort als `~/nebula-backups/`.
Kopieren Sie das Archiv danach von der Maschine weg, zum Beispiel mit
`restic backup ~/nebula-backups`.

**Erwartetes Ergebnis:** ein neues Archiv in `~/nebula-backups/` des
Admins, der `sudo` ausgeführt hat. Die Dienste laufen währenddessen weiter.

**Was enthalten ist:** Inventar, Historie, Konfiguration (`server.json`,
`backup-recipients`, die systemd-Drop-ins), die Server-Datenbank mit Logs
und Artefakten sowie die Datenbank und die SSH-Schlüsseldateien des
Executors (weiterhin passphrasegeschützt). **Nicht** enthalten: die
Passphrasen, entschlüsselte Schlüssel, Klartext-Secrets und der
Event-Schlüssel.

**Häufige Fehler:**

- `run this with sudo`: führen Sie `sudo nebula backup` aus Ihrem
  Admin-Login aus, nicht aus einer Root-Shell.
- Keine Empfänger: tragen Sie einen in `/etc/nebula/backup-recipients` ein.
- `--no-encrypt` schreibt ein unverschlüsseltes Archiv (Sie tippen
  `unencrypted`). Es hat keinen eigenen Integritätsschutz; bewahren Sie
  eine Prüfsumme an anderer Stelle auf.

<a id="restore-a-backup"></a>

## Eine Sicherung wiederherstellen

**Ziel:** den Zustand von Nebula auf derselben oder einer neuen Maschine
zurückholen.

**Voraussetzungen:** auf einer neuen Maschine lief `install.sh` mit
**denselben** `--admin-users` und `--rp-id`; die age-Identitätsdatei; die
Schlüssel-Passphrase.

**Schritte:**

```
sudo nebula restore --identity nebula-backup.key FILE
```

1. Lesen Sie, was angezeigt wird: wann, wo und mit welcher Version die
   Sicherung erstellt wurde. Der Befehl prüft das Manifest, jede Prüfsumme
   und die Schema-Versionen, bevor sich etwas ändert.
2. `restore` eintippen. Bei einer Sicherung von einer anderen Maschine
   zusätzlich den Namen dieser Maschine eintippen (oder `unknown`).
3. Der Befehl stoppt die Dienste, schiebt die aktuellen Daten beiseite
   (`*.pre-restore-<time>`), legt die Sicherung an ihren Platz und startet
   die Dienste gesperrt.
4. Abschließen:

   ```
   nebula unlock
   nebula status
   nebula events verify
   ```

**Erwartetes Ergebnis:** die Dienste laufen mit den wiederhergestellten
Daten. Die Konfiguration aus der Sicherung wird zum Vergleich nach
`/etc/nebula/from-backup-<time>/` geschrieben; sie wird **nicht**
angewendet.

**Häufige Fehler:** "schema newer than this binary" (Schema neuer als
dieses Programm): die Sicherung stammt von einer neueren Nebula-Version;
installieren Sie zuerst diese Version. Eine Wiederherstellung auf einer
neuen Maschine beginnt einen neuen Event-Schlüssel; die Kette verzeichnet
den Wechsel, und `nebula events verify` prüft über ihn hinweg weiter.

<a id="back-up-and-restore-a-container-install"></a>

## Eine Container-Installation sichern und wiederherstellen

**Ziel:** verschlüsselte Kopien der Docker-Volumes.

**Voraussetzungen:** der **öffentliche** age-Schlüssel; `age` auf dem
Docker-Host.

**Schritte (Sicherung):**

```
cd deploy/container
docker compose stop
for v in executor-data server-data; do
  docker run --rm -v nebula_$v:/v:ro debian:12-slim tar -C /v -cz . \
    | age -r age1… -o nebula-$v-$(date +%F).tar.gz.age
done
docker compose start
docker compose exec -u nebula-admin executor nebula unlock
```

**Schritte (Wiederherstellung):** den Stack stoppen, jedes Archiv in sein
leeres Volume streamen, starten und entsperren:

```
age -d -i nebula-backup.key nebula-executor-data-<date>.tar.gz.age \
  | docker run --rm -i -v nebula_executor-data:/v debian:12-slim tar -C /v -xpz
```

**Hinweis:** eine Volume-Kopie enthält alles, was der Executor hat,
einschließlich seines Event-Schlüssels. Bewahren Sie sie nie
unverschlüsselt auf. `nebula backup` ist nur für Host-Installationen.

<a id="upgrade-a-tarball-install"></a>

## Eine Tarball-Installation aktualisieren

**Ziel:** ein neues Release, mit vorheriger Sicherung.

**Voraussetzungen:** Sicherungsempfänger eingetragen; Release Notes
gelesen.

**Schritte:**

1. Den neuen Tarball entpacken und daraus als Admin über `sudo` ausführen:

   ```
   sudo ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org
   ```

   Das Skript erstellt zuerst eine Sicherung und hört ohne Änderungen auf,
   wenn das nicht geht.
2. `nebula unlock`.
3. Den eingebauten Aktionen erneut vertrauen, falls sich ihre Versionen
   geändert haben: `nebula artifact trust-builtins`, dann
   `nebula artifact list`.
4. `nebula status` und `nebula events verify`.

**Erwartetes Ergebnis:** die neue Version läuft; unveränderte Unit-Dateien
wurden ersetzt; bearbeitete wurden mit einer Warnung und einem
`diff -u`-Befehl behalten.

**Häufige Fehler:** "no pre-upgrade backup was made" (keine Sicherung vor
dem Upgrade erstellt): einen Sicherungsempfänger eintragen und über `sudo`
aus einem Admin-Konto ausführen, oder bewusst `NEBULA_SKIP_BACKUP=1`
setzen. Es gibt kein automatisches Downgrade; die Sicherung ist der Weg
zurück.

<a id="upgrade-a-debian-package-install"></a>

## Eine Installation aus dem Debian-Paket aktualisieren

**Ziel:** dasselbe für das APT-Paket.

**Schritte:**

```
sudo apt update && sudo apt upgrade
sudo nebula backup && sudo systemctl restart nebula-executor nebula-server
nebula unlock
nebula artifact trust-builtins
nebula status && nebula events verify
```

`apt upgrade` startet die Dienste nie neu, weil die Sicherung Ihr `sudo`
braucht. Die alte Version läuft weiter, bis Sie neu starten. Ein neuer
`nebula-pve-collector` braucht `sudo systemctl restart nebula-pve-collector`.

<a id="upgrade-a-container-install"></a>

## Eine Container-Installation aktualisieren

**Schritte:** das neue Image bauen oder ziehen, die Volumes sichern (siehe
oben), `NEBULA_IMAGE` in `deploy/container/.env` auf das neue Tag setzen,
`docker compose up -d`, dann
`docker compose exec -u nebula-admin executor nebula unlock`.

<a id="test-that-a-backup-can-be-restored"></a>

## Testen, ob sich eine Sicherung wiederherstellen lässt

**Ziel:** wissen, dass die Sicherung funktioniert, bevor Sie sie brauchen.

**Schritte (monatlich):** dieselbe Nebula-Version auf einer Ersatz-VM mit
denselben `--admin-users` und `--rp-id` installieren, das neueste Archiv
und die age-Identität dorthin kopieren,
`sudo nebula restore --identity nebula-backup.key FILE` ausführen, dann
`nebula unlock`, `nebula status` und `nebula events verify`.

**Erwartetes Ergebnis:** die wiederhergestellte Instanz entsperrt, und die
Event-Kette wird bestätigt. Fahren Sie die Ersatz-VM danach herunter: sie
enthält funktionierende Schlüssel für Ihre Hosts.
