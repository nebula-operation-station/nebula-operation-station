# Container

Docker und Compose auf verwalteten Hosts: Container ansehen, nach neuen
Images suchen, Compose-Projekte aktualisieren und Container-Updates mit
Rollback. Referenz: Admin-Handbuch
[9.3](../../admin/guide.md#93-services-and-docker).

Alle Docker-Aktionen lesen über die Gruppe `docker`, wenn der SSH-Benutzer
darin Mitglied ist, sonst über `sudo -n`. Beides bedeutet Root auf dem Host.

<a id="list-the-containers-on-a-host"></a>

## Die Container eines Hosts auflisten

**Ziel:** jeden Container mit Image, Zustand, Health, veröffentlichten Ports
und Compose-Projekt sehen.

**Voraussetzungen:** Host angemeldet (enrolled); Docker auf dem Host.

**Schritte:**

1. *Operations → New operation* (`/operations/new`) → **List containers**
   (Container auflisten; `docker.list`, LOW), Hosts auswählen, planen.
2. Oder im Inventardiagramm (`/inventory/chart`): Hosts auswählen →
   **Refresh updates, containers, services** (Updates, Container und
   Dienste aktualisieren).

**Erwartetes Ergebnis:** Das Ergebnis listet die Container auf; der
Host-Kasten im Diagramm zeigt sie an, mit Links zu *logs*, *inspect*,
*restart* und *update project*.

**Häufige Fehler:** „no Docker“ auf dem Host oder ein Berechtigungsfehler:
Docker fehlt, oder der SSH-Benutzer ist weder in der Gruppe `docker` noch
für `sudo -n` berechtigt.

<a id="read-a-containers-logs-or-details"></a>

## Logs oder Details eines Containers lesen

**Ziel:** einen einzelnen Container untersuchen, ohne sich am Host
anzumelden.

**Schritte:**

1. *Operations → New operation* → **Container logs** (`docker.logs`) oder
   **Container details** (`docker.inspect`), mit Name oder ID des
   Containers. Die Links *logs* und *inspect* im Diagramm füllen dieses
   Formular vor.
2. Planen.

**Erwartetes Ergebnis:** *logs* zeigt den Zustand und die letzten 100
Logzeilen. *details* zeigt Image und Repository-Digest, Zustand, Health,
Restart-Policy, Mounts, veröffentlichte Ports und Netzwerke.

**Hinweis:** Die Details zeigen nie Umgebungsvariablen, Kommandozeile oder
Labels des Containers, weil diese oft Secrets enthalten.

<a id="start-stop-or-restart-a-container"></a>

## Einen Container starten, stoppen oder neu starten

**Ziel:** einen einzelnen Container bedienen.

**Voraussetzungen:** Ihr Sicherheitsschlüssel (MEDIUM).

**Schritte:** *Operations → New operation* → **Start container**, **Stop
container** oder **Restart container** (`docker.start`, `docker.stop`,
`docker.restart`) mit dem Containernamen; freigeben.

**Erwartetes Ergebnis:** Das Ergebnis zeigt den Zustand vorher und nachher.
Nichts wird neu erstellt, gepullt oder aktualisiert, und die Aktion wird nie
automatisch wiederholt.

<a id="check-which-images-have-updates"></a>

## Prüfen, für welche Images es Updates gibt

**Ziel:** wissen, für welche laufenden Container es ein neueres Image zu
ihrem Tag gibt.

**Schritte:** *Operations → New operation* → **Check image updates**
(Image-Updates prüfen; `docker.check_updates`, LOW), Hosts auswählen,
planen.

**Erwartetes Ergebnis:** eine Liste der Images, für die ein Update
verfügbar ist.

**So funktioniert es:** Der Host fragt bei jeder Registry den aktuellen
Digest des Tags ab (eine anonyme Manifest-HEAD-Anfrage). Nichts wird
gepullt, und die Pull-Limits von Docker Hub werden nicht belastet.

**Häufige Fehler:** Private Registries, die Zugangsdaten verlangen,
erscheinen als „unknown“. Der Host braucht `curl` und HTTPS-Zugriff auf die
Registries.

<a id="update-a-compose-project"></a>

## Ein Compose-Projekt aktualisieren

**Ziel:** neue Images für ein Projekt pullen und seine Container neu
erstellen.

**Voraussetzungen:** zuerst *Check image updates* ausgeführt; Ihr
Sicherheitsschlüssel (MEDIUM, ein dauerhafter Job).

**Schritte:**

1. *Operations → New operation* → **Update Compose project**
   (`docker.compose_update`) mit dem Projektnamen, oder *update project* im
   Diagramm.
2. Freigeben.

Der Job ermittelt Verzeichnis und Dateien des Projekts aus den
Container-Labels, führt `docker compose pull` und danach
`docker compose up -d` aus und vergleicht die Container vorher und nachher.

**Erwartetes Ergebnis:** OK, wenn alle Container wie vorher laufen. FAILED,
wenn weniger Container laufen, ein Befehl fehlgeschlagen ist oder ein
gesunder Container nicht mehr gesund ist. WARNING, wenn ein Container
ungesund ist, sich veröffentlichte Ports geändert haben oder sich die Zahl
der Container geändert hat.

**Hinweis:** Dieser Weg hat kein Rollback. Für Updates, die Sie eventuell
rückgängig machen möchten, verwenden Sie den nächsten Abschnitt.

<a id="update-containers-with-a-rollback-option"></a>

## Container mit Rollback-Möglichkeit aktualisieren

**Ziel:** ausgewählte Compose-Services je Umgebung aktualisieren, wobei das
alte Image für ein Rollback erhalten bleibt.

**Voraussetzungen:**

1. Eingebaute Aktionen als vertrauenswürdig markiert
   ([Erste Schritte](getting-started.md#trust-the-built-in-actions-after-install-or-upgrade)).
2. Der Host hat eine Umgebung (DEV, QA oder PROD) und ist angemeldet.
3. *Prepare container updates* (Container-Updates vorbereiten;
   `docker.update_prepare`, MEDIUM) lief einmal auf dem Host.
4. Ein *Preview container updates* (Vorschau der Container-Updates;
   `docker.update_preview`, LOW) lief vor höchstens einer Stunde. Um einen
   Tag zu ändern, tragen Sie die Ziel-Tags im Parameter `target_tags` der
   Vorschau ein.

**Schritte:**

1. Folgen Sie im Inventardiagramm dem Link des Hosts zu *Container and
   Compose updates and rollbacks* (`/inventory/containers`). Die Seite
   verlinkt auf den Vorbereitungs- oder Vorschauschritt, wenn einer fehlt
   oder veraltet ist.
2. Haken Sie die zu aktualisierenden Services an. Services, die sich einen
   Namespace teilen, müssen zusammen ausgewählt werden. Ein
   Major-Versionswechsel braucht zusätzlich „I confirm a major version
   change“ (ich bestätige einen Major-Versionswechsel).
3. *Review the plan* (Plan prüfen): je Service die Images, Digests, Tags,
   neu zu erstellende Container, betroffene Abhängigkeiten, Stufe und
   Risiko.
4. *Confirm and propose batch* (bestätigen und Batch vorschlagen), dann auf
   der Batch-Seite (`/batches/<id>`) freigeben. Im gehärteten Modus:
   `nebula batch review DIGEST` und `nebula batch approve DIGEST`.
5. Öffnen Sie jede Stufe (DEV, dann QA, dann PROD), wenn die vorherige
   bestanden hat.

**Erwartetes Ergebnis:** Die Batch-Seite zeigt den Fortschritt jedes
Mitglieds. Das erste fehlgeschlagene Mitglied stoppt alles, was noch nicht
gestartet ist.

**Häufige Fehler:**

- Ein Service hat kein Kontrollkästchen: Die Seite sagt, warum (per Digest
  gepinnt, lokal gebaut, privates Image, aktuell, …).
- Eigenständige Container (nicht Compose) werden hier noch nicht angeboten.
- Solange der Server keine Tag-Richtlinie hat, werden nur Aktualisierungen
  auf demselben Tag angeboten.

<a id="roll-back-a-container-update"></a>

## Ein Container-Update zurückrollen

**Ziel:** zu den Images zurückkehren, die ein Update ersetzt hat.

**Voraussetzungen:** Das Update wurde auf `/inventory/containers`
aufgezeichnet; das Rollback-Fenster ist noch offen (alte Images bleiben mit
der Markierung `nos-retained` auf dem Host); eine frische Vorschau zeigt das
Projekt so, wie das Update es hinterlassen hat.

**Schritte:** Wählen Sie auf `/inventory/containers` unter *Rollback* das
Update aus, prüfen Sie es und schlagen Sie es vor; geben Sie es wie ein
Update frei.

**Erwartetes Ergebnis:** Die Container laufen wieder mit den alten Images.

**Hinweis:** Migrationen von Volumes und Datenbanken werden **nicht**
rückgängig gemacht. Sichern Sie Daten, die eine neue Version migriert. NOS
löscht aufbewahrte Images nie; entfernen Sie sie auf dem Host, wenn Sie sie
nicht mehr brauchen.

<a id="store-a-standalone-containers-definition"></a>

## Die Definition eines eigenständigen Containers speichern

**Ziel:** festhalten, wie ein eigenständiger Container (ohne Compose)
definiert ist, als Grundlage für spätere Updates.

**Voraussetzungen:** Admin-Login auf der Nebula-Maschine; eine
JSON-Definitionsdatei.

**Schritte:**

```
nebula container definition put web-01 grafana grafana.json
nebula container definition list web-01
nebula container definition remove web-01 grafana
```

Die Definition kommt aus einer Datei oder von stdin (`-`), nie aus einem
Argument. `remove --version N` entfernt eine ältere Version; innerhalb eines
Rollback-Fensters wird das Entfernen abgelehnt.

**Erwartetes Ergebnis:** `list` zeigt Version, Autor und Zeitpunkt, nie den
Inhalt.

**Hinweis:** Das Aktualisieren eigenständiger Container über die Oberfläche
wird noch nicht angeboten (siehe
[Container mit Rollback-Möglichkeit aktualisieren](#update-containers-with-a-rollback-option)).
