# Patchen und Dienste

Hosts aktuell halten, sie sicher neu starten, systemd-Dienste bedienen
und eigene Skripte ausführen. Referenz: Admin-Handbuch
[9.1 bis 9.6](../../admin/guide.md#9-daily-operation).

Jede Operation folgt demselben Muster: planen, prüfen, was der Executor
ausführen wird, mit Ihrem Sicherheitsschlüssel freigeben (oder im
Hardened-Modus auf der Maschine selbst), Ergebnis lesen. Ohne diese
Freigabe läuft nichts auf einem Host.

<a id="check-which-updates-a-host-needs"></a>

## Prüfen, welche Updates ein Host braucht

**Ziel:** die Zahl der Sicherheitsupdates und aller Updates sehen, und ob
ein Neustart nötig ist.

**Voraussetzungen:** Host eingebunden und gepinnt ([Hosts](hosts.md));
Executor entsperrt; eingebaute Aktionen vertrauenswürdig
([Erste Schritte](getting-started.md#trust-the-built-in-actions-after-install-or-upgrade)).

**Schritte:**

1. Dashboard → **Open privileged session** (privilegierte Sitzung öffnen;
   Sicherheitsschlüssel). *Check updates* ist LOW und läuft innerhalb der
   Sitzung ohne weitere Abfrage.
2. *Operations → New operation* (`/operations/new`), **Check
   updates** (`package.list_updates`) wählen, Hosts auswählen, planen und
   freigeben.

Auch im Inventar-Diagramm (`/inventory/chart`) können Sie Hosts auswählen
und **Refresh updates, containers, services** verwenden.

**Erwartetes Ergebnis:** das Inventar zeigt pro Host etwa
`2 security / 9 total, reboot required, checked …`.

**Häufige Fehler:** ohne vertrauenswürdige eingebaute Aktionen oder bei
einem Host ohne Kritikalitätseintrag braucht selbst diese reine
Leseprüfung einen Sicherheitsschlüssel mit Benutzerverifikation (sie zählt
dann als HIGH).

<a id="install-security-updates-or-all-updates"></a>

## Sicherheitsupdates oder alle Updates installieren

**Ziel:** Hosts mit Vor- und Nachprüfungen patchen.

**Voraussetzungen:** ein aktuelles Ergebnis von *Check updates*; Ihr
Sicherheitsschlüssel.

**Schritte:**

1. *Operations → New operation*, **Install security updates**
   (`package.install_security`) oder **Install all updates**
   (`package.install_all`) wählen, Hosts auswählen. (Im Inventar-Diagramm:
   Hosts auswählen → **Install updates…**.)
2. Optional: unter *Rollout* einen Rollout wählen (siehe
   [In Stufen ausrollen](#roll-out-an-operation-in-stages-canary-waves-dev--qa--prod)).
3. Den Plan prüfen und **Approve with security key** (mit
   Sicherheitsschlüssel freigeben).

Der Job läuft auf dem Host unter systemd. Vorprüfungen: freier Platz auf
`/` und `/var`, `dpkg`-Zustand, beschreibbare Platte, apt-Sperre.
Nachprüfungen: `dpkg`-Zustand, Neustart nötig, neu fehlgeschlagene Units.
Auf Proxmox-VE-Knoten verwendet *Install all updates* `full-upgrade`.

**Erwartetes Ergebnis:** die Seite der Operation (`/operations/<id>`)
zeigt das Ergebnis jedes Hosts; die Update-Zahlen im Inventar sinken nach
der nächsten Prüfung.

**Häufige Fehler:**

- `precheck_failed`: es wurde nichts installiert. Der Grund steht auf der
  Seite (Plattenplatz, `dpkg`-Zustand, apt-Sperre durch einen anderen
  apt-Lauf, schreibgeschützte Platte). Beheben Sie das auf dem Host und
  planen Sie neu.
- `network_unreachable`: kein Endpunkt hat geantwortet, es wurde nichts
  gesendet. Planen Sie neu, sobald der Host erreichbar ist.

<a id="reboot-hosts-that-need-it"></a>

## Hosts neu starten, die es brauchen

**Ziel:** neu starten und bestätigen, dass der Host wieder da ist.

**Voraussetzungen:** ein Ergebnis mit *reboot required* (Neustart nötig);
Ihr Sicherheitsschlüssel (Neustart ist HIGH: Benutzerverifikation).

**Schritte:**

1. *Operations → New operation* → **Reboot** (`system.reboot`), oder im
   Inventar-Diagramm Hosts auswählen → **Reboot…**.
2. Bei mehreren Hosts besser einen gestuften Rollout wählen (**Plan a
   staged reboot…**).
3. Freigeben.

**Erwartetes Ergebnis:** Nebula wartet, bis der Host eine neue Boot-ID
meldet.

**Häufige Fehler:** `host_not_returned`: der Host ist nicht innerhalb von
20 Minuten zurückgekommen. Prüfen Sie seine Konsole.

<a id="roll-out-an-operation-in-stages-canary-waves-dev--qa--prod"></a>

## Eine Operation in Stufen ausrollen (Canary, Wellen, DEV → QA → PROD)

**Ziel:** den Schaden eines fehlerhaften Updates auf wenige Hosts
begrenzen.

**Voraussetzungen:** Hosts mit gesetzter Umgebung im Inventar (für
DEV → QA → PROD).

**Schritte:**

1. Auf der Planungsseite (`/operations/new`) unter *Rollout* wählen: alle
   auf einmal (Standard), *canary first* (zuerst N Hosts allein), *in
   waves* (in Wellen von N Hosts) oder *DEV → QA → PROD*.
2. Festlegen, wie viele fehlgeschlagene und unerreichbare Hosts eine Stufe
   toleriert (ein Canary toleriert keine).
3. Freigeben. Die Stufen sind Teil dessen, was Sie freigeben; der Executor
   setzt sie durch.
4. Nach jeder Stufe: **Continue to stage N** (weiter zu Stufe N). LOW- und
   MEDIUM-Operationen können von selbst weiterlaufen, wenn Sie das gewählt
   haben. HIGH- und CRITICAL-Stufen brauchen erneut Ihren
   Sicherheitsschlüssel (Hardened-Modus: `nebula approve --stage N <digest>`).

**Erwartetes Ergebnis:** eine Stufe mit zu vielen Fehlern stoppt den
Rollout endgültig; spätere Hosts laufen nicht. **Abort rollout** (Rollout
abbrechen) stoppt alle Hosts, die noch nicht gelaufen sind.

**Häufige Fehler:** ein unerreichbarer Host kann wiederholt oder
übersprungen werden (Überspringen braucht dieselbe Freigabe wie das Öffnen
einer Stufe; Hardened-Modus: `nebula approve --skip HOST <digest>`). Ein
Neustart des Executors beendet den Rollout.

<a id="approve-on-the-machine-in-hardened-mode"></a>

## Im Hardened-Modus auf der Maschine freigeben

**Ziel:** HIGH- und CRITICAL-Operationen dort freigeben, wo der Executor
selbst zeigt, was laufen wird, nicht der Webserver.

**Voraussetzungen:** der Executor läuft mit `-hardened` (Admin-Handbuch
[6.2](../../admin/guide.md#62-executor-flags)); ein Admin-Login auf der
Nebula-Maschine.

**Schritte:**

```
nebula pending                    # lists permits waiting for approval
nebula approve <digest>           # a unique prefix is enough
```

`nebula approve` zeigt die Befunde des Safety Scanners und die ersten 40
Zeilen des Skripts (höchstens 4 KiB), bevor Sie bestätigen. Stapel
(Batches): `nebula batch review DIGEST`, dann `nebula batch approve DIGEST`.

**Erwartetes Ergebnis:** die Operation startet; ihre Seite zeigt den
Fortschritt.

<a id="restart-start-stop-or-reload-a-systemd-service"></a>

## Einen systemd-Dienst neu starten, starten, stoppen oder neu laden

**Ziel:** eine Unit auf einem oder mehreren Hosts bedienen.

**Voraussetzungen:** Host mit sudo eingebunden; Ihr Sicherheitsschlüssel
(diese Aktionen sind MEDIUM).

**Schritte:**

1. *Operations → New operation* → **Service status** (`service.status`,
   LOW) mit dem Unit-Namen, zum Beispiel `nginx.service`. Es zeigt die Unit
   und die letzten Journal-Zeilen.
2. **Restart service** (`service.restart`) planen, oder Start, Stopp bzw.
   Neuladen (`service.start`, `service.stop`, `service.reload`) mit
   demselben Unit-Namen, und freigeben.

**Erwartetes Ergebnis:** das Ergebnis zeigt den Zustand der Unit; prüfen
Sie ihn erneut mit *Service status*.

**Häufige Fehler:** ein Unit-Name, den es auf dem Host nicht gibt, schlägt
nur auf diesem Host fehl. Ohne sudo (`--no-sudo` bei der Einbindung)
funktionieren nur die lesenden Dienst-Aktionen.

<a id="run-read-only-checks-on-a-schedule-read-lease"></a>

## Lesende Prüfungen nach Zeitplan ausführen (Read Lease)

**Ziel:** *Check updates*, *List services* und ähnliche Lesezugriffe
laufen von selbst alle 15 Minuten.

**Voraussetzungen:** die Aktionen sind vertrauenswürdige eingebaute
Aktionen mit Einstufung LOW, und jeder gewählte Host hat einen
Kritikalitätseintrag auf dem Executor (`nebula host pin
--criticality` oder `nebula host criticality`). Sonst lehnt der Executor
die Lease ab.

**Schritte:**

1. *Operations → Read leases → New read lease* (`/leases/new`).
2. Den Umfang wählen (alle Hosts, ein Tag oder eine Umgebung), die
   lesenden Aktionen (zum Beispiel `package.list_updates`, `service.list`,
   `docker.list`) und 7 oder 30 Tage.
3. Mit Ihrem Sicherheitsschlüssel freigeben. Hardened-Modus:
   `nebula read-grant pending`, dann `nebula read-grant approve <digest>`
   mit dem **vollständigen** Digest aus 64 Hex-Zeichen.

**Erwartetes Ergebnis:** Ergebnisse erscheinen als Operationen, die von
"schedule" angelegt wurden. Jeder Host läuft standardmäßig höchstens
24-mal pro gleitender Stunde.

**Verwaltung:** *Refresh* bei einer Lease schlägt eine neue Lease mit
demselben Umfang vor (sie braucht eine neue Freigabe). *Revoke* auf der
Lease-Seite oder `nebula read-grant revoke <id>` stoppt sie sofort.
Solange der Executor gesperrt ist, läuft nichts; verpasste Läufe werden
nicht nachgeholt. Details: Admin-Handbuch
[9.4](../../admin/guide.md#94-read-leases-and-scheduled-checks).

**Häufige Fehler:** "A schedule is refused" (ein Zeitplan wird
abgelehnt): eine Aktion ist nicht auf jedem Host LOW. Vertrauen Sie der
eingebauten Aktion und tragen Sie die Kritikalität des Hosts ein.
`package.refresh`, `docker.logs` und Aktionen mit Secrets können nie per
Lease laufen.

<a id="write-and-run-your-own-runbook"></a>

## Ein eigenes Runbook schreiben und ausführen

**Ziel:** ein eigenes POSIX-`sh`-Skript mit typisierten Parametern auf
Hosts ausführen.

**Voraussetzungen:** angemeldet; für das Vertrauen auf der Maschine ein
Admin-Login.

**Schritte:**

1. *Runbooks → New runbook* (`/runbooks/new`).
2. Einen Namen vergeben (die Aktion heißt dann `runbook.<name>`), ein
   erklärtes Risiko, ein Timeout, attached oder durable, und Parameter
   (`name`, `int`, `path` oder `choice`). Das Skript liest sie als
   `$NEBULA_P_<NAME>`.
3. Speichern. Jedes Speichern erzeugt eine neue, unveränderliche Version.
4. Der Version vertrauen, sonst braucht jeder Lauf einen
   Sicherheitsschlüssel mit Benutzerverifikation (HIGH): das Skript auf
   seiner Seite herunterladen, lesen und den dort angezeigten Befehl
   `nebula artifact trust …` ausführen; oder auf der Runbook-Seite *Trust
   this version* (dieser Version vertrauen) mit Ihrem Sicherheitsschlüssel
   verwenden (nur im Standardmodus).
5. Wie jede Operation planen (*Plan operation* auf der Runbook-Seite).

**Erwartetes Ergebnis:** die Ausgabe erscheint im Operations-Log.

**Häufige Fehler:** ein Skript, das `sh -n` nicht besteht oder Steuer-
bzw. unsichtbare Formatierungszeichen enthält, wird beim Speichern
abgelehnt. Ein attached-Lauf ist auf 10 Minuten begrenzt; nehmen Sie für
längere Arbeiten durable (bis zu 6 Stunden).

<a id="use-a-secret-in-a-runbook"></a>

## Ein Secret in einem Runbook verwenden

**Ziel:** einem Runbook ein Token oder Passwort geben, ohne dass es in
Argumenten oder Logs auftaucht.

**Voraussetzungen:** Vault initialisiert (`nebula vault init`) und
entsperrt; für attached-Läufe `$XDG_RUNTIME_DIR` (ein tmpfs) für den
SSH-Benutzer auf dem Host.

**Schritte:**

1. Auf der Nebula-Maschine: `nebula secret set influx-token`. Der Wert
   kommt vom Terminal oder von stdin, nie aus einem Argument.
2. Im Runbook einen Secret-Slot deklarieren, zum Beispiel `influx_token`.
3. Beim Planen der Operation das Vault-Secret für den Slot angeben.
4. Das Skript liest den Wert aus der Datei, die
   `$NEBULA_SECRET_INFLUX_TOKEN` nennt.

**Erwartetes Ergebnis:** der Lauf sieht den Wert; bekannte Secret-Werte
werden aus seinem Log und Ergebnis entfernt. `nebula secret list` zeigt
IDs und Versionen, nie Werte. `nebula secret rm ID` löscht eines.

**Häufige Fehler:** `vault_locked`: `nebula unlock` ausführen.
`secret_unavailable: no vault secret …`: `nebula secret list` prüfen. Ein
Lauf mit Secrets ist mindestens MEDIUM und kann nicht nach Zeitplan
laufen.
