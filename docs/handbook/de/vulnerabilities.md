# Schwachstellen

Nebula speichert Schwachstellen-Befunde und zeigt sie an; den Abgleich
übernimmt ein externer Agent, **Hermes**. Referenz: Admin-Handbuch
[10.4](../../admin/guide.md#104-vulnerability-management-hermes) und
[ADR 0011](../../adr/0011-vulnerability-management.md).

Nebula selbst lädt keine CVE-Feeds, gleicht keine Pakete ab und betreibt
kein LLM. Hermes läuft auf einer eigenen VM, liest einen Inventar-Export
von Nebula und schickt Befunde zurück. Befunde sind **nur Hinweise**:
nichts in diesem Kapitel schlägt jemals eine Änderung vor, plant sie oder
gibt sie frei. Jede Behebung läuft über den normalen Operations-Ablauf
([Patchen und Dienste](patching-and-services.md)).

<a id="what-works-in-this-release"></a>

## Was in diesem Release funktioniert

| Teil | Status |
| --- | --- |
| Agent-API (Inventar-Export, Runs, Befunde, Abschluss), Befundspeicher, Seiten unter *Vulnerabilities*, Benachrichtigungen, Export | Verfügbar |
| Inhalt des Inventar-Exports | **Geplant:** der Export ist noch leer (Snapshot-ID `nos-empty-<unix time>`, keine Subjekte), daher lehnt Nebula jeden Befund mit "subject not in the run's inventory snapshot" ab. Runs werden abgeschlossen, aber noch wird nichts gespeichert oder geschlossen |
| Schließen von Befunden anhand der eigenen Paketdaten von NOS | **Geplant:** Schließungen, die ein Run verlangt, werden stattdessen für einen Admin zurückgehalten |
| Maintainer-Entscheidungen (Risiko akzeptieren, False Positive, eine zurückgehaltene Schließung bestätigen oder verwerfen, eine Feed-Markierung zurücksetzen) | **Geplant:** die Formulare werden angezeigt, das Absenden schlägt aber mit "vulnerability decisions need an executor-verified security key assertion, which this executor does not offer" fehl |
| Priorität mit tatsächlicher Exposition und Host-Kritikalität | **Geplant:** die Stufe `vu-prio-v1` verwendet die Exposition "unknown" und die Kritikalität "unset" (zählt als HIGH) |
| Befunde zu Geräten, Hermes-Erläuterungen zu Angriffspfaden | Nicht verfügbar; Erläuterungen sind nicht geplant |

<a id="set-up-the-hermes-agent-token"></a>

## Das Token für den Hermes-Agenten einrichten

**Ziel:** Hermes kann den Inventar-Export lesen und Befunde schreiben,
sonst nichts.

**Voraussetzungen:** Root auf der Nebula-Maschine (um `server.json` zu
bearbeiten); die Adresse der Hermes-VM.

**Schritte:**

1. Das Token erzeugen:

   ```
   nebula-server -api-token hermes-vuln:vuln.inventory.read,vuln.findings.write
   ```

   Der Befehl gibt das Token einmalig und einen JSON-Eintrag aus. (Der
   Hilfetext von `-api-token` nennt nur die lesenden Scopes; die beiden
   Schwachstellen-Scopes werden trotzdem akzeptiert.)
2. Den Eintrag in `/etc/nebula/server.json` unter
   `"api": {"enabled": true, "tokens": [ ... ]}` ergänzen und die Adresse
   der Hermes-VM eintragen:

   ```json
   {"name": "hermes-vuln", "sha256": "<printed hash>",
    "scopes": ["vuln.inventory.read", "vuln.findings.write"],
    "source_addresses": ["<address or prefix of the Hermes VM>"]}
   ```

3. `sudo systemctl restart nebula-server`.
4. Das Token an Hermes übergeben (dessen Konfiguration liegt außerhalb
   dieses Repositorys).

**Erwartetes Ergebnis:** `nebula-server` startet; Anfragen von Hermes an
`/api/v1/vuln/inventory` werden mit `200` beantwortet.

**Häufige Fehler:**

- Der Server startet nicht: nur **ein** Token darf die
  Schwachstellen-Scopes haben, es darf **keinen anderen** Scope haben, und
  `source_addresses` (höchstens 16, keine Host-Bits in Präfixen) ist nur
  bei diesem Token erlaubt.
- `401`: falsches Token. `403`: falsche Quelladresse oder fehlender Scope.
  Jede Ablehnung ist eine `audit`-Zeile in `journalctl -u nebula-server`.
- `source_addresses` prüft die TCP-Gegenadresse. Geht Hermes über den
  Reverse Proxy, ist das die Adresse des Proxys, und damit wird jeder
  zugelassen, der den Proxy erreicht. Lassen Sie Hermes direkt mit
  `nebula-server` verbinden, wenn die Allowlist etwas bedeuten soll.

Um das Token zu widerrufen, entfernen Sie den Eintrag und starten
`nebula-server` neu.

<a id="find-the-findings-for-a-host-image-or-cve"></a>

## Die Befunde zu einem Host, Image oder CVE finden

**Ziel:** sehen, was offen ist, wo, und wie dringend.

**Voraussetzungen:** angemeldet (die Seiten stehen jedem angemeldeten
Benutzer offen).

**Schritte:**

1. *Vulnerabilities* (`/vulnerabilities`): Befunde nach CVE oder nach
   Subjekt. Filter nach Stufe (tier), KEV, Zustand, Subjektart und stale
   (veraltet).
2. Ein CVE anklicken (`/vulnerabilities/cve/<id>`) für alle betroffenen
   Subjekte, oder ein Subjekt (`/vulnerabilities/subject/<kind>/<id>`) für
   dessen Befunde.
3. Einen Befund öffnen (`/vulnerabilities/f/<key>`) für Details,
   zurückgehaltene Schließungen und die Hermes-Bewertung, beschriftet mit
   "Hermes assessment (LLM, unverified)" (Hermes-Bewertung, LLM, nicht
   geprüft).

**Erwartetes Ergebnis:** eine Liste mit höchstens 5.000 Zeilen pro Seite
(ein größeres Ergebnis wird als gekürzt markiert).

**Beheben:** nutzen Sie den Link "Fix with" (beheben mit) des Befunds. Er
öffnet das Update des Betriebssystempakets oder das Container-Update
vorausgefüllt und sendet nie etwas ab. "update available, fix not
verified" (Update verfügbar, Behebung nicht geprüft) heißt, dass die
Quellversion des Kandidaten unter der behobenen Version liegt.
Kernel-Befunde sagen außerdem, dass ein Neustart nötig ist.

<a id="understand-finding-states-and-labels"></a>

## Zustände und Beschriftungen von Befunden verstehen

**Ziel:** den Zustand eines Befunds richtig lesen.

| Sie sehen | Bedeutung |
| --- | --- |
| `open` | Von einem Hermes-Run gemeldet (neu oder wieder geöffnet). Der Standardfilter |
| fixed (confirmed by NOS inventory) | Geschlossen, weil die eigenen Daten von NOS die Behebung zeigen |
| fixed (subject removed) | Der Host oder das Image ist weg |
| fixed (confirmed by admin) | Ein Maintainer hat eine zurückgehaltene Schließung bestätigt |
| **closed by Hermes, not confirmed by NOS** | Hermes hat ihn als behoben gemeldet, NOS konnte das aber nicht aus eigenen Daten bestätigen. Er hat einen eigenen Filter und wird nie als sauber angezeigt |
| `accepted_risk` | Ein Maintainer hat das Risiko mit Begründung akzeptiert; läuft standardmäßig nach 90 Tagen ab, höchstens nach 365; wird bei Ablauf, KEV-Aufnahme oder Versionswechsel wieder geöffnet |
| `false_positive` | Ein Maintainer hat ihn mit Kategorie und Begründung markiert; wird wieder geöffnet, wenn sich die installierte Version ändert |
| stale since … | Kein vollständiger Run hat das Subjekt in 48 Stunden abgedeckt. Wird nie als "0 findings" angezeigt |
| not assessed | Noch kein vollständiger Run hat das Subjekt abgedeckt |
| feed `<source>` stale | Ein Feed ist älter als sein Höchstalter; Runs schließen keine Befunde, die auf ihm beruhen |

**Zurückgehaltene Schließungen:** Nebula hält eine Schließung für einen
Admin zurück, statt sie anzuwenden, wenn die eigenen Daten von NOS ihr
widersprechen, der Befund in dieser Episode KEV-gelistet oder kritisch
war, er auf einem Feed auf Bewährung beruht oder sie zu viele Befunde auf
einmal schließen würde. Zurückgehaltene Befunde bleiben `open`.

<a id="mark-crown-jewels-and-entry-points"></a>

## Kronjuwelen und Einstiegspunkte markieren

**Ziel:** Nebula mitteilen, welche Systeme am wichtigsten sind und welche
Einstiegspunkte sind (Internet, NetBird), für die Priorisierung.

**Voraussetzungen:** Admin.

**Schritte:** `/vuln/jewels` öffnen, ein Subjekt und eine Rolle wählen,
das vorgeschlagene Gewicht (1 bis 10) bestätigen oder ändern und
speichern. **Unmark** (Markierung entfernen) nimmt es wieder heraus.

**Erwartetes Ergebnis:** die Seite listet die markierten Kronjuwelen und
Einstiegsklassen; jede Änderung wird protokolliert.

**Hinweis:** vorgeschlagene Gewichte sind nur vorausgefüllt; ohne Ihre
Bestätigung wird nichts angewendet. Exposition und Host-Kritikalität sind
noch nicht mit der Prioritätsstufe verbunden (siehe *Was in diesem Release
funktioniert*).

<a id="get-notified-about-kev-and-critical-findings"></a>

## Über KEV- und kritische Befunde benachrichtigt werden

**Ziel:** eine Nachricht, wenn ein Befund KEV-gelistet oder kritisch wird
oder Hermes keine Meldungen mehr schickt.

**Voraussetzungen:** Benachrichtigungen in `server.json` konfiguriert
(Admin-Handbuch [10.1](../../admin/guide.md#101-notifications)); das
Schwachstellen-Token eingerichtet.

**Schritte:** nichts weiter. Die Anbieter testen Sie mit
`nebula-server -config /etc/nebula/server.json -notify-test`.

**Erwartetes Ergebnis:** Ereignisse `vuln.kev_new`, `vuln.critical_new`,
`vuln.hermes_stale` (kein vollständiger Run seit 48 Stunden),
`vuln.feed_stale`, `vuln.feed_regressed`; höchstens 10 Nachrichten pro
Stunde, der Rest in einem stündlichen `vuln.digest`. Nachrichten enthalten
CVE-ID, Subjekt, Stufe und KEV-Kennzeichen, nie die LLM-Bewertung.

<a id="export-all-findings"></a>

## Alle Befunde exportieren

**Ziel:** eine CSV- oder JSON-Datei mit allen Befunden.

**Voraussetzungen:** Admin mit offener privilegierter Sitzung.

**Schritte:** `/vulnerabilities/export?format=csv` (Standard) oder
`/vulnerabilities/export?format=json` öffnen.

**Erwartetes Ergebnis:** ein Download mit Schlüssel, Subjekt, Zustand,
Versionen, Stufe, CVSS, KEV, Daten und einem Advisory-Link. Kein
Bewertungstext, keine Admin-Begründungen, Host-Beschriftungen oder
Adressen. Mehr als 200.000 Befunde werden abgelehnt, nie teilweise
exportiert. Zellen, die mit `=`, `+`, `-`, `@`, einem Tabulator oder einem
Wagenrücklauf beginnen, bekommen ein vorangestelltes `'`.

**Häufige Fehler:** der Export wird ohne privilegierte Sitzung abgelehnt,
oder wenn der Audit-Eintrag nicht geschrieben werden kann
(`vuln.export_refused`).

<a id="check-a-container-image-with-host-trivy"></a>

## Ein Container-Image mit Trivy auf dem Host prüfen

**Ziel:** ein schneller Image-Scan ohne Hermes.

**Voraussetzungen:** Trivy, von Ihnen auf dem Host installiert.

**Schritte:** die Leseaktion `image.vulnerabilities` auf dem Host
ausführen.

**Erwartetes Ergebnis:** das Image-Badge im Organigramm zeigt das
Ergebnis, beschriftet mit "host Trivy, partial" (Trivy auf dem Host,
unvollständig). Wenn ein frischer vollständiger Hermes-Run das Image
abdeckt, zeigt das Badge stattdessen den Hermes-Status. Beides wird nie
zusammengeführt.
