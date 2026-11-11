# FAQ

Kurze Antworten mit einem Link auf die Anleitung oder den Abschnitt im
Admin-Handbuch, der die Details enthält. Jede Frage ist ein eigener
Abschnitt.

<a id="why-does-the-executor-ask-for-unlock-after-every-reboot"></a>

## Warum verlangt der Executor nach jedem Neustart ein Entsperren?

Der Executor hält die SSH-Schlüssel und die Vault-Secrets **nur im
Speicher**, und nur solange er entsperrt ist. Ihre Passphrase steht in keiner
Datei und in keinem Backup. Nach einem Neustart (Reboot, Upgrade, Absturz)
startet er gesperrt, und nichts läuft, bis ein Admin auf der Nebula-Maschine
`nebula unlock` ausführt. Keine Browser-Sitzung kann ihn entsperren. Das ist
Absicht: So kann ein kompromittierter Webserver die Schlüssel nicht
zurückholen. Genehmigte Lese-Leases laufen nach dem Entsperren weiter. Siehe
[Den Executor entsperren](getting-started.md#unlock-the-executor).

<a id="can-i-unlock-automatically-at-boot"></a>

## Kann ich beim Booten automatisch entsperren?

Nein. Es gibt keine Option, die Passphrase zu speichern oder über die
Weboberfläche zu entsperren. Richten Sie Benachrichtigungen ein
(Admin-Handbuch [10.1](../../admin/guide.md#101-notifications)): Sie erhalten
eine Nachricht, wenn der Executor nach einem Neustart gesperrt vorgefunden
wird.

<a id="where-are-secrets-stored"></a>

## Wo werden Secrets gespeichert?

- **SSH-Schlüssel** für verwaltete Hosts:
  `/var/lib/nebula/executor/keys/<ref>.key`, mit Ihrer Passphrase
  verschlüsselt, nur für `nebula-executor` lesbar.
- **Vault-Secrets** (Runbook-Secrets, Proxmox-Tokens, Zugangsdaten für
  Netzwerkgeräte): in der Datenbank des Executors
  `/var/lib/nebula/executor/executor.db`, verschlüsselt, nur innerhalb des
  Executors und nur im entsperrten Zustand entschlüsselt.
- **Secrets für Benachrichtigungen und Hashes der API-Tokens**:
  `/etc/nebula/server.json` (Modus 0640, `root:nebula-server`); die Datei
  speichert von jedem API-Token nur den SHA-256.
- **Passphrasen** (Schlüssel, Vault) und die **age-Backup-Identität**:
  nirgends auf der Nebula-Maschine. Bewahren Sie sie in Ihrem
  Passwortmanager auf.

Der Webserver hält keine Schlüssel. Siehe Admin-Handbuch
[17.1](../../admin/guide.md#171-users-files-and-directories).

<a id="do-backups-contain-my-secrets"></a>

## Enthalten Backups meine Secrets?

Sie enthalten die Datenbank des Executors und die SSH-Schlüsseldateien,
**weiterhin verschlüsselt** mit ihrer Passphrase, und darum das
age-verschlüsselte Archiv. Sie enthalten nie die Passphrasen,
entschlüsselte Schlüssel, Secrets im Klartext oder den Event-Schlüssel. Siehe
[Nebula sichern](backup-restore.md#back-up-nebula).

<a id="how-do-i-enroll-a-host-behind-netbird"></a>

## Wie nehme ich einen Host hinter NetBird auf?

Machen Sie die Nebula-Maschine zu einem NetBird-Peer (außerhalb von Nebula).
Erzeugen Sie dann das Enrollment-Skript mit **beiden** Quelladressen, LAN
und NetBird, zum Beispiel
`nebula host enroll-script --from 192.168.0.10,100.64.0.10`. Geben Sie dem
Host seine LAN- und NetBird-Endpunkte in der bevorzugten Reihenfolge und
pinnen Sie mit allen:
`nebula host pin --criticality MEDIUM web-01 192.168.0.21 100.64.0.21`.
Bei einem TCP-Fehler weicht Nebula auf den nächsten Endpunkt aus. Siehe
[Einen Host über ein VPN aufnehmen](hosts.md#enroll-a-host-reachable-over-a-vpn-netbird-wireguard-tailscale).

<a id="why-does-a-vpn-host-fail-to-log-in-although-the-lan-works"></a>

## Warum scheitert die Anmeldung an einem VPN-Host, obwohl das LAN funktioniert?

Die Schlüsselzeile auf dem Host trägt `from="…"` mit den Adressen, die Sie
an `--from` übergeben haben, und das sshd-Drop-in verwendet sie ebenfalls.
Fehlte die NetBird- oder WireGuard-Adresse der Nebula-Maschine, werden
Anmeldungen über das VPN abgelehnt. Führen Sie das Enrollment-Skript erneut
mit der vollständigen `--from`-Liste aus.

<a id="why-is-a-finding-closed-by-hermes-not-confirmed-by-nos"></a>

## Warum steht bei einem Fund "closed by Hermes, not confirmed by NOS"?

Hermes (der Schwachstellen-Agent) hat den Fund als behoben gemeldet, aber
Nebula konnte das aus dem eigenen Inventar nicht bestätigen. Nebula wertet
das Wort des Agenten allein nie als Beweis: Solche Funde haben einen eigenen
Filter und werden nie als sauber angezeigt. In diesem Release kann Nebula
Funde noch nicht mit den eigenen Paketdaten vergleichen. Schließungen, die
ein Lauf anfordert, werden daher meist für einen Admin **zurückgehalten**
(held). Siehe
[Zustände und Kennzeichnungen von Funden verstehen](vulnerabilities.md#understand-finding-states-and-labels).

<a id="why-are-there-no-vulnerability-findings-although-hermes-runs"></a>

## Warum gibt es keine Schwachstellen-Funde, obwohl Hermes läuft?

Der Inventar-Export ist in diesem Release noch leer (Snapshot-ID
`nos-empty-<unix time>`, keine Subjekte). Nebula lehnt deshalb jeden Fund
mit "subject not in the run's inventory snapshot" ab. Läufe werden
abgeschlossen, aber nichts wird gespeichert, bis der Export das Inventar
enthält (**Geplant**, ADR 0011). Siehe
[Schwachstellen](vulnerabilities.md#what-works-in-this-release).

<a id="can-i-accept-a-vulnerability-risk-or-mark-a-false-positive"></a>

## Kann ich ein Schwachstellen-Risiko akzeptieren oder einen Fehlalarm markieren?

Noch nicht. Die Formulare werden dem Maintainer angezeigt, aber das Absenden
scheitert mit "vulnerability decisions need an executor-verified security
key assertion, which this executor does not offer". Der Executor-Aufruf, der
einen Sicherheitsschlüssel an eine solche Entscheidung bindet, ist
**geplant** (ADR 0011).

<a id="does-nebula-install-fixes-for-vulnerabilities-by-itself"></a>

## Installiert Nebula Korrekturen für Schwachstellen selbstständig?

Nein. Funde sind nur Hinweise. Links "Fix with" (beheben mit) öffnen die
normalen Update-Formulare vorausgefüllt und senden nie ab. Jede Korrektur
braucht den üblichen Plan und die übliche Genehmigung.

<a id="why-does-even-check-updates-ask-for-my-security-key-with-pin"></a>

## Warum verlangt sogar "Check updates" meinen Sicherheitsschlüssel mit PIN?

Die Aktion gilt als HIGH, weil das eingebaute Skript noch nicht
vertrauenswürdig ist (nach Installation oder Upgrade) oder weil es für den
Host auf dem Executor keinen Eintrag zur Kritikalität gibt (Hosts ohne
Eintrag gelten als HIGH). Führen Sie `nebula artifact trust-builtins` und
`nebula host criticality HOST LEVEL` aus. Mit einer offenen privilegierten
Sitzung laufen LOW-Aktionen dann ohne Abfrage.

<a id="what-is-the-difference-between-the-inventorys-criticality-and-nebula-host-criticality"></a>

## Was ist der Unterschied zwischen der Kritikalität im Inventar und `nebula host criticality`?

Das Feld im Inventar dient nur der Anzeige. Nur der Eintrag des Executors
(gesetzt mit `nebula host pin --criticality` oder `nebula host criticality`)
entscheidet, wie stark eine Genehmigung sein muss. Der Webserver kann ihn
nicht herabsetzen.

<a id="what-do-low-medium-high-and-critical-mean-for-approvals"></a>

## Was bedeuten LOW, MEDIUM, HIGH und CRITICAL für Genehmigungen?

LOW: läuft innerhalb einer offenen privilegierten Sitzung, kann geplant
werden. MEDIUM: Sicherheitsschlüssel pro Operation. HIGH:
Sicherheitsschlüssel mit Benutzerverifikation (PIN) pro Operation und pro
Stufe. CRITICAL: wie HIGH, zusätzlich muss die Anzahl der Ziele eingetippt
werden. Im Hardened Mode werden HIGH und CRITICAL nur mit `nebula approve`
auf der Maschine genehmigt. Siehe Admin-Handbuch
[17.3](../../admin/guide.md#173-risk-classes).

<a id="what-is-hardened-mode-and-should-i-use-it"></a>

## Was ist der Hardened Mode, und sollte ich ihn verwenden?

Mit dem Executor-Flag `-hardened` werden HIGH- und CRITICAL-Operationen,
das Öffnen von Stufen, Lese-Leases und Batch-Rollouts auf der
Nebula-Maschine genehmigt (`nebula pending`, `nebula approve`,
`nebula read-grant approve`, `nebula batch approve`). Die CLI zeigt, was der
Executor wirklich ausführen wird, nicht was der Webserver behauptet.
Verwenden Sie ihn, wenn der Webserver mehr Personen zugänglich sein könnte
als nur Ihnen. Siehe Admin-Handbuch
[11](../../admin/guide.md#11-operating-securely).

<a id="what-happens-if-i-lose-my-yubikey"></a>

## Was passiert, wenn ich meinen YubiKey verliere?

Wenn Sie einen zweiten Schlüssel registriert haben: Melden Sie sich damit an
und entfernen Sie den verlorenen mit `nebula webauthn remove ID` (siehe
`nebula webauthn list`). Das sperrt den Executor; führen Sie
`nebula unlock` aus. Sind alle Schlüssel verloren: Melden Sie sich mit der
TOTP-Wiederherstellung an, registrieren Sie einen neuen Schlüssel und
bestätigen Sie auf der Maschine mit `nebula totp finish-recovery`. Deshalb
wird `nebula totp setup` empfohlen.

<a id="can-i-use-a-passkey-touch-id-windows-hello-instead-of-a-yubikey"></a>

## Kann ich statt eines YubiKeys einen Passkey (Touch ID, Windows Hello) verwenden?

Ja. Sowohl Hardware-Schlüssel als auch Passkeys funktionieren. Registrieren
Sie mindestens zwei Authentifikatoren.

<a id="can-i-change-the-hostname-rp-id-later"></a>

## Kann ich den Hostnamen (RP ID) später ändern?

Nicht, ohne jeden Sicherheitsschlüssel neu zu registrieren. Die RP ID wird
bei der Installation festgelegt (`--rp-id`); WebAuthn-Schlüssel sind an sie
gebunden. Wählen Sie sie sorgfältig.

<a id="why-does-the-ui-say-no-release-bundle-is-installed-on-this-executor-host"></a>

## Warum meldet die Oberfläche "No release bundle is installed on this executor host"?

Das Verzeichnis `/usr/share/nebula/release` enthält keinen der signierten
Release-Anhänge. Bei einer Installation aus dem Quellcode oder per
Quickstart ist das normal. Stufen Sie die eingebauten Skripte einzeln als
vertrauenswürdig ein, mit `nebula-server -export-actions DIR` und den
ausgegebenen Befehlen `nebula artifact trust …`. Siehe Admin-Handbuch
[8.2](../../admin/guide.md#82-trusting-the-built-ins-together-after-an-upgrade).

<a id="does-nebula-need-an-agent-on-managed-hosts"></a>

## Braucht Nebula einen Agenten auf den verwalteten Hosts?

Nein. Nebula meldet sich per SSH mit dem eingeschränkten Benutzer `nebula`
an, den das Enrollment-Skript anlegt. Verwaltete Hosts brauchen OpenSSH,
`sudo` und systemd.

<a id="which-operating-systems-can-nebula-manage"></a>

## Welche Betriebssysteme kann Nebula verwalten?

Debian 12, Ubuntu 22.04 und 24.04 sowie Proxmox VE (Patchen verwendet dort
`full-upgrade`). Dauerhafte Jobs (durable jobs) brauchen `sudo -n` und
systemd auf dem Host.

<a id="is-the-nebula-user-on-the-host-root"></a>

## Ist der Benutzer `nebula` auf dem Host root?

Faktisch ja, mit der Standard-sudo-Regel (NOPASSWD in
`/etc/sudoers.d/nebula`). Verwenden Sie bei der Aufnahme `--no-sudo` für
Hosts, die nur gelesen werden. Jeder Lauf ist trotzdem an ein Permit
gebunden, das Sie genehmigt haben.

<a id="what-happens-to-a-running-update-if-the-nebula-machine-restarts"></a>

## Was passiert mit einem laufenden Update, wenn die Nebula-Maschine neu startet?

Updates laufen als dauerhafte Jobs unter systemd auf dem Host. Der Executor
führt nie etwas doppelt aus: Nach dem Neustart (und `nebula unlock`) holt er
das Ergebnis ab. Ein Rollout in Stufen endet allerdings mit dem Neustart.

<a id="can-nebula-manage-dhcp-or-dns"></a>

## Kann Nebula DHCP oder DNS verwalten?

Nein. IPAM erfasst Netze, Adressen und Geräte und berechnet den Status jeder
Adresse; es ändert nie DHCP oder DNS.

<a id="why-are-some-discovered-hosts-shown-as-possible-match"></a>

## Warum werden manche gefundenen Hosts als POSSIBLE MATCH angezeigt?

Die Adresse passt zu einem Asset, aber es gibt keine MAC-Adresse zum
Vergleich. Das ist typisch für VPN- und geroutete Netze, in denen Nmap keine
MAC-Adressen sieht. Prüfen und importieren Sie von Hand.

<a id="why-does-the-traffic-map-show-no-process-names"></a>

## Warum zeigt die Verkehrskarte keine Prozessnamen?

`net.facts` führt `ss` ohne `-p` aus. So braucht es kein root und sammelt
keine Prozessnamen. Ein Bericht mit einer Prozessspalte wird als ungültig
abgelehnt, damit ein kompromittierter Host keine einschleusen kann.

<a id="can-nebula-change-vlans-or-firewall-rules-on-my-switch-or-firewall"></a>

## Kann Nebula VLANs oder Firewall-Regeln auf meinem Switch oder meiner Firewall ändern?

Nicht in diesem Release. Netzwerkgeräte lassen sich registrieren
(`nebula netdev`), und selbst das Auslesen ihrer Daten ist noch **geplant**
(ADR 0010). Änderungen sind eine spätere Phase, über die der Maintainer
entscheidet, nachdem Phase 1 gelaufen ist. Alles auf Nebulas eigenem
Management-Pfad bleibt abgelehnt.

<a id="why-does-my-cisco-cbs-switch-session-abort-with-a-login-prompt"></a>

## Warum bricht die Sitzung zu meinem Cisco-CBS-Switch mit einer Login-Abfrage ab?

Der Switch fragt innerhalb der SSH-Sitzung erneut nach `User Name:`. Nebula
beantwortet nie Abfragen. Aktivieren Sie `ip ssh password-auth`
(Passwort-Login) oder `ip ssh pubkey-auth auto-login` (Schlüssel-Login),
damit die SSH-Authentifizierung die einzige Anmeldung ist. Siehe
[Auto-Login- und Prompt-Fallen bei CBS vermeiden](network.md#avoid-cbs-auto-login-and-prompt-pitfalls).

<a id="is-a-cisco-cbs220-supported"></a>

## Wird ein Cisco CBS220 unterstützt?

Nein. Er hat keine SSH-CLI. Führen Sie ihn als IPAM-Asset.

<a id="does-nebula-change-anything-on-proxmox"></a>

## Ändert Nebula etwas an Proxmox?

Nein, nicht in diesem Release. Die Integration ist nur lesend.
Ein-/Ausschalten von Gästen, Snapshots und Provisionierung sind noch nicht
verfügbar (ADR 0006 Phase 2, ADR 0008). Siehe [Proxmox VE](proxmox.md).

<a id="why-does-the-proxmox-page-say-no-approved-read-lease"></a>

## Warum meldet die Proxmox-Seite "no approved read lease"?

Ein Remote zu registrieren reicht nicht; der Executor beantwortet
Leseanfragen des Collectors nur unter einem genehmigten Lease. Klicken Sie
auf `/pve/<id>` auf **Request read lease** (Lese-Lease anfordern) und
genehmigen Sie es. Nach einer Token-Rotation oder einem neuen Pin verwenden
Sie **Renew read lease** (Lese-Lease verlängern).

<a id="is-there-a-one-step-enrollment"></a>

## Gibt es eine Aufnahme in einem Schritt?

Kommt. Heute besteht die Aufnahme aus Skript, dann Pin, dann Test (siehe
[Hosts](hosts.md)).

<a id="how-do-i-give-home-assistant-the-host-status"></a>

## Wie gebe ich Home Assistant den Host-Status?

Erzeugen Sie ein Nur-Lese-Token mit
`nebula-server -api-token homeassistant:inventory.read`, tragen Sie den
ausgegebenen Eintrag in `server.json` unter `"api"` ein, starten Sie
`nebula-server` neu und fragen Sie `GET /api/v1/hosts/{id}` mit
`Authorization: Bearer <token>` ab. Siehe Admin-Handbuch
[10.2](../../admin/guide.md#102-read-only-api-home-assistant-status-pages).

<a id="how-do-i-check-that-nobody-rewrote-the-history"></a>

## Wie prüfe ich, dass niemand die Historie umgeschrieben hat?

Notieren Sie nach der Installation den Fingerabdruck aus
`nebula events key` außerhalb der Maschine. Führen Sie dann ab und zu
`nebula events verify` aus, vergleichen Sie den Schlüssel mit der Seite
*History* (Historie) und kopieren Sie wöchentlich
`nebula events list --json` an einen anderen Ort.
Siehe Admin-Handbuch [10.3](../../admin/guide.md#103-history-and-events).

<a id="who-can-be-an-admin-and-how-do-i-remove-one"></a>

## Wer kann Admin sein, und wie entferne ich einen?

Admins sind die Logins in den `-admin-users` des Executors (gesetzt mit
`install.sh --admin-users`). Die Mitgliedschaft in `nebula-rpc` erlaubt
einem Benutzer nur, den Socket zu erreichen. Wenn jemand geht, entfernen Sie
ihn aus beiden, starten Sie dann den Executor neu und führen Sie
`nebula unlock` aus.

<a id="how-do-i-uninstall-nebula"></a>

## Wie deinstalliere ich Nebula?

Tarball: `sudo ./deploy/uninstall.sh`; Paket:
`sudo apt remove nebula-operation-station`; Container:
`docker compose down` (mit `-v` werden alle Schlüssel und Daten gelöscht).
Daten, Benutzer und Konfiguration bleiben erhalten, bis Sie sie entfernen.
Geben Sie jeden verwalteten Host frei wie in
[Einen Host aus Nebula entfernen](hosts.md#remove-a-host-from-nebula). Siehe
Admin-Handbuch [16](../../admin/guide.md#16-uninstalling).
