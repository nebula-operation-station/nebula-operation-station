# Erste Schritte

Von einer leeren Maschine bis zur ersten Anmeldung mit einem
Sicherheitsschlüssel. Referenz: Admin-Leitfaden Abschnitte
[2](../../admin/guide.md#2-planning) bis
[5](../../admin/guide.md#5-first-login-and-security-keys).

<a id="install-nebula-on-a-fresh-machine"></a>

## Nebula auf einer frischen Maschine installieren

**Ziel:** Die drei Dienste (`nebula-executor`, `nebula-server`,
`nebula-discovery`) laufen auf einer eigenen Maschine.

**Voraussetzungen:**

- Eine kleine VM oder ein Host mit Debian 12 (Ubuntu 22.04/24.04 geht auch),
  der für nichts anderes genutzt wird.
- Ein normaler Login pro Admin (nicht root), zum Beispiel `alice`.
- Der kleingeschriebene Hostname, unter dem die Oberfläche erreichbar sein
  wird, die WebAuthn-*RP ID*, zum Beispiel `nebula.lab.example.org`. Sie
  lässt sich später nicht ändern, ohne jeden Sicherheitsschlüssel neu zu
  registrieren.

**Schritte (Release-Tarball):**

1. Laden Sie `nebula_<version>_linux_<arch>.tar.gz` und
   `nebula_<version>_checksums.txt` aus dem Release herunter.
2. Prüfen und entpacken:

   ```
   sha256sum --ignore-missing -c nebula_<version>_checksums.txt
   mkdir nebula && tar -xzf nebula_<version>_linux_amd64.tar.gz -C nebula
   cd nebula
   ```

3. Installieren, mit Ihren Admin-Benutzern und der RP ID:

   ```
   sudo ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org
   ```

   Um vorher zu sehen, was das Skript tun würde:
   `NEBULA_INSTALL_DRY_RUN=1 ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org`.
4. Für die Netzwerk-Discovery zusätzlich `sudo apt install nmap`.
5. **Melden Sie sich ab und wieder an**, damit Ihr Login die Gruppe
   `nebula-rpc` erhält.

Andere Wege: das Debian-Paket (`sudo apt install nebula-operation-station`,
danach `sudo /usr/share/nebula/deploy/install.sh --from-package --admin-users alice --rp-id nebula.lab.example.org`)
und Container (`deploy/container/compose.yaml`). Für ein Lab ist
[`deploy/quickstart/`](../../../deploy/quickstart/README.md) der schnellste
Weg. Details: Admin-Leitfaden [3.1 bis 3.3](../../admin/guide.md#3-installation).

**Erwartetes Ergebnis:** `nebula status` antwortet und zeigt `unlocked: false`.

**Häufige Fehler:**

- `permission denied` am Socket oder `peercred: peer UID holds no role`:
  Sie haben sich nicht ab- und wieder angemeldet, oder Ihr Login steht nicht
  in `--admin-users`. Prüfen Sie das mit `id`.
- Der Installer lehnt root oder einen Nebula-Systembenutzer als Admin ab:
  Wählen Sie einen normalen Login.

<a id="create-the-ssh-key-nebula-uses-for-managed-hosts"></a>

## Den SSH-Schlüssel erzeugen, den Nebula für verwaltete Hosts nutzt

**Ziel:** Der Executor hat einen passphrasegeschützten Schlüssel, mit dem er
sich an Ihren Hosts anmeldet.

**Voraussetzungen:** Nebula ist installiert; eine lange Passphrase liegt in
Ihrem Passwortmanager (alle Schlüsseldateien nutzen dieselbe).

**Schritte:**

```
sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \
  -f /var/lib/nebula/executor/keys/nebula-default.key
```

Geben Sie die Passphrase ein, wenn Sie danach gefragt werden. Lassen Sie sie
nicht leer.

Bei einer Container-Installation erzeugen Sie den Schlüssel auf dem
Docker-Host und kopieren ihn in das Executor-Volume, wie im Admin-Leitfaden
[3.3, Schritt 4](../../admin/guide.md#33-in-containers) gezeigt.

**Erwartetes Ergebnis:** `/var/lib/nebula/executor/keys/nebula-default.key`
existiert, gehört `nebula-executor` und hat die Rechte 0600.

**Häufige Fehler:** `keyring: … is not passphrase-protected`, `has mode …`
oder `is owned by uid …` beim Entsperren: Der Schlüssel muss im
OpenSSH-Format mit Passphrase vorliegen, Rechte 0600 haben und dem
Executor-Benutzer gehören. Einen alten PEM-Schlüssel wandeln Sie mit
`ssh-keygen -p -o -f FILE` um. Siehe Admin-Leitfaden
[3.4](../../admin/guide.md#34-the-ssh-key-for-managed-hosts).

<a id="unlock-the-executor"></a>

## Den Executor entsperren

**Ziel:** Der Executor entschlüsselt die SSH-Schlüssel (und den Vault) in den
Arbeitsspeicher, damit Operationen laufen können.

**Voraussetzungen:** ein Admin-Login auf der Nebula-Maschine mit Terminal
(die Passphrase wird nie aus einer Pipe gelesen).

**Schritte:**

```
nebula status
nebula unlock
```

`nebula unlock` fragt nach der Passphrase des Schlüssels.

**Erwartetes Ergebnis:** `nebula status` zeigt `unlocked: true` und listet
die geladenen Zugangsdaten auf, zum Beispiel `credentials: nebula-default`.

**Häufige Fehler:**

- `nebula: this needs a terminal`: Führen Sie den Befehl in einer
  interaktiven Shell aus; im Container nutzen Sie `docker compose exec` ohne
  `-T`.
- Eine falsche Passphrase oder eine Schlüsseldatei mit einer anderen
  Passphrase: Das Entsperren schlägt als Ganzes fehl. Alle Schlüsseldateien
  müssen dieselbe Passphrase haben.

**Wann:** nach **jedem** Neustart des Executors (Reboot, Upgrade, Absturz).
Er startet immer gesperrt, und nichts läuft, bis ein Admin ihn auf der
Maschine entsperrt. Keine Browser-Sitzung kann ihn entsperren. Siehe
Admin-Leitfaden [11.1](../../admin/guide.md#111-locking-unlocking-and-restarting).

<a id="set-up-the-vault-and-note-the-event-key"></a>

## Den Vault einrichten und den Event-Schlüssel notieren

**Ziel:** Es gibt einen Vault für Runbook-Secrets, und Sie haben den
Fingerabdruck des Event-Schlüssels des Executors außerhalb der Maschine
gespeichert.

**Voraussetzungen:** Executor entsperrt.

**Schritte:**

```
nebula vault init      # optional; passphrase of at least 32 characters
nebula vault status
nebula events key      # copy the fingerprint to your password manager
```

**Erwartetes Ergebnis:** `nebula vault status` meldet den Vault, und Sie
haben den Fingerabdruck des Event-Schlüssels notiert. Vergleichen Sie ihn ab
und zu mit der Seite *History* (`/history`, Verlauf).

<a id="put-a-reverse-proxy-with-tls-in-front"></a>

## Einen Reverse Proxy mit TLS vorschalten

**Ziel:** Die Oberfläche ist als `https://<rp-id>` erreichbar.

**Voraussetzungen:** ein Zertifikat für `<rp-id>` (Caddy kann selbst eines
beziehen).

**Schritte (Caddy):**

```
nebula.lab.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

Der Proxy muss die Header `Host` und `Origin` unverändert durchreichen.
Machen Sie Port 8080 selbst nie von außen erreichbar. Ein nginx-Beispiel
steht im Admin-Leitfaden [4](../../admin/guide.md#4-reverse-proxy-and-tls).

**Erwartetes Ergebnis:** `https://<rp-id>/login` lädt im Browser.

**Häufige Fehler:** Anmeldung oder Freigaben schlagen im Browser fehl, wenn
Sie eine andere Adresse als genau `https://<rp-id>` verwenden oder wenn der
Proxy `Host`/`Origin` umschreibt. `public_origin` in
`/etc/nebula/server.json` muss `https://<rp-id>` sein.

<a id="log-in-for-the-first-time-and-register-your-first-security-key"></a>

## Erste Anmeldung und ersten Sicherheitsschlüssel registrieren

**Ziel:** Sie können sich mit einem FIDO2-Sicherheitsschlüssel (zum Beispiel
einem YubiKey) an der Weboberfläche anmelden.

**Voraussetzungen:** Executor läuft; Reverse Proxy ist eingerichtet; ein
Sicherheitsschlüssel mit gesetzter PIN.

**Schritte:**

1. Auf der Nebula-Maschine: `nebula webauthn code`. Der Befehl gibt einen
   Einmalcode aus, der 15 Minuten gültig ist und einmal benutzt werden kann.
   (`--user NAME` und `--label TEXT` sind optional.)
2. Öffnen Sie `https://<rp-id>/setup`, geben Sie den Code ein und
   registrieren Sie den Schlüssel (berühren, PIN eingeben).
3. Melden Sie sich unter `https://<rp-id>/login` an.

**Erwartetes Ergebnis:** Sie sehen das Dashboard. `nebula webauthn list`
zeigt den neuen Schlüssel.

**Häufige Fehler:** Der Code ist abgelaufen (15 Minuten) oder wurde schon
benutzt: Führen Sie `nebula webauthn code` erneut aus.

<a id="register-a-second-security-key-yubikey-or-passkey"></a>

## Einen zweiten Sicherheitsschlüssel registrieren (YubiKey oder Passkey)

**Ziel:** ein Ersatzschlüssel, damit Sie sich beim Verlust eines Schlüssels
nicht aussperren.

**Voraussetzungen:** angemeldet mit einem registrierten Schlüssel; Zugang
zur Nebula-Maschine.

**Schritte:**

1. Auf der Nebula-Maschine: `nebula webauthn code`.
2. In der Oberfläche: *Settings → Sign-in and security keys → Add a security
   key* (Einstellungen → Anmeldung und Sicherheitsschlüssel →
   Sicherheitsschlüssel hinzufügen, `/settings`). Geben Sie den Code und eine
   Bezeichnung ein (zum Beispiel `yubikey-backup`).
3. Berühren Sie den neuen Schlüssel und bestätigen Sie dann mit einem bereits
   registrierten Schlüssel.

Ein Hardware-Schlüssel (YubiKey) und ein Passkey (Touch ID, Windows Hello)
funktionieren beide.

**Erwartetes Ergebnis:** `nebula webauthn list` zeigt beide Schlüssel und
welcher Schlüssel den neuen bestätigt hat.

**Einen Schlüssel entfernen** geht nur per CLI: `nebula webauthn remove ID`.
Das sperrt den Executor (alle Permits widerrufen, offene Vorschläge
verworfen); führen Sie danach `nebula unlock` aus. Die Seite *Settings*
zeigt für jeden Schlüssel den genauen Befehl.

<a id="set-up-totp-recovery"></a>

## TOTP-Wiederherstellung einrichten

**Ziel:** ein Weg zurück, wenn alle Sicherheitsschlüssel verloren sind.

**Voraussetzungen:** eine Authenticator-App; Admin-Login auf der
Nebula-Maschine.

**Schritte:**

```
nebula totp setup            # optional: --account LABEL; asks for a code to confirm
nebula totp status
```

**Wiederherstellung, wenn alle Schlüssel verloren sind:**

1. Melden Sie sich mit dem TOTP-Code an (Wiederherstellungs-Login auf
   `/login`).
2. Nebula zwingt Sie, einen neuen Sicherheitsschlüssel zu registrieren.
3. Bestätigen Sie ihn auf der Nebula-Maschine: `nebula totp finish-recovery`.

**Erwartetes Ergebnis:** `nebula totp status` zeigt, dass TOTP eingerichtet
ist, und während einer Wiederherstellung, dass eine aussteht.
`nebula totp remove` entfernt es wieder.

<a id="open-a-privileged-session-and-lock-when-you-leave"></a>

## Eine privilegierte Sitzung öffnen und beim Gehen sperren

**Ziel:** LOW-Aktionen (etwa *Check updates*) ohne Schlüsselabfrage für jede
einzelne ausführen und die Schlüssel löschen, wenn Sie fertig sind.

**Voraussetzungen:** angemeldet; Executor entsperrt.

**Schritte:**

1. Dashboard (`/dashboard`) → **Open privileged session** (privilegierte
   Sitzung öffnen): Berühren Sie Ihren Schlüssel und geben Sie seine PIN ein.
2. Arbeiten. LOW-Aktionen laufen während der Sitzung ohne weitere Abfrage
   (standardmäßig 60 Minuten, Executor-Flag `-session-minutes`).
3. Wenn Sie gehen: Dashboard → **Lock executor** (Executor sperren) oder
   `nebula lock` auf der Maschine.

**Erwartetes Ergebnis:** Nach dem Sperren zeigt `nebula status`
`unlocked: false` und `privileged session: false`; jedes Permit ist
widerrufen.

**Hinweis:** `nebula lock` verwirft auch offene Vorschläge und pausiert
genehmigte Read Leases bis zum nächsten `nebula unlock`. Siehe
Admin-Leitfaden [11.1](../../admin/guide.md#111-locking-unlocking-and-restarting).

<a id="trust-the-built-in-actions-after-install-or-upgrade"></a>

## Den eingebauten Aktionen nach Installation oder Upgrade vertrauen

**Ziel:** Eingebaute Aktionen (Updates prüfen, Updates installieren, Docker,
…) laufen mit ihrem deklarierten Risiko statt mit mindestens HIGH.

**Voraussetzungen:** Executor entsperrt; das Release-Bundle
(`builtins.tar`, `release-manifest.json`, `release-manifest.json.sig`) Ihres
Releases liegt in `/usr/share/nebula/release`. Eine Installation aus dem
Quellcode oder per Quickstart hat keines.

**Schritte:**

```
nebula artifact trust-builtins     # as your admin user, not with sudo
nebula artifact list
```

Prüfen Sie den Diff, entscheiden Sie sich bei Nachfrage für `--pin` oder
`--retire` für alte Versionen und tippen Sie zum Bestätigen den angezeigten
Digest ein.

Ohne Release-Bundle vertrauen Sie den Aktionen stattdessen einzeln:

```
nebula-server -export-actions ~/nebula-actions-<version>
less ~/nebula-actions-<version>/*.sh
# then run the printed `nebula artifact trust ...` commands
```

**Erwartetes Ergebnis:** `nebula artifact list` listet die eingebauten
Aktionen; das Banner in der Weboberfläche meldet nicht mehr, dass ihnen nicht
vertraut wird.

**Häufige Fehler:** *No release bundle is installed on this executor host*
ist bei einer Installation aus dem Quellcode normal; nutzen Sie den Weg pro
Aktion. *Built-in trust status is unreachable* bedeutet ein unvollständiges,
gemischtes oder nicht prüfbares Bundle; das Executor-Log nennt die Ursache.
Details: Admin-Leitfaden
[8.1](../../admin/guide.md#81-the-built-in-actions) und
[8.2](../../admin/guide.md#82-trusting-the-built-ins-together-after-an-upgrade).
