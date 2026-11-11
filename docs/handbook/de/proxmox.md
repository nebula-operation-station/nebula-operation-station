# Proxmox VE

Eine reine Leseansicht Ihrer Proxmox-VE-Cluster und -Hosts: Nodes, Gäste,
Speicher, Tasks und Live-Werte. Referenz: der
[Proxmox-VE-Betreiberleitfaden](../../operator/proxmox.md) und Admin-Handbuch
[9.4, „Live values“](../../admin/guide.md#live-values-for-proxmox-nodes-and-guests).

**Was heute funktioniert:** Verwaltung von Remotes auf der Kommandozeile,
Inventarerfassung, die PVE-Seiten (`/pve`, `/pve/<id>`), Lese-Leases und
Live-Werte, das Verknüpfen von Gästen mit verwalteten Hosts,
Deploy-Profile (nur Vorlagen).

**Noch nicht verfügbar:** Bereitstellung von Gästen (die Seiten gibt es,
jeder Vorschlag wird abgelehnt; ADR 0008), Ein-/Ausschalten von Gästen und
Snapshots (die Routen antworten mit 404), Gast-Backup, Migration,
Node-Neustart und Konfigurationsänderungen (**Geplant**, ADR 0006 Phase 2).
NOS ändert heute nichts an PVE. Siehe
[What you can use today](../../operator/proxmox.md#what-you-can-use-today).

Das Patchen eines Proxmox-VE-Nodes selbst funktioniert wie bei jedem
anderen Host: Melden Sie ihn wie unter [Hosts](hosts.md) beschrieben an;
*Install all updates* (alle Updates installieren) verwendet dort
`full-upgrade`.

<a id="create-a-least-privilege-read-only-pve-token"></a>

## Ein PVE-Token mit minimalen Leserechten anlegen

**Ziel:** ein PVE-API-Token, das der Executor für Lesezugriffe akzeptiert.

**Voraussetzungen:** Root-Shell auf einem PVE-Node (oder dessen Web-Shell).

**Schritte:** Folgen Sie
[Read-only token (required)](../../operator/proxmox.md#read-only-token-required).
Kurz gesagt: vier Rollen mit je einem Audit-Recht (`Sys.Audit` auf `/`,
`VM.Audit` auf `/vms`, `Datastore.Audit` auf `/storage`, `Pool.Audit` auf
`/pool`), ein nicht interaktiver Benutzer wie `nos-read@pve` mit Ablaufdatum,
ein Token mit `--privsep 1` und Ablaufdatum sowie dieselben ACLs für den
Benutzer **und** das Token. Notieren Sie das Token-Secret; PVE zeigt es nur
einmal an.

**Erwartetes Ergebnis:** ein Token der Form `nos-read@pve!nosread1=<secret>`.

**Häufige Fehler:** Der Executor lehnt das Token ab, wenn es irgendein
anderes Recht oder einen anderen Pfad hat (`PVEAuditor` ist zu weit gefasst),
kein Ablaufdatum hat, kein `privsep` hat oder zu einem Benutzer `*@pam`,
`Administrator@*` oder `PVEVMAdmin@*` gehört.

<a id="add-a-proxmox-remote"></a>

## Ein Proxmox-Remote hinzufügen

**Ziel:** Der Executor kennt einen PVE-Cluster oder einen einzelnen Host,
gepinnt auf dessen TLS-Identität, mit dem Lese-Token in seinem Vault.

**Voraussetzungen:** das Lese-Token; Executor entsperrt (`nebula unlock`);
Admin-Login mit Terminal auf der Nebula-Maschine.

**Schritte:**

```
nebula pve remote add pve-lab --kind cluster \
  --endpoint pve1.lab:8006 --endpoint pve2.lab:8006 --name "Lab cluster"
```

Für einen einzelnen Host verwenden Sie `--kind standalone` und ein
`--endpoint`. Die Reihenfolge der `--endpoint`-Angaben ist die
Failover-Reihenfolge. `--action-token` fragt zusätzlich nach einem
Aktions-Token (das noch nichts verwendet). Für einen Cluster, dessen Nodes
nur ihr Leaf-Zertifikat ausliefern, ergänzen Sie `--ca-file pve-root-ca.pem`
(auf separatem Weg kopiert aus `/etc/pve/pve-root-ca.pem`).

1. Der Befehl prüft die Endpunkte ohne Zugangsdaten und gibt die
   Fingerprints von Leaf- und CA-Zertifikat aus.
2. Vergleichen Sie den Fingerprint auf separatem Weg (PVE-Konsole) und
   tippen Sie ihn ein.
3. Fügen Sie das Lese-Token an der Eingabeaufforderung ein (ohne Anzeige;
   niemals als Argument).

**Erwartetes Ergebnis:**
`remote pve-lab added: active, pin generation 1, read credential <ref>@1`.
`nebula pve remote list` zeigt es an.

**Häufige Fehler:** `confirmation does not match the presented trust
identity; nothing stored`: falscher Fingerprint eingegeben, erneut
ausführen. Der Befehl verweigert die Ausführung ganz: Der Vault ist
gesperrt, führen Sie `nebula unlock` aus.

<a id="approve-a-read-lease-so-data-appears"></a>

## Eine Lese-Lease freigeben, damit Daten erscheinen

**Ziel:** Der Collector darf das Remote lesen, und `/pve` füllt sich mit
Daten.

**Voraussetzungen:** Remote hinzugefügt und `active`;
`nebula-pve-collector` läuft; Ihr Sicherheitsschlüssel.

**Schritte:**

1. Öffnen Sie `/pve/<id>` → **Request read lease** (Lese-Lease anfordern)
   (oder *Operations → Read leases → New read lease* mit dem Scope
   **Proxmox remote**).
2. Behalten Sie die Standardmethoden (`nodes`, `guests`, `storage`,
   `cluster`, `tasks`). Ergänzen Sie `guest_config`, wenn Sie
   MAC-basierte Vorschläge für die Zuordnung Gast–Host wünschen;
   `guest_agent`, `snapshots` und `backups` sind optional.
3. Wählen Sie 7 oder 30 Tage, **Preview** (Vorschau), und geben Sie mit
   Ihrem Sicherheitsschlüssel frei.

**Erwartetes Ergebnis:** Innerhalb weniger Minuten erscheint das Remote auf
`/pve` mit Nodes und Gästen; der PVE-Teil des Inventardiagramms füllt sich.

**Häufige Fehler:** Datensätze `unavailable` oder `partial` und
`read_grant_does_not_cover` in `journalctl -u nebula-executor`: Keine aktive
Lease deckt Remote und Methode ab (abgelaufen, widerrufen oder durch ein
Re-Pin oder eine Token-Rotation ungültig geworden). Die Seite bietet dann
**Renew read lease** (Lese-Lease erneuern) an.
Details: [Read lease for a remote](../../operator/proxmox.md#read-lease-for-a-remote).

<a id="see-live-values-on-node-and-guest-boxes"></a>

## Live-Werte in den Node- und Gast-Kästen sehen

**Ziel:** Live-Metriken im 10-Sekunden-Takt in den PVE-Node- und
Gast-Kästen des Diagramms.

**Voraussetzungen:** eine Lese-Lease mit dem Trigger `on_demand`, die den
Kasten aufführt; `nebula-pve-collector` läuft.

**Schritte:** Fordern Sie die Live-Werte-Lease wie in
[Live values and their lease](../../operator/proxmox.md#live-values-and-their-lease)
beschrieben an und geben Sie sie frei. Lassen Sie den Kasten dann im
Browser sichtbar.

**Erwartetes Ergebnis:** Die Werte aktualisieren sich etwa alle 10 Sekunden,
solange der Kasten auf dem Bildschirm ist. Höchstens vier Live-Kästen pro
Remote.

**Häufige Fehler:** keine Werte: Prüfen Sie
`systemctl status nebula-pve-collector` und
`journalctl -u nebula-pve-collector` auf
`live leases refused` (keine Lease deckt den Kasten ab) oder
`live lease refresh` (Executor gesperrt). Die vollständige Checkliste steht
im Admin-Handbuch
[9.4](../../admin/guide.md#live-values-for-proxmox-nodes-and-guests).

<a id="link-a-proxmox-guest-to-its-managed-host"></a>

## Einen Proxmox-Gast mit seinem verwalteten Host verknüpfen

**Ziel:** Der PVE-Gast und der NOS-Host werden als dieselbe Maschine
angezeigt.

**Voraussetzungen:** Gast und Host existieren beide; für MAC-Vorschläge
enthält die Lese-Lease `guest_config` und das IPAM-Asset des Hosts hat die
MAC.

**Schritte:** Wählen Sie auf `/pve/<remote>` in der Gast-Tabelle in der
Spalte **Managed host** (verwalteter Host) den vorgeschlagenen Host
(MAC-Treffer oder POSSIBLE MATCH über die IP) und verknüpfen Sie ihn.

**Erwartetes Ergebnis:** Die Spalte zeigt die Verknüpfung, seit wann und
von wem.

**Hinweis:** Ein IP-Treffer ist nie mehr als ein möglicher Treffer, und
Konflikte (zum Beispiel eine geklonte VM mit derselben MAC) werden
angezeigt, aber nie für Sie aufgelöst. Siehe
[Linking guests to hosts](../../operator/proxmox.md#linking-guests-to-hosts).

<a id="rotate-a-pve-token"></a>

## Ein PVE-Token rotieren

**Ziel:** das Lese-Token ersetzen, bevor es abläuft.

**Voraussetzungen:** ein neues, in PVE angelegtes Token mit denselben ACLs;
Executor entsperrt.

**Schritte:**

```
nebula pve remote rotate-token pve-lab --purpose read
```

Fügen Sie das neue Token an der Eingabeaufforderung ein. Widerrufen Sie
danach das alte Token in PVE.

**Erwartetes Ergebnis:** Das neue Token wird geprüft, bevor sich etwas
ändert. Lese-Leases, die an die alte Version der Zugangsdaten gebunden
sind, werden widerrufen; fordern Sie also auf `/pve/<id>` eine neue Lease an
(**Renew read lease**).

<a id="re-pin-a-remote-after-a-certificate-change"></a>

## Ein Remote nach einem Zertifikatswechsel neu pinnen

**Ziel:** ein `blocked`-Remote nach einem Wechsel von CA oder Zertifikat
wieder in Betrieb nehmen.

**Schritte:** Prüfen Sie das neue Zertifikat auf separatem Weg, führen Sie
dann `nebula pve remote repin pve-lab` aus und tippen Sie den neuen
Fingerprint ein. Eine Verlängerung mit derselben CA braucht kein Re-Pin.

**Erwartetes Ergebnis:** Das Remote ist wieder `active`; geben Sie eine neue
Lese-Lease frei. Details:
[Re-pinning the trust identity](../../operator/proxmox.md#re-pinning-the-trust-identity).

<a id="remove-a-proxmox-remote"></a>

## Ein Proxmox-Remote entfernen

**Schritte:** `nebula pve remote remove pve-lab`. Der Befehl deaktiviert das
Remote, widerruft abhängige Leases, löscht seine Vault-Secrets und hinterlässt
einen Tombstone (Löschvermerk). Löschen Sie danach das Token in PVE.

<a id="deploy-a-new-guest-from-a-profile-planned"></a>

## Einen neuen Gast aus einem Profil bereitstellen (geplant)

**Status:** nicht verfügbar. Deploy-Profile (`/deploy`) lassen sich
speichern, und den Assistenten (`/deployments/new`) gibt es, aber jeder
Vorschlag wird mit
`the template is not prepared or changed; prepare it again` abgelehnt, weil
noch kein Release ein Template vorbereiten kann (ADR 0008). PVE wird nicht
verändert. Siehe
[Guest provisioning](../../operator/proxmox.md#guest-provisioning).
