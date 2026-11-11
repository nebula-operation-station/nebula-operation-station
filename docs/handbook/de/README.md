# Betriebshandbuch

Aufgabenorientierte Anleitungen für den Betrieb von Nebula Operation Station
(NOS), dazu eine FAQ. Jede Seite beantwortet Fragen der Art „Wie mache ich …“;
jeder `##`-Abschnitt ist eine Aufgabe und ist für sich allein lesbar. Er
nennt das Ziel, die Voraussetzungen, die Schritte mit dem genauen Befehl oder
UI-Pfad, das erwartete Ergebnis und die Fehler, die dabei häufig auftreten.

Das Handbuch wiederholt nicht das Referenzmaterial. Flags, Dateirechte,
Konfigurationsschlüssel und die vollständige Fehlertabelle stehen im
[Installations- und Betriebsleitfaden](../../admin/guide.md) (im Folgenden
„Admin-Leitfaden“). Die Anleitungen verlinken auf den genauen Abschnitt.

<a id="chapters"></a>

## Kapitel

| Kapitel | Aufgaben |
| --- | --- |
| [Erste Schritte](getting-started.md) | Installieren, SSH-Schlüssel erzeugen, entsperren, erste Anmeldung, YubiKey registrieren, TOTP-Wiederherstellung einrichten, sperren |
| [Hosts](hosts.md) | Host hinzufügen, CSV importieren, Enrollment-Skript ausführen, Host-Schlüssel pinnen, Anmeldung testen, Kritikalität setzen, geänderten Host-Schlüssel behandeln, Host freigeben |
| [Patchen und Dienste](patching-and-services.md) | Updates prüfen und installieren, neu starten, Rollouts in Stufen, Dienst neu starten, geplante Prüfungen, Runbooks mit Secrets |
| [Container](containers.md) | Container und Logs anzeigen, Image-Updates prüfen, Compose-Projekt aktualisieren, Container-Updates mit Rollback |
| [Proxmox VE](proxmox.md) | Read-only-Token erstellen, Remote hinzufügen, Read Lease genehmigen, Live-Werte, Gäste mit Hosts verknüpfen, Token rotieren |
| [Netzwerk](network.md) | IPAM-Netze und Assets, Discovery-Scans, die Traffic-Map, einen Cisco-CBS-Switch oder eine PAN-OS-Firewall mit einem `nos-read`-Konto registrieren |
| [Schwachstellen](vulnerabilities.md) | Hermes-Agent-Token einrichten, die Findings-Seiten lesen, Zustände und Labels verstehen, Findings exportieren |
| [Backup und Wiederherstellung](backup-restore.md) | Backup-Schlüssel erstellen, sichern, wiederherstellen, Container-Volumes, sicher upgraden |
| [Fehlerbehebung](troubleshooting.md) | Lösungen für die häufigsten Probleme, geordnet nach Symptom |
| [FAQ](faq.md) | Kurze Antworten auf häufige Fragen |

<a id="conventions"></a>

## Konventionen

- `nebula …`-Befehle laufen auf der **Nebula-Maschine** als **Admin-Benutzer**
  (ein Login, der in `-admin-users` des Executors steht und Mitglied der
  Gruppe `nebula-rpc` ist), nicht als root. Ausnahmen sind `nebula backup`
  und `nebula restore`: Sie laufen über `sudo` aus einem Admin-Login.
- Bei einer Container-Installation stellen Sie jedem `nebula …`-Befehl
  `docker compose exec -u nebula-admin executor` voran (Admin-Leitfaden
  [3.3](../../admin/guide.md#33-in-containers)).
- UI-Pfade stehen als **Menü → Seite → Schaltfläche**; wo es hilft, steht der
  URL-Pfad in Klammern, zum Beispiel *Inventory → Enroll hosts*
  (`/inventory/enroll`). Die Oberfläche ist englisch, daher bleiben die
  Bezeichnungen englisch.
- `<rp-id>` ist Ihr Nebula-Hostname, zum Beispiel `nebula.lab.example.org`.
- **Geplant** kennzeichnet etwas, das in diesem Release nicht enthalten ist;
  das zuständige ADR oder der Plan wird genannt. Suchen Sie es noch nicht in
  der Oberfläche.
- Maßgeblich ist die englische Fassung in [`../`](../README.md), falls die
  beiden Fassungen voneinander abweichen; die Überschriften tragen die
  englischen Anker, damit Links in beiden Sprachen gleich funktionieren.

<a id="using-these-pages-as-a-knowledge-base"></a>

## Diese Seiten als Wissensbasis nutzen

Die Seiten sind so geschrieben, dass man sie an den `##`-Überschriften
aufteilen kann. Jeder Abschnitt nennt seine eigenen Voraussetzungen und
Links. So ergibt er auch dann Sinn, wenn ein Leser (oder ein
Hilfe-Assistent) nur diesen Teil sieht. Behalten Sie das beim Bearbeiten
bei: eine Aufgabe pro `##`-Abschnitt, kein „wie oben beschrieben“.
