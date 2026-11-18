# Benachrichtigungen

NOS sendet Nachrichten an einen Webhook, ntfy oder Telegram (Admin-Handbuch
[10.1](../../admin/guide.md#101-notifications)). Diese Seite erklärt, welche
Nachrichten es gibt, was geplant ist und was NOS mit einem Anbieter nie tut.
Jede Nachricht ist Klartext aus einer festen NOS-Vorlage. Keine enthält
Host-Ausgaben und keine enthält Text des LLM des Ops-Agenten.

## NOS liest nie von Telegram

NOS **sendet nur** an Telegram, ntfy und den Webhook. NOS liest nie von
einem Anbieter: Es fragt Telegram nicht nach Updates ab, hat keinen
eingehenden Webhook-Endpunkt für Nachrichten, führt keine Bot-Befehle aus
und nimmt keinen Freitext an. Die einzige Telegram-Methode, die NOS aufruft,
ist `sendMessage`.

**Folge:** Du kannst dem Telegram-Bot nicht antworten und ihm keine Befehle
schicken. Eine Nachricht des Bots ist eine Benachrichtigung; was du dort
eintippst, erreicht NOS nicht. Fragen an den Ops-Agenten werden nur in der
NOS-Weboberfläche gestellt (Tab Ops).

## Welche Nachrichten es heute gibt

Welche Nachrichten in diesem Release gesendet werden, steht im
Admin-Handbuch [10.1](../../admin/guide.md#101-notifications): ein geänderter
Host-Schlüssel, eine Änderung des Ops-Zustands, eine Operation mit
fehlgeschlagenen Hosts, ein nach dem Neustart gesperrter Executor, die
Schwachstellen-Ereignisse aus [Schwachstellen](vulnerabilities.md) und die
zwei Lease-Ereignisse unten. Der Tagesdigest ist optional und standardmäßig
aus.

Jedes Ereignis, das der Server sendet, zurückhält (Ratenlimit oder
Stummschaltung) oder nicht zustellen kann, wird mit seinem Ergebnis im
Benachrichtigungslog des Servers gespeichert. Das Log behält 30 Tage und
höchstens 5.000 Einträge.

**Nicht in diesem Release: die Benachrichtigungsliste in der Weboberfläche.**
Das Log gibt es; die Seite, die es anzeigt, ist in diesem Release nicht
enthalten. Bis sie kommt, prüfe das Log über den Verlaufsabschnitt des
Admin-Handbuchs (10.3).

## Lease-Ablauf und fehlgeschlagene Leases

Diese zwei Ereignisse werden in diesem Release gesendet. Sie brauchen weder
LLM noch Agenten.

- `lease.expiring`: Ein Read-Lease oder eine Schedule-Freigabe läuft innerhalb
  von 7 Tagen ab, und nochmals innerhalb von 1 Tag. Du bekommst eine
  Nachricht pro Freigabe und Schwelle.
- `lease.run_failed`: Ein Lease-Lauf ist fehlgeschlagen. Du bekommst eine
  Nachricht pro Freigabe, Aktion und Host, bis zum nächsten erfolgreichen
  Lauf dieser Kombination.

## Der Tagesdigest

**Status: optional, standardmäßig aus.** Ein Admin schaltet ihn in
`server.json` ein (Admin-Handbuch [10.1](../../admin/guide.md#101-notifications)).

Der Digest wird einmal am Tag zu einer Uhrzeit gesendet, die du setzt. Er
enthält nur Zähler: offene Updates, ausstehende Neustarts, Hosts, die nicht
READY sind, Freigaben, die innerhalb von 7 Tagen ablaufen, offene Befunde je
Tier und die Anzahl KEV, sowie fehlgeschlagene Ausführungen der letzten 24
Stunden. Er braucht mindestens einen Benachrichtigungsanbieter.

## Was eine Nachricht von dir verlangen kann

Eine Nachricht verlinkt in die NOS-Weboberfläche. Sie bittet nie um eine
Antwort und enthält nie einen Befehl. Um zu handeln, melde dich bei NOS an,
prüfe die verlinkte Seite und handle dort mit den üblichen Genehmigungen.
