// SPDX-License-Identifier: AGPL-3.0-or-later

package helpsearch

// synonym is one reviewed row of the query synonym table (ADR 0014 D2).
// A question token equal to one of From (after lower-casing and umlaut
// mapping, before or after folding) adds the terms of To to the query.
// The corpus is never rewritten. Why is the review note; a row without
// one fails TestSynonymRowsAreReviewed.
type synonym struct {
	From []string
	To   []string
	Why  string
}

// synonyms is the reviewed table. It maps German operator vocabulary
// onto the words the English handbook and admin guide use, plus a few
// English wordings that the docs spell differently. Rows name general
// vocabulary, never a single section or test question.
var synonyms = []synonym{
	{From: []string{"einrichten", "einrichtung", "konfigurieren", "konfiguration"}, To: []string{"setup", "set", "configure", "configuration", "enroll"},
		Why: "General German for set up and configure. The docs write \"set up\", \"setup\" and \"configure\" for backups, schedules and notifications, and \"enroll\" for setting up a host; all are one down-weighted group, so the topic word of the question decides which applies."},
	{From: []string{"anbinden", "aufnehmen"}, To: []string{"add", "enroll"},
		Why: "Taking a host into the lab (\"Host anbinden/aufnehmen\") is adding or enrolling it in the docs."},
	{From: []string{"benachrichtigung", "benachrichtigungen", "benachrichtigen"}, To: []string{"notification", "notify", "notified"},
		Why: "German for notification and notify."},
	{From: []string{"enroll", "enrol", "onboard", "onboarding"}, To: []string{"enroll-script"},
		Why: "Enrolling a host is done with the `enroll-script` command; questions name the verb, sections name the command."},
	{From: []string{"verbindung", "verbinden", "connection", "connect"}, To: []string{"connect", "login", "ssh"},
		Why: "The docs describe the connection to a host as the SSH login of the nebula user."},
	{From: []string{"installieren", "installation", "installiere"}, To: []string{"install"},
		Why: "German verb and noun for install."},
	{From: []string{"deinstallieren", "entfernen", "loeschen"}, To: []string{"uninstall", "remove", "delete"},
		Why: "German for remove, delete and uninstall."},
	{From: []string{"sichern", "sicherung", "datensicherung"}, To: []string{"backup", "back"},
		Why: "German for backup; the docs write both \"backup\" and \"back up\"."},
	{From: []string{"wiederherstellen", "wiederherstellung", "zurueckspielen"}, To: []string{"restore"},
		Why: "German for restore."},
	{From: []string{"aktualisieren", "aktualisierung", "updaten"}, To: []string{"update", "upgrade"},
		Why: "German for update and upgrade."},
	{From: []string{"neustart", "neustarten", "neu-starten"}, To: []string{"reboot", "restart"},
		Why: "German for reboot and restart."},
	{From: []string{"entsperren"}, To: []string{"unlock"},
		Why: "German for unlock (executor, vault)."},
	{From: []string{"sperren"}, To: []string{"lock"},
		Why: "German for lock."},
	{From: []string{"schluessel", "hostschluessel", "host-schluessel"}, To: []string{"key"},
		Why: "German for key; host-key questions use the compound."},
	{From: []string{"sicherheitsschluessel"}, To: []string{"security", "key", "yubikey", "passkey"},
		Why: "German for security key; the docs name YubiKey and passkey."},
	{From: []string{"verloren", "verlieren", "verlust"}, To: []string{"lose", "lost"},
		Why: "German for lose and lost."},
	{From: []string{"geaendert", "aendern", "aenderung", "gewechselt"}, To: []string{"change", "changed"},
		Why: "German for change and changed."},
	{From: []string{"importieren", "import"}, To: []string{"import"},
		Why: "German verb for import."},
	{From: []string{"hinzufuegen", "anlegen"}, To: []string{"add", "create"},
		Why: "German for add and create."},
	{From: []string{"pruefen", "testen", "ueberpruefen"}, To: []string{"test", "check"},
		Why: "German for test and check."},
	{From: []string{"anmeldung", "anmelden", "einloggen"}, To: []string{"login", "log"},
		Why: "German for login; the docs write both \"login\" and \"log in\"."},
	{From: []string{"fehler", "fehlgeschlagen", "scheitert"}, To: []string{"error", "fail"},
		Why: "German for error and fail."},
	{From: []string{"netzwerk", "netz"}, To: []string{"network"},
		Why: "German for network."},
	{From: []string{"dienst", "dienste"}, To: []string{"service"},
		Why: "German for service."},
	{From: []string{"schwachstelle", "schwachstellen", "sicherheitsluecke"}, To: []string{"vulnerability", "cve", "finding"},
		Why: "German for vulnerability; the docs also speak of CVEs and findings."},
	{From: []string{"geraet", "geraete"}, To: []string{"device"},
		Why: "German for device."},
	{From: []string{"freigeben", "freigabe", "genehmigen", "genehmigung"}, To: []string{"approve", "approval"},
		Why: "German for approve and approval."},
	{From: []string{"zeitplan", "planen"}, To: []string{"schedule"},
		Why: "German for schedule."},
	{From: []string{"protokoll", "protokolle"}, To: []string{"log"},
		Why: "German for log."},
	{From: []string{"adresse", "adressen"}, To: []string{"address"},
		Why: "German for address."},
	{From: []string{"kritikalitaet"}, To: []string{"criticality"},
		Why: "German for criticality."},
	{From: []string{"festlegen", "setzen"}, To: []string{"set"},
		Why: "German for set."},
	{From: []string{"aktualisierungen", "updates", "patches", "patchen"}, To: []string{"update", "patch"},
		Why: "Updates and patching are the same task in the docs (patching chapter)."},
}
