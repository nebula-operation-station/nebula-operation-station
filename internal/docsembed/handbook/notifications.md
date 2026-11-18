# Notifications

NOS sends messages to a webhook, ntfy or Telegram (admin guide
[10.1](../admin/guide.md#101-notifications)). This page explains which
messages exist, what is planned, and what NOS never does with a provider.
Every message is plain text built by a fixed NOS template. None contains
host output, and none contains text from the LLM of the ops agent.

## NOS never reads from Telegram

NOS only **sends** to Telegram, ntfy and the webhook. It never reads from a
provider: it does not poll Telegram for updates, it has no incoming webhook
endpoint for messages, it runs no bot commands and it takes no free text.
The only Telegram method NOS calls is `sendMessage`.

**Consequence:** you cannot answer the Telegram bot or send it commands. A
message from the bot is a notification, and nothing you type there reaches
NOS. Questions to the ops agent are asked only in the NOS web UI (Ops tab).

## Which messages exist now

The messages that are sent in this release are listed in admin guide
[10.1](../admin/guide.md#101-notifications): a changed host key, an Ops
State change, an operation with failed hosts, an executor locked after a
restart, the vulnerability events of [Vulnerabilities](vulnerabilities.md)
(KEV and critical findings), and the two lease events below. The daily
digest is optional and off by default.

Every event that the server sends, holds back (rate limit or mute) or fails
to deliver is written to the server's notification log, with its outcome.
The log keeps 30 days and at most 5,000 entries.

**Not in this release: reading the log.** The log is written, but in this
release no web UI page and no CLI command reads it, so you cannot inspect it
through NOS. The admin guide's history section (10.3) covers executor events
and audit lines, not this log.

## Lease expiry and failed leased runs

These two events are sent in this release. They need no LLM and no agent.

- `lease.expiring`: a read lease or schedule grant expires within 7 days,
  and again within 1 day. You get one message per grant and threshold.
- `lease.run_failed`: a leased run failed. You get one message per grant,
  action and host, until the next successful run of that combination.

## The daily digest

**Status: optional, off by default.** An admin turns it on in `server.json`
(admin guide [10.1](../admin/guide.md#101-notifications)).

The digest is sent once a day at a time you set. It contains counts only:
open updates, reboots pending, hosts not READY, grants expiring within 7
days, open findings per tier and the KEV count, and failed executions of the
last 24 hours. It needs at least one notification provider.

## What a message can ask you to do

A message links into the NOS web UI. It never asks you to reply, and it
never carries a command. To act on it, log in to NOS, check the page it
links to and act there, with the normal approvals.
