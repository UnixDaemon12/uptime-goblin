# Alerts and notifications

[Back to Uptime Goblin](../README.md) · [Configuration](configuration.md) · [Troubleshooting](troubleshooting.md)

Uptime Goblin tells you about alerts in the dashboard and, when you set them up, by email, through a webhook and as push notifications through [ntfy](#ntfy) or [Gotify](#gotify). From 1.5 every notification is saved before it is sent, retried until it is delivered or 24 hours have passed, and listed under **Configure → Notifications**, so a failing receiver, a restart or an upgrade no longer loses one.

## What is sent, and when

The switches are 1.4.2's, unchanged: **Evaluate alerts**, **Connection notifications** and **Metric notifications** (with each source's overrides), **Notify when an alert begins** and **Notify when a source recovers** (see [alert settings](configuration.md#alerts-and-notification-controls)). Each alert change that they allow becomes one notification per channel:

- **Email**, once it is enabled and set up (sender, recipient and app password saved). Uptime Goblin makes no email notifications while email is on but not set up, as 1.4.2 sent nothing then.
- **Webhook**, when `GOBLIN_WEBHOOK_URL` is set on the Uptime Goblin server.
- **ntfy** and **Gotify**, each once it is switched on and set up under **Configure → Notifications** ([ntfy](#ntfy): a server and topic; [Gotify](#gotify): a server and application token).

Uptime Goblin's own notices go the same way: history writes failing and working again, a full disk and its recovery, and a channel that pauses or works again (told on the other channels, below). They follow **Evaluate alerts**, **Notify when an alert begins** and **Notify when a source recovers**, but not **Connection notifications**, **Metric notifications** or a source's overrides. While **Notify when a source recovers** is on, a recovery always follows its notice, also across a restart: see [a full disk](#a-full-disk). With it off, receivers never hear that the disk, the history database or a channel works again.

**Delivered** means the mail server or the receiver accepted it: SMTP `250` after the message, or an HTTP `2xx` answer. Uptime Goblin cannot know whether someone read it.

## Durable delivery

- **Saved first.** The same database write that records an alert's change records its notification. A crash or a restart in between cannot lose it: Uptime Goblin copies it into its delivery queue (in `control.sqlite`) at the next start, once.
- **In order per alert.** A recovery never goes out before its alert on the same channel: it waits until the alert's notification was delivered or given up.
- **Retries.** A notification that could not be sent (no connection, a timeout before anything was sent, an SMTP `4xx`, an HTTP `408`, `425`, `429` or `5xx`) is tried again after 30 seconds, then after waits that double up to 15 minutes, each shortened at random by up to half so many Uptime Goblin servers do not retry together. After 5 such outcomes in a row the channel waits 1 minute, doubling up to 15 minutes, then sends one notification to see whether it works again.
- **Retry-After.** A `429` or `503` with `Retry-After` holds the whole channel for that long (at most 1 hour), not only that notification: the receiver asked Uptime Goblin to slow down.
- **24 hours.** A notification not delivered within 24 hours of its alert is given up (**Expired** in the history).
- **Email digests.** Email keeps 1.4.x's gathering: alerts are collected until a minute passes without a new one (at most 3 minutes), then sent as one message, of up to 100 alerts. A retry sends the same message again, with all of its alerts: when one of them has to wait (behind an older notification of its alert that **Retry** sent again, or in the control database while a full disk lets Uptime Goblin send only what it keeps in memory), the whole message waits for it, because mail services drop a second message with a `Message-ID` they already have, and later notifications of its alerts wait with it. Uptime Goblin reads the queue 200 notifications at a time, so a message waiting to go again can have alerts beyond that; when nothing else can go, the first such message whose alerts are all due and have nothing older still waiting goes whole, so these messages never stop email. Each message has a stable `Message-ID` (`<orbit.g_…@your sender's domain>`), the same on every attempt.
- **Webhooks** get one request per notification, with the body of 1.4.2 (below).
- **At most one send per channel at a time** and four in all, so a slow receiver cannot hold the other channel up, and a long queue on one channel (after **Resume**, say) never delays the other's notifications.
- **A full backlog.** The webhook holds at most 10,000 notifications not yet sent (waiting, retrying, being sent or held). While it holds that many, a new alert is not queued for it at all: it is never sent and has no row in the history. **Configure → Notifications** says so in its summary and a banner ("10 notifications for Webhook were not queued because its backlog was full (the last at …): they are not sent and not in the delivery history.") until 24 hours after the last one, the webhook's card and the System page count them since Uptime Goblin started, and the log says so at most once a minute ("The env-webhook notification backlog is full (10000 waiting); 37 more notification(s) were not queued."). Fix what keeps the webhook from delivering, or **Resume** it if it is paused. Email notifications are always queued: one message carries up to 100 of them.
- **Stopping Uptime Goblin** sends what is due first, email digests included (for up to 8 seconds), then stops. Notifications waiting for a retry, held by a paused channel, or in the middle of a send stay in the queue and are sent after the next start.

### Paused channels

Some answers mean the next attempt will fail the same way, so Uptime Goblin **pauses** the channel instead of retrying: its notifications are held (they still expire after 24 hours), and the page and a banner say why.

| Channel | Pauses until something changes | Pauses, and tries again by itself |
|---|---|---|
| Email | Sign-in failed (`EAUTH`), sender refused, the SMTP server's address is not allowed, settings incomplete | The server's TLS certificate is not trusted |
| Webhook | The address is not allowed (below); `GOBLIN_WEBHOOK_URL` is not a valid `http:` or `https:` URL, or contains a user name or password; a new signing key that receivers may not have ([held for Resume](#a-new-signing-key-waits-for-resume)) | `401`, `403`, `404`, `410`, any redirect (`3xx`), an untrusted TLS certificate |
| ntfy, Gotify | `401` or `403` (the token or password was refused); the server's address is not allowed ([below](#which-addresses-ntfy-and-gotify-may-use)); the settings are incomplete; a saved token or password can no longer be opened (the encryption key changed) | `404`, `410`, any redirect (`3xx`), an untrusted TLS certificate |

A paused channel works again when:

- you press **Resume** on the Notifications page;
- you save email settings, or send a test email that the mail server accepts (email only);
- you save the ntfy or Gotify settings, or send a test notification that the server accepts (that channel only);
- a **probe** works: for causes in the right-hand column Uptime Goblin sends the oldest held notification again every 15 minutes, since a proxy restarting, a flow being deployed or a certificate being renewed answers like that for a moment; and at every start Uptime Goblin sends one probe on each paused channel, whatever the cause, so a fix made while Uptime Goblin was stopped is found at once (except a webhook held for a new signing key, which only **Resume** ends: [below](#a-new-signing-key-waits-for-resume));
- Uptime Goblin starts with the channel switched off: email switched off while Uptime Goblin was stopped (also under 1.4.x after a [rollback](#rolling-back-to-14x-and-upgrading-again)), or `GOBLIN_WEBHOOK_URL` removed. Such a channel can send nothing, so no probe could end its pause: it ends at the start, as saving the email settings ends it, the notifications it held are not sent (**Skipped**), and the other channel hears that it works again (while **Evaluate alerts** and **Notify when a source recovers** are on). Email switched on but not complete stays paused ("Email is not set up: …").

When a channel pauses, Uptime Goblin tells you on the other channels ("Webhook notifications are paused: …"), and again when it works again, as [the switches](#what-is-sent-and-when) allow (the second only while **Notify when a source recovers** is on). Sent alone, the email adds that the paused channel's notifications are held (each for at most 24 hours) and that **Configure → Notifications** says why; only the notices about history writes and a full disk speak of readings or disk space. With only one channel set up there is no other channel to tell: the banner, the Notifications page and the probes are what remain, so check the page after changing a receiver.

### Refusing notifications

An answer that refuses one notification (an HTTP `4xx` other than those above, such as `400` or `422`; an SMTP `5xx` such as a recipient refused or a daily quota) ends that notification as **Failed**, and the channel goes on. After three such answers in a row the channel shows **Refusing notifications: {last error}** and the banner asks you to look; one accepted notification clears it. **Retry** sends a failed notification again.

### Checked again when sent

Just before a notification is sent, Uptime Goblin checks that it still should be: a notification whose source was deleted, or whose kind of alert was switched off after it was queued, is not sent (**Skipped** or **Not sent**, with the reason). Deleting a source also cancels its waiting notifications at once.

### Acceptance unknown, and duplicates

A send can end without knowing whether it arrived: the whole request was sent, but the receiver had not started its answer when the request's 8-second deadline ran out (the 8 seconds count from the start of the request, so looking up and connecting to the receiver use part of them), or the mail server did not confirm the message, or Uptime Goblin was stopped or killed in the middle of a send. Uptime Goblin then sends it once more:

- **Webhook**: after 2 minutes, with the same `X-Goblin-Delivery`. A receiver that takes about 8 seconds or longer to answer (an n8n workflow that answers at its end, a slow Node-RED flow) therefore gets the request twice. Make the receiver answer quickly, or drop a repeated `X-Goblin-Delivery`.
- **Email**: after 5 minutes, with the same `Message-ID`, so most mail programs show it once.

If that is not confirmed either, the notification ends as **May have arrived; Uptime Goblin could not confirm it.** Other cases where a receiver can see the same notification twice: Uptime Goblin restarted while it could not write its control database (see [a full disk](#a-full-disk)). Every attempt of one notification carries the same delivery id, so a receiver that remembers ids it has seen for a day never acts on one twice.

## Configure → Notifications

- **Summary**: one sentence about now (for example "Webhook is paused: …", "2 notifications waiting to retry (next attempt …)" or "All notifications were delivered."), when it was read, and **Refresh**. The page reads it again every 15 seconds while it is open. It counts only the channels that are set up and switched on, as the banners do: a channel that is not (`GOBLIN_WEBHOOK_URL` removed, email alerts switched off) skips what it still holds when it comes to send it.
- **Channels**: for Email, Webhook, ntfy and Gotify, the state in words (**Working**, **Ready (nothing sent yet)**, **Retrying**, **Waiting before the next try**, **Paused**, **Refusing notifications**, **Off**, **Not set up**; **Retrying** and **Waiting before the next try** only while notifications are still to go or the wait has not ended, so a channel whose failed notifications all ended unsent, for example because their source was deleted, says **Working** again), the last success and failure, the counts (waiting, retrying, sending, held, and failed since the channel last delivered one, within the last 24 hours: the card says since when), and **Resume** for a paused channel. The webhook's card names the host it sends to and offers **Show public key** and **Replace signing key** (below); the ntfy and Gotify cards name their server's host (never its path or the topic) and lead to their settings.
- **Push notifications**: the [ntfy](#ntfy) and [Gotify](#gotify) settings, each with **Save** and **Send test notification**.
- **Needs attention**: up to 20 notifications waiting to retry, held by a paused channel, or failed since their channel last delivered one (within the last 24 hours), on a channel that is set up and switched on. It looks through the newest 500 notifications with problems (older failures no longer count); if it stops there before finding 20, it says that older notifications were not checked rather than that nothing needs attention.
- **Delivery history**: every notification, newest first, filtered by kind (all, waiting and retrying, problems, delivered) and channel, with **Load more**. **Problems** are the notifications waiting to retry, held by a paused channel, or failed, however many newer ones wait for their first attempt (for example behind a webhook that keeps failing). **Load more** goes with the last page; if Uptime Goblin cannot be read, the rows shown stay and a line beside the button says the older ones were not read. After **Retry** or **Resume** the history is read again as far as it was shown, so the rows **Load more** brought in stay and the focus stays on the same control. Each says what happened, how many attempts it took, the last error or the reason it was not sent, and the next attempt (for an email waiting to be gathered into one message, when that message goes). While Uptime Goblin cannot write its control database, the notifications it keeps in memory are listed first, page by page, so **Load more** reaches every one of them; a line says how many there are, and under a filter or channel that leaves some or all of them out, that only those that match are listed, or that none of them matches. Finished notifications (delivered, or ended without a send) are kept for 7 days after they finished, at most the newest 50,000. Failed, expired and unconfirmed ones (**May have arrived**) are kept for 30 days, at most the newest 5,000. An hourly clean-up removes the oldest first, so behind a receiver that refuses every alert, failures can leave the history before 30 days. Notifications in one email say "Sent as one email with others" once that email went out (delivered, or may have arrived), and "Grouped into one email with others" before then or when it was never accepted (waiting, retrying, held, failed or expired). **Attempts** counts only the times Uptime Goblin sent a notification: one skipped just before a send (its source deleted, its kind of alert switched off, its channel no longer set up or switched off) counts no attempt for it.

**Retry** sends a failed notification again (with a new 24-hour limit), or a notification waiting to retry at once. It is not offered for a notification being sent, one held by a paused channel (resume the channel instead), one waiting for its first attempt, one that finished otherwise, one whose channel is not set up or is switched off (set `GOBLIN_WEBHOOK_URL` and restart Uptime Goblin, or switch email alerts on, first: until then Uptime Goblin would only skip it), or one whose source was deleted or whose kind of alert was switched off since (Uptime Goblin would only skip it too: 409 `delivery_not_retryable`); and Uptime Goblin refuses it when a later notification of the same alert was already delivered, or is being sent, on that channel, since it would arrive out of order. Notifications sent as one email are retried together, so when one of them would be skipped (its source deleted, its kind of alert switched off), Retry is offered for none of them, and the others are refused with "This notification was sent in one email with another whose source was deleted, so Uptime Goblin does not send that email again." (or "… another of a kind of alert that is switched off …"). The same holds when Retry refuses one of them for another reason, and the others' refusals name it too: "This notification was sent in one email with another whose alert already had a later notification delivered or being sent on this channel, so sending that email again would arrive out of order." (`delivery_outdated`), or, for one being sent, waiting for its first attempt or cancelled (its source deleted while the email waited to retry), "This notification was sent in one email with another that cannot be retried now, so Retry cannot send that email again." (`delivery_not_retryable`). A notification that may have arrived asks first.

When **Needs attention** or **Delivery history** cannot be read, it says why, with **Try again**. Once the read works, the rows replace that message and the keyboard focus moves to the list's first row (or to its heading when the list is empty), never back to the top of the page.

While Uptime Goblin cannot read its delivery status (its control database cannot be read), the page, the Email page, the Alerts page, the alerts window and the System page say **Delivery status is unavailable** rather than showing older figures as current. Nothing in the history ever contains a webhook URL, a secret or a message body.

## The webhook

Set `GOBLIN_WEBHOOK_URL` on the Uptime Goblin server and restart Uptime Goblin. Each notification is one `POST` with the body of 1.4.2, unchanged:

```json
{"source":"orbit","service":"linux-1","name":"Example host","kind":"firing","category":"measurement","rule":"cpu","message":"CPU is 95 % (above 80)","time":1800000000000}
```

`kind` is `firing` or `resolved`. `category` is `availability` (the connection check), `measurement` (a metric threshold) or `system` (Uptime Goblin's own notices). `rule` is `__availability` for the connection check, the metric's key for a threshold, and for Uptime Goblin's own notices `__disk` (a full disk), `__storage` (history writes) or `__channel_email` and `__channel_env-webhook` (a paused channel). A recovery has the same `service` and `rule` as its alert. Uptime Goblin's own notices use `"service":"orbit"` and `"name":"Uptime Goblin"`. `time` is when the alert changed, in milliseconds since 1970 (UTC). Headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `Uptime-Goblin` |
| `X-Goblin-Delivery` | The notification's delivery id (`d_` and 26 letters and digits): the same on every attempt of one notification, different for every other. |
| `X-Goblin-Signature` | `t=<Unix time in seconds>,v1a=<key id>:<hex Ed25519 signature>`; during a key's replacement a second `,v1a=…` (below). |
| `X-Orbit-Delivery` | The same value as `X-Goblin-Delivery`, under the name from before the rename to Uptime Goblin, for receivers written for Orbit. Sent in 1.5 and 1.6. |
| `X-Orbit-Signature` | The same value as `X-Goblin-Signature`, under the name from before the rename. Sent in 1.5 and 1.6. |

Each request has an 8-second deadline. Redirects are not followed (a redirect pauses the webhook: set the final address). Uptime Goblin sends at most 64 KiB and reads at most 4 KiB of the answer, of which it uses only the status and `Retry-After`. An answer counts as soon as its status arrives: a receiver that answers `200` at once and ends the body later (or keeps the connection open) has the notification delivered once, as with 1.4.x, even when the deadline or Uptime Goblin stopping cuts the body short.

**Changing the receiver.** Notifications are queued per channel, not per address. After you point `GOBLIN_WEBHOOK_URL` at another receiver and restart Uptime Goblin, every webhook notification still waiting, retrying or held goes to the new address, with the same `X-Goblin-Delivery`, and **Retry** sends failed ones there too. The signing key stays the same, also while `GOBLIN_WEBHOOK_URL` is unset. Uptime Goblin has no way to discard the queue. If the queued alerts must not reach the new receiver, first restart Uptime Goblin with `GOBLIN_WEBHOOK_URL` removed: each waiting notification then ends as "Skipped: not sent" at its next attempt, within an hour (the delivery history, showing **Waiting and retrying** on **Webhook**, lists none once all have ended). Then set the new address and restart. Receivers hold only the public key, which cannot sign, so the old receiver cannot make a request the new one accepts. Email is the same: email still waiting or held when you save a new recipient or mail server goes to the new one (1.4.x dropped it).

### Verifying signatures

Uptime Goblin signs each request with an Ed25519 private key that never leaves Uptime Goblin. Receivers verify with its public key, which is not a secret: **Show public key** on the webhook's card shows it (PEM) with its key id. Give it to the receiver. The signature is Ed25519 over the delivery id, a dot, the `t` value, a dot and the exact body bytes:

```text
<X-Goblin-Delivery>.<t>.<body>
```

`v1a` names the scheme, as Standard Webhooks names its Ed25519 signatures, but the header format is Uptime Goblin's own (`X-Goblin-Signature`, with `t=` and `v1a=` pairs, and each signature in hexadecimal after a key id): Standard Webhooks libraries do not verify it, so use the examples below. Each `v1a` value is `<key id>:<signature>`: the key id is the first 16 hexadecimal digits of the SHA-256 of the raw 32-byte public key, and the signature is 128 hexadecimal digits (64 bytes). Pre-release builds of 1.5 sent `v1` (an HMAC with a secret): this release never does, and keeps its private keys in settings fields those builds never open ([rolling back](#rolling-back-to-14x-and-upgrading-again)). Its first start replaces such a secret with a new key pair ("Uptime Goblin replaced the alert webhook's HMAC signing secret (from a pre-release build) with an Ed25519 signing key…"), or, without `GOBLIN_WEBHOOK_URL`, removes it and makes no key ("Uptime Goblin removed the alert webhook's HMAC signing secret (from a pre-release build)…"); the key pair is then made at the first start with a webhook. Either way the webhook then [waits for **Resume**](#a-new-signing-key-waits-for-resume). At a start with a webhook, a stored key that is neither such a secret (64 lower-case hexadecimal digits) nor an Ed25519 private key is replaced with a new key pair too ("A stored signing key of the alert webhook could not be read as an Ed25519 key…"); without one it is left where it is, and never signs. Private keys from formerly revealable HMAC fields are treated as potentially disclosed, even when they are Ed25519 keys in another PEM form. They are never adopted or kept for overlap. If retired material cannot be opened, active and previous keys are also treated as potentially equivalent. A successful atomic preservation clears that authority and, with a webhook, installs a fresh key held for Resume. Failed preservation leaves the stored bytes unchanged and cannot authorize signing with those keys; without a webhook, no key is created.

- Use the body exactly as received, before any JSON parsing.
- Accept the request when a `v1a` whose key id you hold verifies with that public key, and reject a `t` more than 5 minutes from your clock or one that is not ASCII digits (`0`-`9`). Python's `str.isdigit()` also takes `²` (the byte 0xB2, as a server that decodes headers as Latin-1 gives it), which `int()` then refuses with an error instead of a no.
- Then drop a request whose `X-Goblin-Delivery` you have already handled.

Both examples take each public key as PEM text, the form **Show public key** shows and `publicKey` in the answer of `GET /api/notifications/webhook/public-key` (below). That answer's `publicKeyRaw` is the same key as its raw 32 bytes in base64, for a library that wants that form.

Node.js (nothing to install):

```js
import crypto from 'node:crypto';

// keys: {keyId: publicKey PEM}, as Show public key gives them. During a planned replacement, add
// the previous key while it still signs, if the receiver had it; never after a suspected exposure
// of the private key (then keep only the new key). rawBody: the body as received (Buffer or
// string).
export function verifyUptimeGoblin(keys, headers, rawBody, nowMs = Date.now()) {
  const delivery = headers['x-goblin-delivery'] ?? '';
  const fields = String(headers['x-goblin-signature'] ?? '')
    .split(',')
    .map(field => field.trim().split('='));
  const t = fields.find(([key]) => key === 't')?.[1] ?? '';
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(delivery) || !/^\d{1,12}$/.test(t)) return false;
  if (Math.abs(nowMs / 1000 - Number(t)) > 300) return false; // 5 minutes
  const signed = Buffer.concat([Buffer.from(`${delivery}.${t}.`), Buffer.from(rawBody)]);
  return fields.some(([key, value = '']) => {
    const [, keyId, signature] = /^([0-9a-f]{16}):([0-9a-f]{128})$/.exec(value) ?? [];
    if (key !== 'v1a' || !keyId || !keys[keyId]) return false;
    return crypto.verify(null, signed, keys[keyId], Buffer.from(signature, 'hex'));
  });
}
```

Python (with the `cryptography` package, 3.1 or later):

```python
import re, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def verify_uptime_goblin(keys, headers, raw_body, now=None):
    """keys: {key id: public key PEM (str)}, as Show public key gives them.
    raw_body: the body as received (bytes)."""
    delivery = headers.get("X-Goblin-Delivery", "")
    fields = [f.strip().split("=", 1) for f in headers.get("X-Goblin-Signature", "").split(",")]
    fields = [f for f in fields if len(f) == 2]
    t = next((value for key, value in fields if key == "t"), "")
    # ASCII digits only: isdigit() also takes "²", which int() refuses with an error.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", delivery) or not re.fullmatch(r"[0-9]{1,12}", t):
        return False
    if abs((time.time() if now is None else now) - int(t)) > 300:  # 5 minutes
        return False
    signed = f"{delivery}.{t}.".encode() + raw_body
    for key, value in fields:
        entry = re.fullmatch(r"([0-9a-f]{16}):([0-9a-f]{128})", value)
        if key != "v1a" or not entry or entry.group(1) not in keys:
            continue
        public_key = serialization.load_pem_public_key(keys[entry.group(1)].encode())
        if not isinstance(public_key, Ed25519PublicKey):  # only an Ed25519 key verifies
            continue
        try:
            public_key.verify(bytes.fromhex(entry.group(2)), signed)
            return True
        except InvalidSignature:
            pass
    return False
```

To check your code, use the first test key of RFC 8032 (a published key, for tests only). Its public key is `11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=` (raw, base64), or in PEM:

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
-----END PUBLIC KEY-----
```

and its key id is `21fe31dfa154a261`. With the delivery id `d_abcdefghijklmnopqrstuvwxyz`, `t=1800000000` and the body `{"source":"orbit","kind":"firing"}`, the header is `t=1800000000,v1a=21fe31dfa154a261:e6bd05a7d32a1aa5280efe20ea563ffa5c98a9fc98110f1fd524c8384eb7781014e2badde775f0ed86e8b6be2f6715161a21fe471875dcdd5c1b564116eb8a0a` (Ed25519 signatures are deterministic, so yours must match).

**The public key for scripts.** `GET /api/notifications/webhook/public-key` answers the same as **Show public key**, and only public material:

```json
{"algorithm":"Ed25519","keyId":"21fe31dfa154a261","publicKey":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n","publicKeyRaw":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=","createdAt":1800000000000,"previousUntil":null,"previous":null}
```

While a replaced key still signs, `previous` holds its `keyId`, `publicKey` and `publicKeyRaw`, and `previousUntil` the time it stops (milliseconds since 1970). The route needs the right to read notifications, as the delivery status does.

**Replacing the signing key.** **Replace signing key** makes a new key pair and shows the new public key. For 24 hours the previous key also signs every request (a second `v1a`, with its own key id), so receivers can switch without missing one; only a usable current-format key not potentially exposed in retired fields may overlap ([above](#verifying-signatures)). Uptime Goblin keeps only one previous key: replacing the key again within those 24 hours stops the older one signing at once, and receivers that hold only its public key reject every alert until they have the new one (a webhook that answers 401 or 403 then pauses). The page says so before it replaces it, so give receivers each new public key before you replace it again. When the private key may have been exposed (a copy of the data directory together with its encryption key), follow every step of [a leaked key](security.md#a-leaked-key) instead. First, with Uptime Goblin stopped, put a new encryption key in place and run `goblin-admin key rotate`: a signing key made before that is sealed with a data key the leaked key opens. Then, with `GOBLIN_WEBHOOK_URL` set (set it again first if it was removed: without it the key cannot be replaced, and the exposed key signs again once it is set), press **Replace signing key** twice, so the exposed key stops signing at once (after one press it would sign for 24 hours more). Give receivers the new public key and have them keep only that one, dropping every public key they held before. If your session ends while Uptime Goblin replaces it, the **Sign in again** dialog finishes that replacement instead of making a second one, so the key it replaced still signs for its 24 hours (**Retry** and **Resume** are likewise done once).

**Who can see it.** The public key is not a secret: any signed-in admin can show it, and so can a script with the admin password while [legacy Basic](authentication.md#scripts-and-legacy-basic) is on. Uptime Goblin neither limits nor records reading it. The private key is never shown: no page, API answer, export, log line or [audit log](security.md#audit-log) entry holds it, and Uptime Goblin keeps it sealed with its encryption key (see [the encryption key](installation.md#encryption-key)). Each replacement is recorded in the audit log in the same write as the new key, and logged ("The webhook signing key was replaced by admin…"). **Replace signing key** is refused while the disk is full (503 `storage_full`). **Copy** puts the public key on your computer's clipboard (where the browser does not allow that, it selects the text for you to copy). If Uptime Goblin has no usable signing key, delivery waits and no unsigned request is sent. A safe existing current key can remain usable while an unrelated preservation write is pending; that does not claim the write succeeded. After `goblin-admin key reset --confirm-lost-key` Uptime Goblin makes a new key pair at its next start, and the webhook holds its notifications until you give receivers its public key and press **Resume** ([below](#a-new-signing-key-waits-for-resume)).

#### A new signing key waits for Resume

A key pair that Uptime Goblin makes in place of signing material it had before cannot sign beside it: an HMAC secret of a pre-release build was shown to admins and never signs again, and a key the encryption key no longer opens cannot sign at all. A receiver that still checks the old one refuses every request, and a refusal such as `400` or `422` would end each notification as **Failed**. So a start that makes a key pair where the settings already held signing material (a pre-release build's HMAC secret, also one an earlier start removed without `GOBLIN_WEBHOOK_URL`; a stored value that is not an Ed25519 key; a key that no longer opens, after `goblin-admin key reset`) pauses the webhook with "Uptime Goblin made a new signing key, which receivers that check X-Goblin-Signature may not have. Give them its public key (Show public key), then press Resume to send what waits." It holds every notification and sends nothing, not even unsigned while the new key cannot be saved yet ("The new webhook signing key could not be saved (…); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds."). No probe ends this pause, also not at a restart, and the other channel hears of it as of any pause. When Uptime Goblin cannot read its settings at all, delivery waits; it never falls back to unsigned requests. Give receivers the public key (**Show public key**, or `GET /api/notifications/webhook/public-key`), then press **Resume** (`POST /api/notifications/channels/env-webhook/resume` for scripts): that ends the hold, and the held notifications go, signed with the new key. The [audit log](security.md#audit-log) records it as any **Resume** of the webhook (`channel.resume` on `env-webhook`, with how many notifications it released; a refused one with its error code): the first successful one while the webhook is held is the one that ended the hold. Until the new key is saved there is no public key to give them (**Show public key** answers 503 `signing_unavailable`), so **Resume** is refused the same way and the hold stays. The held notifications still expire 24 hours after their alert (**Retry** sends one again). **Replace signing key** keeps the hold, also one whose key could not be saved yet: the hold is saved with the replacement, so a restart still holds. A replacement that has no key to keep signing (the settings held such signing material in place of a current key, and Uptime Goblin had not replaced it yet, for example because it could not read its settings at the start) holds the webhook in the same way. The first key pair of settings that never held one (a new install, an upgrade from 1.4.x, data restored from before 1.5) does not pause the webhook: nothing was signed for it before. Uptime Goblin never sends an unsigned webhook. If signing settings cannot be read or no usable signing key is available, delivery waits. With newer read-only settings, a usable current key may keep signing only when no saved signing hold applies; saved holds stay effective. **Replace signing key** always refuses such settings. **Resume** cannot clear an immutable saved hold or resume without a usable current key. These compatibility refusals answer 409 `signing_compatibility` with no `Retry-After`: "A newer Uptime Goblin saved these signing settings. Upgrade Uptime Goblin or restore a compatible backup before changing them.". A missing usable key in writable settings instead answers 503 `signing_unavailable` with `Retry-After: 60`; concurrent changes answer 409 `signing_conflict`.

### Which addresses the webhook may use

`http:` and loopback (`127.0.0.1`, `localhost`, `::1`) stay allowed, as in 1.4.x. Link-local addresses (such as `169.254.169.254`, the cloud metadata service), multicast, unspecified and reserved addresses are refused, also when they are written inside an IPv6 address (NAT64 `64:ff9b::…` and the local-use `64:ff9b:1::…`, IPv4-compatible `::a.b.c.d`, IPv4-translated `::ffff:0:a.b.c.d` and 6to4 `2002:…`; other NAT64 prefixes are not recognised, see [security](security.md#outbound-requests-and-tls)). A host name is checked against every address it resolves to when Uptime Goblin connects, so a name that resolves somewhere it may not go is refused too. A refused address pauses the webhook with the reason.

## ntfy

[ntfy](https://ntfy.sh) pushes notifications to its phone and desktop apps. Under **Configure → Notifications → Push notifications**, set:

- **Server**: `https://ntfy.sh` by default, or your own ntfy server (a path such as `https://example.com/ntfy` is kept, for a server behind a reverse proxy).
- **Topic**: letters, digits, `_` and `-`, at most 64. On a public server anyone who knows the topic can read its notifications: choose one that is hard to guess, or protect the topic on your server and give Uptime Goblin a token.
- **Access token**, or a **user name and password** (not both): optional, for a protected topic. Uptime Goblin sends the token as `Authorization: Bearer …`, or the user name and password as Basic.
- **Priority of an alert** and **of a recovery**: ntfy's 1 (min) to 5 (max); by default 4 (high) when an alert begins and 3 (default) when it recovers. Uptime Goblin's own notices use the same two.
- **Tags**: up to 5 emoji short codes or words. Uptime Goblin adds `warning` to an alert and `white_check_mark` to a recovery, which ntfy shows as emoji.
- **Uptime Goblin's address**: optional. When it is set, tapping a notification opens it (ntfy's `click`).

Switch **Send alerts to ntfy** on and press **Save ntfy settings**. Each notification is one `POST` of ntfy's JSON to the server's address:

```json
{"topic":"goblin-alerts","title":"Example host alert","message":"CPU is 95 % (above 80)","priority":4,"tags":["warning"],"click":"https://goblin.example.com/"}
```

The title is the source's name and `alert` or `recovered` (`Uptime Goblin alert` for Uptime Goblin's own notices); the message is the alert's message, at most 2,000 characters.

## Gotify

[Gotify](https://gotify.net) is a self-hosted notification server. In Gotify, create an application and copy its token; then, under **Configure → Notifications → Push notifications**, set the **Server** (for example `https://gotify.example.com`) and the **Application token**, and optionally the two priorities (Gotify's 0 to 10; by default 8, which the Gotify apps show as high, when an alert begins and 4 when it recovers) and **Uptime Goblin's address** (tapping a notification opens it). Switch **Send alerts to Gotify** on and press **Save Gotify settings**. Each notification is one `POST` to the server's `/message`, with the token in the `X-Gotify-Key` header, never in the address:

```json
{"title":"Example host alert","message":"CPU is 95 % (above 80)","priority":8,"extras":{"client::notification":{"click":{"url":"https://goblin.example.com/"}}}}
```

### How ntfy and Gotify deliver

They go through the same queue as email and the webhook: saved first, retried, kept in order per alert, listed in the delivery history, paused and resumed as described above. Every request carries `User-Agent: Uptime-Goblin` and `X-Goblin-Delivery`, the same on every attempt of one notification; neither ntfy nor Gotify drops a repeat by it, so a notification whose acceptance is unknown (the request was sent and no answer came within 8 seconds) can arrive twice: Uptime Goblin sends it once more after 2 minutes, then gives up with **May have arrived; Uptime Goblin could not confirm it.** Each request has an 8-second deadline; Uptime Goblin sends at most 16 KiB, reads at most 4 KiB of the answer (only its status and `Retry-After` are used), never follows a redirect and verifies TLS (a private CA through `NODE_EXTRA_CA_CERTS`). A `401` or `403` pauses the channel until something changes: fix the token or password and save (which resumes it), press **Resume**, or send a test that the server accepts. Other answers are handled as for the webhook: `408`, `425`, `429` and `5xx` retry, `404`, `410` and redirects pause and are probed every 15 minutes, and any other `4xx` fails that notification. If Uptime Goblin cannot read the ntfy and Gotify settings (`control.sqlite` gives a read error at the start or after a save), it does not yet know whether they get a notification: email and the webhook get theirs at once (in memory, and sent again after a restart until they are delivered, if `control.sqlite` cannot be written either), and the ntfy and Gotify ones wait and are queued once the settings can be read again (Uptime Goblin tries every 10 seconds). An alert's change is not lost to them: it stays in the history until it is queued, and waiting changes never hold up newer alerts' email or webhook notifications. Uptime Goblin's own notices wait in memory, at most 1,000 of them across alerts and notices: past that, the oldest notice is not sent to ntfy and Gotify, and the log says how many were not ("… Uptime Goblin notice(s) were not queued for ntfy or Gotify: their settings could not be read."); a restart also forgets the notices waiting.

**Send test notification** sends one notification ("Uptime Goblin: test notification") with the saved settings, also while the channel is switched off, and says what the server answered. It is limited to one every 30 seconds per channel (429 `test_rate_limited`), is recorded in the [audit log](security.md#audit-log), and its result appears on the channel's card as its last success or failure. Save first: a test of a channel that is not set up is refused (409 `channel_not_set_up`).

### Which addresses ntfy and Gotify may use

The server address must be `https:`, or `http:` to this computer (`localhost`, `127.0.0.1`, `::1`), without a user name, password, query or fragment, at most 2,048 characters. Plain `http:` to another computer needs **Allow plain HTTP**: the token or password and every notification would cross the network unencrypted, so use it only on a network you trust. The addresses Uptime Goblin connects to follow the rule of [collection destinations](security.md#outbound-requests-and-tls), not the webhook's: link-local (such as `169.254.169.254`, the cloud metadata service), multicast, unspecified and reserved addresses are always refused, also when written inside an IPv6 address, and loopback is refused unless `GOBLIN_ALLOW_LOOPBACK=1` is set (for an ntfy or Gotify server on the Uptime Goblin host itself). Private addresses (`192.168.x.x`, `10.x.x.x`, ULA) are allowed. A host name is checked against every address it resolves to when Uptime Goblin connects, so DNS cannot swap in a refused address afterwards. A refused address pauses the channel with the reason, and a test says it.

### Tokens and passwords are write-only

The ntfy access token and password and the Gotify application token are sealed with Uptime Goblin's [encryption key](security.md#encryption-key-and-sealed-secrets) in `control.sqlite`, like the webhook's signing key. No page, API answer, export, log line or audit entry holds them: `GET /api/notifications/channels/<id>/settings` answers them only as `{"set": true}` or `{"set": false}`, the form shows "Saved · leave blank to keep", a value is sent only when you type one, and **Clear the saved token…** removes it. The [audit log](security.md#audit-log) records each change of the settings (`channel.settings`) with what changed, the token, password and the ntfy topic only as set, changed or cleared. If the encryption key changes so that a saved token can no longer be opened, the channel pauses and the form asks you to enter it again.

**For scripts.** `GET /api/notifications/channels/ntfy/settings` (or `gotify`) needs the right to read the configuration; `PATCH` the same address with the fields to change (those above, as the answer names them, plus an optional `version` from the last read: 409 `channel_settings_conflict` when the settings changed since) needs the right to change channels, as does `POST /api/notifications/channels/<id>/test` (`{}`). A token or password set to `null` or `""` is cleared; one left out is kept. A change that breaks the rules above is refused whole (400 `channel_settings_invalid`, naming the field but never its value), and while the disk is full with 503 `storage_full`.

## A full disk

Uptime Goblin keeps 8 MiB of reserve space in `run/space-reserve` in its data directory. When the disk is full it releases that space, so signing in and sending alerts keep working, and meanwhile:

- settings changes answer "Uptime Goblin's disk is full, so this change was not saved…" (HTTP 503), and a banner says so;
- readings are not saved, and Uptime Goblin sends a notice ("The Uptime Goblin host's disk is full: …"), and another once there is free space again, as [the switches](#what-is-sent-and-when) allow;
- alerts are still evaluated and sent.

**A restart in between.** Uptime Goblin records in its control database that a disk-full notice (or a history notice, "Uptime Goblin cannot write its history database…") was sent and has not ended yet, so a stop does not break the pair. When the disk had space again by the next start (you cleaned up and restarted, the host rebooted, or you rolled back to 1.4.x and upgraded again: 1.4.x leaves that record alone), Uptime Goblin sends "The Uptime Goblin host's disk has free space again." at that start (while **Notify when a source recovers** is on), after the notice if that one was still waiting to be retried. When the disk is still full at the start, the notice goes on: no second one is sent (unless it was delivered more than 7 days ago and has left the history, when it is sent once more, with the same delivery id), and the recovery follows once space is freed. A history notice ends as it does without a restart, once the new run has saved readings at least three times and five minutes have passed since the first of them; the dashboard shows no history failure meanwhile, since none happened in that run. Only when the control database refused that record until Uptime Goblin stopped does the next start know nothing of the notice, as with the notifications kept in memory (below).

If even the control database cannot be written, notifications are sent from memory and a banner says "Notifications are not being saved". **Resume** and **Retry** are refused then (503 `audit_unavailable`, "Uptime Goblin cannot write its audit log, so nothing was changed…"), because Uptime Goblin records them in its [audit log](security.md#audit-log), in that database, before it acts. Only a test email that the mail server accepts still resumes paused email; the notifications it held in the database go as soon as the database can be written again (until then email shows as working with them counted as held). An email whose alerts are partly in memory and partly in the database goes as one message once the database can be written again, and a later notification of one of its alerts (a recovery) waits for it. A probe that cannot release its held notifications leaves the channel paused and tries again shortly. A notification Uptime Goblin had sent just as the disk filled, whose result it could not save yet, counts as sent: a later notification of the same alert is not held back behind it. Alerts not yet delivered when Uptime Goblin restarts are sent again after the restart (so one may arrive twice); Uptime Goblin's own notices still waiting are lost. Everything returns to normal once space is freed: the notifications that finished in memory are then saved too, so their history survives a restart, and one still waiting to retry is saved once it finishes (until then the history lists it first, kept in memory). See [a full disk](troubleshooting.md#a-full-disk).

## Clock changes

Uptime Goblin notices when the system clock jumps by more than a minute while it runs (a host without a working clock that sets it from the network after starting, a restored container, a resumed virtual machine). A jump forward does not expire waiting notifications, nor one whose send was in progress when the clock jumped; a jump back does not make them wait for days. The order of an alert's notifications never depends on the clock, also when some are kept in memory on a full disk: a recovery Uptime Goblin already delivered still makes **Retry** of its alert's failed notification answer that a later one was delivered. When the control database cannot be written at that moment (a full disk), the notifications it holds are adjusted once it can be written again, and none of them expires before then. A change while Uptime Goblin was stopped cannot be told from the time it was stopped: notifications older than 24 hours by the new clock expire.

## Rolling back to 1.4.x and upgrading again

**Before rolling back, receivers that check signatures must accept unsigned requests.** 1.4.x sends each webhook without `X-Goblin-Delivery` and `X-Goblin-Signature` (the body is the same), so a receiver that verifies them as [above](#verifying-signatures) rejects every one. 1.4.x sends each notification once and never retries it, so those alerts are lost for as long as the rollback lasts. Let the receiver accept Uptime Goblin's unsigned requests while 1.4.x runs, and turn the check back on once 1.5 runs again, with the new public key if the data from before the upgrade was restored (below).

**The private signing key stays in `control.sqlite`**, which 1.4.x ignores, so 1.4.x neither uses nor shows it. **Do not start data that this release has run on with an earlier 1.5 pre-release build.** Such a build shows no signing secret, cannot make one and sends webhooks unsigned: this release keeps the private keys in settings fields those builds never open, and every start of it, with or without `GOBLIN_WEBHOOK_URL`, saves those settings in a form the earlier builds can read but not change. Those builds signed with an HMAC secret, read from a field they open without checking what it holds, and 1.5 pre-release builds that already signed with Ed25519 kept the private key in that field, until a start of this release moves it out. An HMAC build started on such data before that took the key for its HMAC secret, signed with its text and showed it under **Show signing secret**. If one has run on the data, press **Replace signing key** twice once this release runs again (after the first press the exposed key keeps signing for 24 hours; the second press stops it at once), with `GOBLIN_WEBHOOK_URL` set (set it again first if it was removed: without it the key cannot be replaced, and the exposed key signs again once it is set), and give receivers the new public key. The native installer's automatic rollback never starts a build that signs with an HMAC secret, but it does restore and start a 1.5 pre-release build that already signs with Ed25519: if the failed start of this release got as far as saving the signing settings, that build sends webhooks unsigned until this release runs again or the data from before the upgrade is restored ([verification and automatic rollback](installation.md#verification-and-automatic-rollback)).

1.4.x does not read Uptime Goblin 1.5's delivery queue: notifications still waiting when you roll back are **not** sent by 1.4.x, which sends its own notifications for alert changes from then on. When you upgrade again, notifications still waiting are sent if they are less than 24 hours old, except those whose alert 1.4.x handled a later change of (for example 1.4.x sent the recovery): those are not sent ("Not sent: Orbit 1.4.x handled a later change of this alert."). That includes a notification Uptime Goblin was sending when it was stopped or killed before the rollback, which it would otherwise send once more. Older ones expire without being sent. Every paused channel tries once at that start; one you switched off under 1.4.x (email) leaves its pause instead, and the other channel hears that it works again, as when you switch it off in 1.5. Notifications 1.4.x sent itself are never sent again.

**Restoring the data from before the upgrade** (the pinned pre-upgrade snapshot, with `goblin-admin restore-snapshot`, or any copy of the data directory taken before 1.5 first ran, such as a deploy script's tarball) removes `control.sqlite`, and with it the notifications still waiting, the delivery history, the webhook signing key and the [audit log](security.md#audit-log) (the next start begins a new, empty one: export it first). Those notifications are never sent, and not listed as not sent either (the pre-restore snapshot keeps the old `control.sqlite`). When 1.5 runs again it makes a new signing key ("Uptime Goblin created a new signing key for the alert webhook…"): give its public key (**Configure → Notifications → Show public key**) to receivers before they check signatures again, or they reject every request. `goblin-admin restore-snapshot` says so when it removes `control.sqlite`.

After restoring a backup or a snapshot, or when `control.sqlite` is another file than before (copied or moved), notifications from before that are not sent ("Not sent: Uptime Goblin's control database is a different file than before…").
