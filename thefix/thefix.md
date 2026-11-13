# The fix: what goes away

This page lists which parts of [the problem](../README.md#the-problem) are no longer needed once [Domain Mail Signing (DMS)](draft-findlay-mail-domain-signing-00.md) is fully adopted. "Full adoption" means every sending and receiving domain is in phase 3 of the draft's [transition plan](draft-findlay-mail-domain-signing-00.md#12-transition-and-coexistence). In phase 3, domains send DMS only, reject mail without it and have closed every cleartext port.

DMS changes how mail is **authenticated** and **transported**. It does not change what a message looks like, how clients read mailboxes or how mail is filtered. The protocols for those jobs stay, and are listed at the end so it's clear the fix isn't claiming more than it does.

## How mail is communicated in the fix

Mail is only ever carried over the following secure connections ([draft §9.1](draft-findlay-mail-domain-signing-00.md#91-permitted-connections)). Anything not on this list is not used.

| Path | Connection | Port |
|---|---|---|
| Server to server | SMTP over implicit TLS 1.3, both ends authenticated (DMS relay) | A new dedicated DMS port, given by `_dms-smtp._tcp`. Legacy port 25 is used only during transition, and only for domains that publish no DMS server. |
| Client sending | SMTP submission over implicit TLS | 465 |
| Client reading | IMAP over implicit TLS | 993 |
| Client reading | POP3 over implicit TLS | 995 |
| Client reading and sending | Exchange (MAPI over HTTP, ActiveSync, EWS / Microsoft Graph) over HTTPS | 443 |
| Client reading and sending | JMAP over HTTPS | 443 |

There are no cleartext ports and no STARTTLS-style upgrades. Weak login methods such as APOP, CRAM-MD5, DIGEST-MD5, NTLM and anonymous login are not offered. Any standard that exists only to support an insecure path is therefore retired below.

## Summary

| | RFCs |
|---|---|
| Retired: no longer required | **22** |
| Changed: absorbed, reduced, restricted or given a bigger role | **12** |
| Unchanged: still required | **127** |
| Added by the fix | **1** (the DMS draft) |

## Retired

### Sender authentication: replaced by `_mail` keys, `_dms-send._tcp` SRV, `Mail-Signature` and `Mail-Hop`

Three overlapping mechanisms, plus a fourth to repair them in transit, become one signature from one key. That key is anchored in both DNS and a CA-issued certificate. The sending servers are named in SRV records.

| RFC | Title | Why it's no longer needed |
|---|---|---|
| [7208](../rfc/rfc7208.txt) | Sender Policy Framework (SPF) | `_dms-send._tcp` SRV records name the authorised sending hosts, and each host proves its identity with a certificate. Hubs are authorised with `h=`. IP-address allow-lists and `include:` chains are no longer needed, and neither is SPF's 10-lookup limit. |
| [6376](../rfc/rfc6376.txt) | DomainKeys Identified Mail (DKIM) Signatures | Replaced by `Mail-Signature`. The key moves from `<selector>._domainkey` to `_mail` and is also bound to a certificate. |
| [8301](../rfc/rfc8301.txt) | Cryptographic Algorithm and Key Usage Update to DKIM | DKIM-specific algorithm rules; DMS defines its own algorithms. |
| [8463](../rfc/rfc8463.txt) | A New Cryptographic Signature Method for DKIM (Ed25519) | As above. |
| [6377](../rfc/rfc6377.txt) | DKIM and Mailing Lists | Replaced by the `Original-Mail-Signature` rules in draft §11. |
| [9989](../rfc/rfc9989.txt) | DMARC | Alignment is mandatory and strict (draft §6.4). Policy is stated by whether the domain publishes `_dms-send._tcp` (draft §4.8), not by a `p=` tag. Under an enforcing policy, failure always means rejection. |
| [9990](../rfc/rfc9990.txt) | DMARC Aggregate Reporting | Receivers no longer need to report pass/fail rates for a policy that doesn't exist. Every failure is reported to the sending server at SMTP time, with a registered reason (draft §10.1). |
| [9991](../rfc/rfc9991.txt) | DMARC Failure Reporting | As above. |
| [7960](../rfc/rfc7960.txt) | Interoperability Issues between DMARC and Indirect Email Flows | The forwarding problems it describes are solved by the hop chain (draft §7.4, §11). |
| [8617](../rfc/rfc8617.txt) | Authenticated Received Chain (ARC) | `Mail-Hop` is a mandatory, signed chain of custody that every hop must add, so an optional repair chain is no longer needed. |
| [8616](../rfc/rfc8616.txt) | Email Authentication for Internationalized Mail | Updates SPF, DKIM and DMARC for internationalised mail. All three are retired, and DMS is defined over UTF-8 domains from the start. |
| [7372](../rfc/rfc7372.txt) | Email Authentication Status Codes | SPF/DKIM/DMARC-specific SMTP codes, replaced by the three DMS enhanced status codes (draft §13.5). |

### Transport security and routing: replaced by mandatory implicit TLS 1.3 with mutual authentication, plus `_dms-smtp._tcp` SRV

If every connection must be encrypted and both ends authenticated, nothing needs to advertise, negotiate, enforce, pin or report on TLS. Receiving servers and the domain's policy are published as SRV records and confirmed against `_mail` keys.

| RFC | Title | Why it's no longer needed |
|---|---|---|
| [3207](../rfc/rfc3207.txt) | SMTP Service Extension for Secure SMTP over TLS (STARTTLS) | Relay uses implicit TLS from the first byte, so there is no cleartext phase to upgrade from and no upgrade to strip. |
| [2595](../rfc/rfc2595.txt) | Using TLS with IMAP, POP3 and ACAP | STARTTLS for mail access. Cleartext ports 143 and 110 are closed and access is implicit TLS only. |
| [8461](../rfc/rfc8461.txt) | SMTP MTA Strict Transport Security (MTA-STS) | Exists to stop TLS downgrade and to pin the valid MX hosts. There is nothing left to downgrade to. `_dms-smtp._tcp` lists the valid receiving hosts in DNS itself, and its presence is the enforcement signal, so no HTTPS policy file is needed. |
| [7672](../rfc/rfc7672.txt) | SMTP Security via Opportunistic DANE TLS | The receiving server is confirmed by its SRV target name, its Web PKI certificate and a matching key in the recipient's `_mail` record. A separate TLSA pin isn't needed for mail. |
| [7505](../rfc/rfc7505.txt) | A "Null MX" No Service Resource Record | Replaced by `_dms-smtp._tcp` with target `.` (accepts no mail). Its sending-side counterpart, `_dms-send._tcp` with target `.`, covers domains that send no mail, which previously took SPF `-all` plus DMARC `p=reject`. |
| [8460](../rfc/rfc8460.txt) | SMTP TLS Reporting (TLS-RPT) | Reports failures of MTA-STS and DANE, which are both retired. A TLS failure now surfaces as a delayed or bounced message (draft §9.4). |
| [8689](../rfc/rfc8689.txt) | SMTP Require TLS Option (REQUIRETLS) | Every message requires TLS, so a per-message flag is meaningless. |
| [8997](../rfc/rfc8997.txt) | Deprecation of TLS 1.1 for Email Submission and Access | TLS 1.3 is the minimum for relay and implicit TLS is required everywhere, so deprecating 1.1 is moot. |
| [8996](../rfc/rfc8996.txt) | Deprecating TLS 1.0 and TLS 1.1 | As above, for mail. The BCP still applies to other protocols. |

### Insecure authentication: removed from every permitted connection

| RFC | Title | Why it's no longer needed |
|---|---|---|
| [4505](../rfc/rfc4505.txt) | Anonymous SASL Mechanism | No permitted connection allows unauthenticated access. Submission, IMAP, POP3, Exchange and JMAP all require a real identity, and relay is authenticated by certificate. |

### Insecure mechanisms outside the stack: also prohibited

These were never part of the current 161-RFC stack, either because they are already historic or because they are not IETF standards. They are listed here because the fix explicitly prohibits them ([draft §9.2](draft-findlay-mail-domain-signing-00.md#92-prohibited-mechanisms)).

| Mechanism | Source | Why |
|---|---|---|
| `CRAM-MD5` | RFC 2195 | MD5, and the server stores password equivalents |
| `DIGEST-MD5` | RFC 2831, moved to Historic by RFC 6331 | Same problems; already deprecated |
| `LOGIN` | Never standardised | Same as `PLAIN` but non-standard |
| NTLM | Microsoft proprietary | Weak and vulnerable to relay attacks |
| HTTP Basic authentication to Exchange | RFC 7617 used by Exchange | Sends a reusable password on every request; replaced by OAuth 2.0 |
| RPC over HTTP (Outlook Anywhere) | Microsoft proprietary | Legacy Exchange transport, replaced by MAPI over HTTP |

## Changed: absorbed, reduced, restricted or given a bigger role

These documents remain. DMS takes over part of what they do, makes their main use optional, restricts them to their secure form, or makes them more important.

| RFC | Title | What changes |
|---|---|---|
| [9051](../rfc/rfc9051.txt) | IMAP4rev2 | **Restricted** to port 993 with implicit TLS. Port 143, the `STARTTLS` command and `LOGINDISABLED` go away. |
| [1939](../rfc/rfc1939.txt) | POP3 | **Restricted** to port 995 with implicit TLS. Port 110 and `APOP` (MD5) go away, and `USER`/`PASS` are only ever sent inside TLS. |
| [5804](../rfc/rfc5804.txt) | ManageSieve | **Restricted** to implicit TLS, so its `STARTTLS` command goes away. It doesn't carry mail, so it isn't in the permitted-connections list, but it must still be encrypted. |
| [8314](../rfc/rfc8314.txt) | Cleartext Considered Obsolete | Its recommendation, implicit TLS for submission and access, becomes a hard requirement. DMS extends it to server-to-server relay, and the draft cites it normatively. |
| [5321](../rfc/rfc5321.txt) | Simple Mail Transfer Protocol | The command protocol stays. Cleartext relay, open relaying and unauthenticated peers are gone. Routing by MX records gives way to `_dms-smtp._tcp` SRV records. The draft formally updates it. |
| [6186](../rfc/rfc6186.txt) | Use of SRV Records for Locating Email Submission/Access Services | **Bigger role.** Its SRV names become the standard way for clients to find mail servers. Only the implicit-TLS names (`_submissions`, `_imaps`, `_pop3s`) may point at a host, and the cleartext names must publish target `.` (draft §4.9). |
| [6409](../rfc/rfc6409.txt) | Message Submission for Mail | Submission over port 587 with STARTTLS is no longer offered. Submission over port 465 with implicit TLS stays. |
| [7817](../rfc/rfc7817.txt) | Updated TLS Server Identity Check for Email-Related Protocols | Still applies to IMAP, POP3 and submission. For relay, DMS's mutual-TLS rules take its place. |
| [8601](../rfc/rfc8601.txt) | `Authentication-Results:` header field | It existed to carry SPF/DKIM/DMARC verdicts to downstream filters and clients. DMS rejects failures at the border, so every delivered message has passed. It remains optional for internal logging. |
| [8553](../rfc/rfc8553.txt) | DNS Attrleaf Changes | Most of its email entries (`_spf`, `_domainkey`, `_dmarc`) refer to retired protocols. DMS registers `_mail` under RFC 8552 instead. |
| [5782](../rfc/rfc5782.txt) | DNS Blacklists and Whitelists | Still useful for reputation, but no longer the first line of defence against forged senders, because forged senders can no longer pass verification. Lists can key on authenticated domains rather than IP addresses. |
| [6522](../rfc/rfc6522.txt) | `multipart/report` | Still used for bounces and read receipts, but no longer carries DMARC or TLS-RPT reports. |

## DNS records no longer published

Fully adopted, a domain's mail-related DNS shrinks to `_mail` TXT records plus two SRV record sets. Keys and Hubs are in TXT. Receiving servers, sending servers and policy are in SRV.

| Today | Purpose | After DMS |
|---|---|---|
| `domain.uk MX …` | Mail routing | Replaced by `_dms-smtp._tcp.domain.uk SRV`, which also carries the port and the receiving policy. MX is kept only for legacy senders during transition. |
| `domain.uk MX 0 .` | Null MX: accepts no mail | Replaced by `_dms-smtp._tcp.domain.uk SRV 0 0 0 .` |
| `domain.uk TXT "v=spf1 …"` | SPF | Replaced by `_dms-send._tcp.domain.uk SRV`, which lists sending hosts by name. Every SRV field is used: priority is the policy persistence period, weight is each host's share of outbound mail, and port is where failure reports are returned. |
| `<selector>._domainkey.domain.uk TXT "v=DKIM1; …"` | DKIM keys (often several, plus CNAMEs to hubs) | Removed |
| `_dmarc.domain.uk TXT "v=DMARC1; …"` | DMARC policy and reporting addresses | Removed. Sending policy is the presence of `_dms-send._tcp`. |
| `_mta-sts.domain.uk TXT` + `https://mta-sts.domain.uk/.well-known/mta-sts.txt` | MTA-STS policy (and a web server just to host it) | Removed. Receiving policy is the presence of `_dms-smtp._tcp`. |
| `_smtp._tls.domain.uk TXT "v=TLSRPTv1; …"` | TLS reporting | Removed |
| `_25._tcp.mx.domain.uk TLSA …` | DANE for SMTP | Removed (TLSA may remain for other services) |
| `_submission._tcp`, `_imap._tcp`, `_pop3._tcp` SRV | Client autodiscovery, including cleartext/STARTTLS services | Kept, but with target `.` (not offered). Only `_submissions`, `_imaps`, `_pop3s` and `_jmap` point at hosts. |
| — | — | **New:** `_mail.domain.uk TXT "v=DMS1; …"` (keys and hub authorisations) |
| — | — | **New, optional:** `<hash>._user._mail.domain.uk TXT "v=DMS1; …; u=user"` (personal signing keys, one per user who signs) |

## Unchanged: still required

DMS doesn't touch these areas. Every other RFC in [the problem](../README.md#rfcs-by-layer) remains in force.

- **Message format and MIME:** RFC 5322, RFC 2045–2049 and related documents. Messages look the same.
- **SMTP service extensions:** `SIZE`, `8BITMIME`, `CHUNKING`, `PIPELINING`, `DSN`, `LIMITS`, enhanced status codes and the rest. They operate inside the encrypted session.
- **Delivery status and notifications:** DSNs, MDNs, ARF and auto-response rules.
- **SASL and `AUTH`:** users still log in to submission and access servers. DMS authenticates domains and servers, not people.
- **IMAP, POP3 and JMAP:** mailbox access is unchanged apart from the loss of cleartext ports.
- **Sieve and ManageSieve.**
- **Internationalised email (EAI / SMTPUTF8).**
- **S/MIME, OpenPGP and header protection:** DMS proves which **domain** sent a message and, optionally, which **user** wrote it (`Mail-User-Signature`, using the user's existing S/MIME certificate). It also encrypts mail **in transit**. End-to-end encryption, so that hubs and providers cannot read the content, remains the job of S/MIME and OpenPGP.
- **Mailing-list headers and URIs:** `List-*`, `mailto:` and similar.

## Net effect

| | Today | After full adoption |
|---|---|---|
| Ways to authenticate a sender | 4 (SPF, DKIM, DMARC, ARC) | 1 (DMS) |
| Ways to secure transport between servers | 5 (STARTTLS, MTA-STS, DANE, REQUIRETLS, TLS-RPT) | 1 (implicit mutual TLS 1.3) |
| Where the sending policy lives | DMARC `p=` tag, SPF `-all` | Presence of `_dms-send._tcp` SRV. The SRV priority sets how many days the policy persists. |
| Where the receiving policy lives | MTA-STS (TXT + HTTPS file), DANE TLSA | Presence of `_dms-smtp._tcp` SRV |
| How senders learn why mail failed | Varies; often a vague bounce, or nothing (DMARC reports go to the domain, not the sender) | Every rejection carries a registered reason code, returned to the sending server |
| Per-user signatures | S/MIME or OpenPGP only, rarely deployed | Optional `Mail-User-Signature`, using the same S/MIME certificate |
| What each server keeps from your mail | Unknown. At best it's in a privacy policy somewhere | Declared per field (sender, recipients, subject, headers, body, attachments, connection) in a signed `Mail-Retention` header field from every server, shown in the mail client |
| Redirected mail | Silent. SPF breaks, and ARC tries to patch it | A signed `Mail-Redirect` names both domains, and both are verifiable by the mail client |
| DNSSEC | Optional, and rarely relied on by mail | RECOMMENDED for every DMS zone, always validated, with the result shown to the recipient |
| Mail routing and auth DNS records per domain | MX + 5–6 others, plus an HTTPS policy host | 3: `_mail` TXT, `_dms-smtp._tcp` SRV, `_dms-send._tcp` SRV |
| Cleartext ports | 25 (before STARTTLS), 587, 143, 110 | 0 |
| Weak login methods offered | APOP, CRAM-MD5, DIGEST-MD5, NTLM, Basic, ANONYMOUS | None |
| RFCs in the stack | 161 | 140 (139 current RFCs plus the DMS draft) |
