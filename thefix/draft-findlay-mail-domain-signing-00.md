```
Internet Engineering Task Force                               M. Findlay
Internet-Draft                                              going-postal
Intended status: Standards Track                       13 November 2026
Updates: 5321, 5322, 6409 (if approved)
Expires: 17 May 2027
```

# Domain Mail Signing (DMS): Certificate-Bound Domain Keys, Authenticated Hops and Mandatory Encryption for Internet Mail

`draft-findlay-mail-domain-signing-00`

## Abstract

This document defines Domain Mail Signing (DMS), a single mechanism for authenticating the source of Internet mail. A domain publishes one or more public keys in DNS TXT records at `_mail.<domain>`. Each key is also bound to an X.509 certificate issued through the existing public Web PKI. SRV records in the same zone name the servers that may receive mail for the domain and the servers that may send it. Which SRV records a domain publishes also states its policy. The domain's key signs every message from that domain and its subdomains. Every server that handles the message afterwards, whether it delivers peer to peer or relays through a delivery hub, adds a signed hop record to the message header. Individual users can also sign their own mail with personal keys bound to their existing S/MIME certificates. Every server that handles a message declares in a signed header field what data it keeps. Redirects name both the redirecting and the new domain, and DNSSEC is recommended for every participating zone. All mail traffic, including server-to-server relay, MUST be carried over mutually authenticated TLS. Mail is only ever communicated over SMTP, IMAP or POP3 with implicit TLS, or over HTTPS-based Exchange and JMAP connections. Nothing is ever sent unencrypted.

Once fully adopted, DMS replaces SPF, DKIM, DMARC, ARC, STARTTLS, MTA-STS, DANE for SMTP, TLS-RPT, REQUIRETLS and Null MX with one protocol.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task Force (IETF). Note that other groups may also distribute working documents as Internet-Drafts. The list of current Internet-Drafts is at <https://datatracker.ietf.org/drafts/current/>.

Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as "work in progress."

This Internet-Draft will expire on 17 May 2027.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights reserved.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Conventions and Terminology](#2-conventions-and-terminology)
3. [Overview](#3-overview)
4. [DNS Records](#4-dns-records)
   - 4.1–4.5 [`_mail` TXT: keys and hub authorisations](#41-location)
   - 4.6 [`_dms-smtp._tcp` SRV: receiving servers](#46-receiving-servers-_dms-smtp_tcp)
   - 4.7 [`_dms-send._tcp` SRV: sending servers](#47-sending-servers-_dms-send_tcp)
   - 4.8 [Policy](#48-policy)
   - 4.9 [Submission and access SRV records](#49-submission-and-access)
   - 4.10 [`_user._mail` TXT: user keys](#410-user-keys-_user_mail)
   - 4.11 [DNSSEC](#411-dnssec)
5. [Certificate Binding](#5-certificate-binding)
6. [The `Mail-Signature` Header Field](#6-the-mail-signature-header-field)
   - 6.5 [User signatures: `Mail-User-Signature`](#65-user-signatures-mail-user-signature)
7. [The `Mail-Hop` Header Field](#7-the-mail-hop-header-field)
   - 7.5 [Data retention: `Mail-Retention`](#75-data-retention-mail-retention)
   - 7.6 [Final delivery: `Mail-Delivered`](#76-final-delivery-mail-delivered)
8. [Delivery Paths: Peer-to-Peer and Hub](#8-delivery-paths-peer-to-peer-and-hub)
9. [Mandatory Encryption](#9-mandatory-encryption)
   - 9.1 [Permitted connections](#91-permitted-connections)
   - 9.2 [Prohibited mechanisms](#92-prohibited-mechanisms)
10. [Verification Procedure](#10-verification-procedure)
    - 10.1 [Failure reporting and bounces](#101-failure-reporting-and-bounces)
    - 10.2 [Verification and display by mail clients](#102-verification-and-display-by-mail-clients)
11. [Forwarding and Mailing Lists](#11-forwarding-and-mailing-lists)
    - 11.1 [Redirection: `Mail-Redirect`](#111-redirection-mail-redirect)
12. [Transition and Coexistence](#12-transition-and-coexistence)
13. [IANA Considerations](#13-iana-considerations)
14. [Security Considerations](#14-security-considerations)
15. [Privacy Considerations](#15-privacy-considerations)
16. [References](#16-references)
- [Appendix A. Complete Example](#appendix-a-complete-example)
- [Appendix B. Open Issues](#appendix-b-open-issues)

---

## 1. Introduction

Today, authenticating the source of an email message takes three separate, independently deployed mechanisms:

- SPF [RFC7208] authorises IP addresses.
- DKIM [RFC6376] signs messages with keys published in DNS.
- DMARC [RFC9989] ties the two to the visible `From:` domain and publishes a policy for failures.

A fourth mechanism, ARC [RFC8617], tries to keep authentication results intact across intermediaries that break the first three.

Transport encryption is similarly fragmented. STARTTLS [RFC3207] is opportunistic and can be stripped. MTA-STS [RFC8461] and DANE [RFC7672] are two different ways to make it mandatory. TLS-RPT [RFC8460] reports when they fail, and REQUIRETLS [RFC8689] lets a sender ask for TLS on a per-message basis.

Each of these mechanisms is optional. Each has its own DNS record, failure modes and partial-adoption problems. Receivers must therefore combine several weak signals rather than check one strong one.

This document replaces all of them with one design built on three principles:

1. **One key, one place.** A domain's keys live at `_mail.<domain>`. They are bound both to DNS and to a certificate from the existing public CA infrastructure. One signature from the domain covers the domain and everything beneath it.
2. **Servers and policy in the zone.** SRV records list the servers that may receive and send mail for the domain. Their presence is the domain's policy, so there is no separate policy record, web host or reporting address.
3. **Every hop is accountable.** Each server that handles a message, whether a peer MTA or a delivery hub such as a cloud email service, authenticates to the next with mutual TLS. It also records its handling in a signed `Mail-Hop` header field, giving a verifiable chain of custody.
4. **No cleartext, ever.** Every connection is TLS 1.3 or later. Downgrade is not a failure mode, because there is nothing to fall back to.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

The architectural terms MUA, MSA, MTA and MDA are as defined in [RFC5598].

**Signing Domain**
: The domain whose key produces the `Mail-Signature` on a message. It is the domain in the `From:` header field, or a parent of that domain.

**Domain Key**
: A key pair whose public half appears in a `_mail` record and in a valid X.509 certificate for the Signing Domain.

**Hub**
: A service or endpoint that accepts mail on behalf of one or more domains and delivers it onward. Examples are cloud delivery services such as Amazon SES on AWS or Azure Communication Services email. Inbound filtering gateways operated for a recipient domain are also Hubs. A Hub has its own domain and its own Domain Keys.

**Peer**
: An MTA operated by the Signing Domain or the recipient domain itself, as opposed to a Hub.

**Hop**
: One authenticated transfer of a message from one server to the next.

**Full Adoption**
: The point at which a receiving domain no longer accepts mail that lacks a valid DMS signature and hop chain. See [Section 12](#12-transition-and-coexistence).

## 3. Overview

```
  domain.uk                                                  recipient.example
 ┌──────────┐  mTLS  ┌──────────────────┐  mTLS  ┌─────────────────────────┐
 │ MSA/MTA  │ ─────▶ │ Hub (optional)   │ ─────▶ │ MX of recipient.example │
 │ signs    │        │ e.g. cloud email │        │ verifies signature and  │
 │ Mail-    │        │ service; adds    │        │ every Mail-Hop, then    │
 │ Signature│        │ Mail-Hop i=2     │        │ delivers                │
 │ adds     │        └──────────────────┘        └─────────────────────────┘
 │ Mail-Hop │
 │ i=1      │   DNS for domain.uk (sender):
 └──────────┘     _mail.domain.uk           TXT "v=DMS1; k=…; p=…"       (domain key)
                  _mail.domain.uk           TXT "v=DMS1; h=hub.example"  (hub authorised)
                  _dms-send._tcp.domain.uk  SRV 90 10 <dms-port> out1.domain.uk.  (sender; 90-day policy)
                DNS for recipient.example (receiver):
                  _dms-smtp._tcp.recipient.example  SRV 10 0 <dms-port> mx1.recipient.example.
```

1. The sending domain publishes its public key at `_mail.domain.uk`. The same key is certified by a publicly trusted CA for `domain.uk`.
2. The sending domain lists its outbound servers in `_dms-send._tcp`. The receiving domain lists its inbound servers in `_dms-smtp._tcp`. Publishing these records states that each domain enforces DMS.
3. The originating server signs the message with the domain's private key. It adds a `Mail-Signature` header field that carries the certificate.
4. The message is delivered over mutual TLS, either directly to a server listed in the recipient's `_dms-smtp._tcp` (peer to peer) or to a Hub the sending domain has authorised in its `_mail` record. The sender confirms the receiving server against the SRV record and the receiver's keys. The receiver confirms the sending server against `_dms-send._tcp` and the sender's keys.
5. Each server that transmits the message adds a signed `Mail-Hop` header field.
6. The receiving server verifies the domain signature, the certificate and the full hop chain. Any failure is a permanent rejection.

## 4. DNS Records

DMS uses two kinds of DNS record in the domain's zone:

- **TXT records at `_mail.<domain>`** ([Sections 4.1–4.5](#41-location)) publish the domain's keys and the Hubs it authorises. They answer the question "which keys and which services speak for this domain?"
- **SRV records** [RFC2782] ([Sections 4.6–4.9](#46-receiving-servers-_dms-smtp_tcp)) name the servers that receive and send mail for the domain, and their presence states the domain's policy. They answer the question "which machines, and is DMS enforced?"

### 4.1. Location

DMS records are TXT records [RFC1035] published at the underscored name `_mail` [RFC8552] directly beneath the domain they cover:

```
_mail.domain.uk.
```

A domain MAY publish any number of DMS records at that name. Each record describes either one key or one hub authorisation. Records that do not begin with `v=DMS1` MUST be ignored.

### 4.2. Syntax

A record is a sequence of `tag=value` pairs separated by semicolons. The tag-list syntax is the same as in Section 3.2 of [RFC6376].

```abnf
dms-record   = dms-version *( *WSP ";" *WSP dms-tag ) [ *WSP ";" ]
dms-version  = %s"v=DMS1"
dms-tag      = key-id / alg / pubkey / usage / scope / hub / expiry / ext-tag
key-id       = %s"k=" 1*32( ALPHA / DIGIT / "-" / "." )
alg          = %s"a=" ( %s"ecdsa-p256-sha256" / %s"ecdsa-p384-sha384"
                      / %s"rsa-pss-sha256" / %s"ed25519" )   ; see Section 4.3.2
pubkey       = %s"p=" base64-spki        ; DER SubjectPublicKeyInfo, base64
usage        = %s"u=" use *( "," use )
use          = 1*64use-char              ; free-form; see Section 4.3.1
use-char     = %x21-2B / %x2D-3A / %x3C / %x3E-7E
                                         ; any visible ASCII except "," ";" "="
scope        = %s"s=" ( %s"tree" / %s"self" )
hub          = %s"h=" domain-name        ; hub authorisation; no k/a/p
expiry       = %s"x=" 1*12DIGIT          ; seconds since the Unix epoch
ext-tag      = tag-name "=" tag-value    ; unknown tags MUST be ignored
```

### 4.3. Tags

| Tag | Required | Meaning |
|-----|----------|---------|
| `v` | Yes | Version. MUST be the first tag and MUST be `DMS1`. |
| `k` | For key records | Key identifier, unique among the domain's `_mail` records. It is referenced by `Mail-Signature` and `Mail-Hop`. |
| `a` | For key records | Signature algorithm. |
| `p` | For key records | Public key as a base64 DER `SubjectPublicKeyInfo`. An empty `p=` revokes the key identified by `k`. |
| `u` | No (default `mail`) | Permitted uses: a comma-separated list of free-form text values. Any string of up to 64 visible characters (other than `,`, `;` and `=`) is a valid use, so a domain can publish keys for any purpose in one place. Only the values in [Section 4.3.1](#431-usage-values) have meaning to DMS. |
| `s` | No (default `tree`) | Scope. `tree` covers the domain and every subdomain that does not publish its own `_mail` records. `self` covers only the exact domain. |
| `h` | For hub records | Domain of a Hub authorised to relay mail for this domain, inbound or outbound. A record with `h=` MUST NOT carry `k`, `a` or `p`. |
| `x` | No | Expiry time. After it, verifiers MUST treat the key as revoked. |

#### 4.3.1. Usage Values

The `u=` tag is deliberately open-ended. `_mail` is the place where a domain publishes all of its keys, and DMS defines only the uses it needs itself. Any other application may define its own value and look up keys at `_mail.<domain>` with that value.

**Values defined by this document:**

| Value | Meaning |
|-------|---------|
| `mail` | Signs `Mail-Signature` for messages that originate from the domain ([Section 6](#6-the-mail-signature-header-field)). |
| `relay` | Signs `Mail-Hop` records and authenticates the domain's servers in mutual TLS ([Section 7](#7-the-mail-hop-header-field), [Section 9](#9-mandatory-encryption)). |
| `any` | Every use, including values not yet defined. NOT RECOMMENDED; see [Section 14.9](#149-free-form-usage-values). |

**Other values** are free-form. These are illustrative examples, not an exhaustive list:

| Example value | Possible use |
|---------------|--------------|
| `web` | The key also serves the domain's HTTPS web servers |
| `api` | Signs or authenticates API requests and webhooks from the domain |
| `ssh` | SSH host key for the domain's servers |
| `vpn` | VPN or IPsec gateway identity |
| `code-signing` | Signs software or packages the domain publishes |
| `document-signing` | Signs invoices, statements or other documents the domain issues |
| `calendar` | Signs iTIP calendar invitations |
| `iot` | Identity for the domain's devices |
| `domain.uk:invoices` | A private use specific to one organisation |

**Rules:**

1. Values are compared case-insensitively (ASCII) and MUST NOT contain whitespace, `,`, `;` or `=`.
2. DMS verifiers MUST act only on `mail`, `relay` and `any`. Wherever this document requires a `u=mail` or `u=relay` key, a key listing `any` also qualifies. Verifiers MUST ignore every other value. A key whose `u=` lists only other values MUST NOT be accepted for a `Mail-Signature`, a `Mail-Hop` or relay TLS authentication.
3. A key MAY list several values, for example `u=mail,relay,web`. Separate keys per use are RECOMMENDED ([Section 14.4](#144-key-reuse)).
4. Values that are not defined in a specification SHOULD be prefixed with a domain name the publisher controls, followed by `:`, for example `domain.uk:invoices`. This prevents two organisations from giving the same value different meanings.
5. Specifications that define a new value SHOULD register it in the "DMS Key Usage Values" registry ([Section 13.6](#136-dms-key-usage-values)). Registration is not required for a value to be valid.
6. Each application that defines a value also defines what a verifier checks for it, including whether the key must be bound to a certificate ([Section 5](#5-certificate-binding)) and which domain-separation string it signs with.

#### 4.3.2. Algorithms

| Algorithm | Status |
|---|---|
| `ecdsa-p256-sha256` | MUST be supported by verifiers. RECOMMENDED for signers today, because public CAs widely issue P-256 certificates. |
| `ecdsa-p384-sha384` | MUST be supported by verifiers. |
| `rsa-pss-sha256` | MUST be supported by verifiers. Keys MUST be at least 2048 bits. |
| `ed25519` | **Allowed, and intended for future use.** Verifiers MUST support it. Signers MAY use it wherever they can obtain an Ed25519 certificate from a trusted CA ([Section 5](#5-certificate-binding)). Until public CAs issue Ed25519 certificates widely, a domain using Ed25519 SHOULD also publish an ECDSA key, so that every verifier can validate at least one certificate chain. |

New algorithms, including post-quantum signature algorithms, can be added by updating this table. Verifiers MUST ignore keys with an `a=` they do not support, rather than failing the whole record set.

### 4.4. Example

The following records are for the illustrative domain `domain.uk`. Keys are truncated.

```dns
; Current message-signing key
_mail.domain.uk. 3600 IN TXT "v=DMS1; k=2026a; a=ecdsa-p256-sha256; u=mail,relay; p=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7c…"

; Next key, pre-published for rollover
_mail.domain.uk. 3600 IN TXT "v=DMS1; k=2027a; a=ecdsa-p256-sha256; u=mail,relay; p=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq9…"

; Key also used by the web servers for domain.uk
_mail.domain.uk. 3600 IN TXT "v=DMS1; k=web1; a=ecdsa-p256-sha256; u=web; p=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3f…"

; Keys for other uses (ignored by mail servers)
_mail.domain.uk. 3600 IN TXT "v=DMS1; k=api1; a=ecdsa-p256-sha256; u=api,webhooks; p=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8a…"
_mail.domain.uk. 3600 IN TXT "v=DMS1; k=inv1; a=ed25519; u=domain.uk:invoices; p=MCowBQYDK2VwAyEA…"

; Hubs this domain sends through
_mail.domain.uk. 3600 IN TXT "v=DMS1; h=amazonses.com"
_mail.domain.uk. 3600 IN TXT "v=DMS1; h=azurecomm.net"
```

### 4.5. Discovery and the Domain Tree

A domain key signs "the domain and everything from it". To find the key for a Signing Domain `D`, a verifier:

1. Queries `_mail.D` for TXT records.
2. If no DMS records exist, removes the leftmost label of `D` and repeats. It does not query a top-level domain and stops after at most 8 queries.
3. Uses the first record set found. Keys in that set with `s=self` apply only if the set was found at the original `D`.

A subdomain that publishes its own `_mail` records is therefore independent of its parent. A subdomain that publishes none inherits its parent's keys.

DNSSEC requirements for the `_mail` RRset and every other DMS record are in [Section 4.11](#411-dnssec).

### 4.6. Receiving Servers: `_dms-smtp._tcp`

A domain that receives mail over DMS publishes SRV records naming its inbound servers:

```dns
_dms-smtp._tcp.domain.uk. 3600 IN SRV 10 50 <dms-port> mx1.domain.uk.
_dms-smtp._tcp.domain.uk. 3600 IN SRV 10 50 <dms-port> mx2.domain.uk.
_dms-smtp._tcp.domain.uk. 3600 IN SRV 20  0 <dms-port> inbound.gateway.example.   ; inbound Hub
```

`<dms-port>` stands for the dedicated port that IANA is asked to assign ([Section 13.4](#134-service-names-and-port)).

- **Priority and weight** select between servers exactly as in [RFC2782].
- **Port** is the port on which the target accepts implicit-TLS DMS relay ([Section 9](#9-mandatory-encryption)). It SHOULD be the dedicated DMS port. DMS relay MUST NOT be offered on port 25. Keeping the new method on its own port means a server never has to guess whether an incoming connection is legacy SMTP (greeting first) or DMS (TLS first).
- **Target** is the host name of a receiving server. It MUST be within the domain's own tree, or within the domain of a Hub that the domain authorises with `h=` in its `_mail` records.
- A single record with target `.` means the domain **accepts no mail**. Senders MUST NOT attempt delivery and MUST return a permanent failure immediately. This replaces Null MX [RFC7505].

When `_dms-smtp._tcp` records exist, senders MUST use them in place of MX records for that domain.

**Falling back to legacy delivery.** A sender falls back to legacy delivery (MX on port 25) only when no DMS delivery server is available for the recipient domain. Here "available" means *published*, not *reachable*:

| Recipient domain's DNS | Sender behaviour |
|---|---|
| `_dms-smtp._tcp` lists one or more hosts | MUST deliver over DMS to those hosts on the port given. If none can be reached or confirmed, MUST queue and retry, and MUST NOT fall back to MX. |
| `_dms-smtp._tcp` has target `.` | MUST NOT deliver. The domain accepts no mail. |
| No `_dms-smtp._tcp` records, and no persisted policy ([Section 4.8](#48-policy)) | MAY fall back to legacy delivery through MX on port 25, during transition only ([Section 12](#12-transition-and-coexistence)). |
| No `_dms-smtp._tcp` records, but a persisted policy is in force | MUST treat the domain as if its last-seen records were still published. |

Falling back when DMS servers are published but unreachable would let an attacker force a downgrade simply by blocking the DMS port. That is why fallback depends on what is published, not on whether a connection succeeds.

**Confirming the receiving server.** After the TLS handshake, and before sending any SMTP command, the sender MUST confirm all of the following:

1. The server's certificate is valid under the Web PKI and contains a `dNSName` equal to the SRV target it connected to.
2. The SRV target is within the recipient domain's tree, or within a Hub domain listed with `h=` in the recipient domain's `_mail` records.
3. The server certificate's `SubjectPublicKeyInfo` matches a `u=relay` key found by running the [Section 4.5](#45-discovery-and-the-domain-tree) walk from the target host name. For `mx1.domain.uk` that finds `_mail.domain.uk`. For `inbound.gateway.example` it finds `_mail.gateway.example`.

If any check fails, the sender MUST close the connection and try the next SRV target. It MUST NOT fall back to MX.

### 4.7. Sending Servers: `_dms-send._tcp`

A domain that sends mail over DMS publishes SRV records naming the hosts that originate or relay mail for it. Every field of the SRV record is used:

```dns
;              service  proto        priority  weight  port        target
;                                    (days)    (share) (returns)
_dms-send._tcp.domain.uk. 3600 IN SRV 90       60      <dms-port>  out1.domain.uk.
_dms-send._tcp.domain.uk. 3600 IN SRV 90       40      <dms-port>  out2.domain.uk.
```

| Field | Meaning in `_dms-send._tcp` |
|---|---|
| **Service** `_dms-send` | The domain's DMS **sending** service. The counterpart of `_dms-smtp`, which is the receiving service. |
| **Protocol** `_tcp` | Sending and return traffic run over TCP with implicit TLS ([Section 9](#9-mandatory-encryption)). |
| **Priority** | The domain's **policy persistence period** in days (0–65535; see [Section 4.8](#48-policy)). All `_dms-send._tcp` records for a domain SHOULD carry the same value. If they differ, verifiers MUST use the largest. |
| **Weight** | Each host's relative share of the domain's outbound mail. Receivers MAY use it to spot anomalies, for example a host listed with weight 0 suddenly sending large volumes. Hubs and receivers also use it, as standard SRV weight [RFC2782], to choose which host to contact for return traffic. |
| **Port** | The port on which the sending host accepts **return traffic** for mail it sent: failure reports and DSNs ([Section 10.1](#101-failure-reporting-and-bounces)). This uses the DMS relay protocol with mutual TLS, and SHOULD be `<dms-port>`. Port `0` means the host accepts no return traffic, and returns go to the domain's `_dms-smtp._tcp` servers instead. |
| **Target** | The host name that the sending server presents in its TLS client certificate. |

The port makes each `_dms-send` record a genuine service location: the sending server can be reached at that host and port. Failures can therefore be returned directly to the server that sent the message, as [Section 10.1](#101-failure-reporting-and-bounces) requires.
- A single record with target `.` (for example `SRV 365 0 0 .`) means the domain **sends no mail**. Its priority still sets the persistence period. Receivers MUST reject any message whose `From:` domain, `MAIL FROM` domain or `Mail-Signature` `d=` falls under that domain. This replaces both the `v=spf1 -all` and DMARC `p=reject` records that parked domains publish today.

A domain that sends only through Hubs does not list the Hubs' hosts. The `h=` authorisation in `_mail` delegates to the Hub, and the Hub publishes its own `_dms-send._tcp` records.

**Confirming the sending server.** When a server accepts a connection, it identifies the client domain `D` as the domain whose `u=relay` key matches the client certificate. That domain becomes the final hop's `d=` ([Section 10](#10-verification-procedure)). The receiver MUST then confirm both of the following:

1. The client certificate contains a `dNSName` equal to one of the targets of `_dms-send._tcp.D`.
2. `D` publishes `_dms-send._tcp` records. If it publishes none, or only a `.` target, the receiver MUST reject the connection with `X.7.TBD3`.

A receiver MAY additionally check that the host name resolves (A/AAAA) to the connecting IP address. This is not required, because the certificate already proves the host's identity and large Hubs send from address pools.

This replaces SPF's IP-address allow-lists with named, certificate-backed hosts.

### 4.8. Policy

A domain's DMS policy is expressed by which records it publishes. No separate policy record, HTTPS policy host or reporting address is needed, and every policy signal can be signed with DNSSEC.

| Records published | Policy |
|---|---|
| `_mail` only | **Testing.** The domain signs its mail. Receivers verify and log the result but MUST NOT reject a message solely because DMS failed. Legacy SPF, DKIM and DMARC still apply. |
| `_mail` + `_dms-send._tcp` | **Sending enforced.** Every message from the domain is DMS-signed and sent from a listed host or an authorised Hub. Receivers MUST reject mail claiming the domain that lacks or fails DMS, even if legacy authentication passes. |
| `_mail` + `_dms-smtp._tcp` | **Receiving enforced.** Senders that implement DMS MUST deliver only through the listed servers and MUST NOT fall back to MX or STARTTLS. Senders that do not yet implement DMS reach the domain through MX for as long as the domain keeps MX records (Phase 2 in [Section 12](#12-transition-and-coexistence)). |
| `_mail` + both | **Full Adoption** for the domain ([Section 12](#12-transition-and-coexistence)). |
| `_dms-send._tcp` target `.` | The domain sends no mail. |
| `_dms-smtp._tcp` target `.` | The domain accepts no mail. |

**Policy persistence.** An attacker could remove or block a domain's SRV records to push its mail back onto legacy delivery. To prevent this downgrade, once a server has observed an enforcing policy (`_dms-send._tcp` or `_dms-smtp._tcp`), it MUST continue to apply that policy for a **persistence period set by the domain**:

- The period, in days, is the **priority field of the domain's `_dms-send._tcp` records** ([Section 4.7](#47-sending-servers-_dms-send_tcp)). It covers the domain's whole policy, both sending and receiving.
- If the domain publishes no `_dms-send._tcp` records, for example while only receiving is enforced, the period is 30 days.
- A value of `0` means the policy persists only for the records' TTL.
- Servers MUST honour values up to 365 and MAY cap larger values at 365.
- The policy is applied for the longer of the persistence period and the records' TTL, and the period restarts each time the records are seen again.

A server MAY stop applying the policy before the period ends only if a DNSSEC-validated response proves that the records no longer exist.

A domain that plans to stop enforcing SHOULD first lower the priority value, wait for the old period to expire, and only then remove the records. Domains SHOULD sign their zones.

### 4.9. Submission and Access

Domains SHOULD publish SRV records for each permitted client connection ([Section 9.1](#91-permitted-connections)) so that mail clients can find servers automatically. These are the records of [RFC6186] and [RFC8620], plus `_autodiscover._tcp` for Exchange. Only the implicit-TLS and HTTPS service names may point at a real host:

```dns
_submissions._tcp.domain.uk. 3600 IN SRV 0 1 465 mail.domain.uk.
_imaps._tcp.domain.uk.       3600 IN SRV 0 1 993 mail.domain.uk.
_pop3s._tcp.domain.uk.       3600 IN SRV 0 1 995 mail.domain.uk.
_autodiscover._tcp.domain.uk. 3600 IN SRV 0 1 443 mail.domain.uk.   ; Exchange
_jmap._tcp.domain.uk.        3600 IN SRV 0 1 443 mail.domain.uk.

; Cleartext and STARTTLS services explicitly not offered
_submission._tcp.domain.uk.  3600 IN SRV 0 0 0 .
_imap._tcp.domain.uk.        3600 IN SRV 0 0 0 .
_pop3._tcp.domain.uk.        3600 IN SRV 0 0 0 .
```

Clients MUST NOT connect to a cleartext service name, even if its record names a host.

### 4.10. User Keys: `_user._mail`

Individual users can also sign their own mail, separately from the domain. Each user has a key pair whose private half is held only by the user, for example in their mail client, and never by the domain or a Hub. The public half is published under the domain's `_mail` name:

```
<hash>._user._mail.<domain>
```

`<hash>` is the SHA-256 digest of the address's local part in UTF-8, truncated to 28 octets and written as 56 lowercase hexadecimal characters. This is the same construction OPENPGPKEY uses [RFC7929]. It keeps local parts that are not valid DNS labels representable, and avoids publishing addresses in clear text.

```dns
; alice@domain.uk  (hash shown truncated)
2bd806c97f0e00af1a1fc3328fa763a9…._user._mail.domain.uk. 3600 IN TXT
    "v=DMS1; k=alice2026; a=ecdsa-p256-sha256; u=user; p=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5b…"
```

- User records use the same syntax as domain records ([Section 4.2](#42-syntax)) and MUST include `u=user`.
- A user key is valid only at a `_user._mail` name, and a domain key is never valid as a user key. `u=any` at a `_user._mail` name means `user` only.
- A user MAY have several keys, for example one per device, distinguished by `k=`.
- The [Section 4.5](#45-discovery-and-the-domain-tree) tree walk does not apply. User keys are looked up only under the exact domain of the address.
- The key MUST be bound to a certificate for the address ([Section 5](#5-certificate-binding), item 4).

The resulting `Mail-User-Signature` is described in [Section 6.5](#65-user-signatures-mail-user-signature).

### 4.11. DNSSEC

Domains that publish DMS records are RECOMMENDED to sign their zones with DNSSEC [RFC4033] [RFC4034] [RFC4035]. This recommendation is part of this specification, not an optional extra. DMS works without DNSSEC, but a signed zone closes attacks that the certificate binding alone cannot.

**Publishers:**

1. Every zone containing `_mail`, `_user._mail`, `_dms-smtp._tcp`, `_dms-send._tcp` or client SRV records ([Section 4.9](#49-submission-and-access)) SHOULD be DNSSEC-signed, with a DS record in the parent zone.
2. Hubs SHOULD sign their zones. They carry other domains' mail, and their keys and SRV records are relied on by every domain that authorises them.
3. Zones that publish user keys SHOULD use NSEC3 configured as in [RFC9276], or online signing with compact denial of existence, to limit enumeration of `_user._mail` names ([Section 15](#15-privacy-considerations)).
4. Domains SHOULD sign their zones before entering Phase 3 of the transition ([Section 12](#12-transition-and-coexistence)).

**Verifiers** (sending servers, receiving servers and mail clients):

1. MUST perform DNSSEC validation on every DMS lookup.
2. MUST treat a *bogus* response (validation failed) as a failure. They MUST NOT fall back to treating it as insecure.
3. MAY accept *insecure* (unsigned) responses, because the certificate binding in [Section 5](#5-certificate-binding) provides an independent second anchor.
4. MUST record the result for each domain in `Mail-Delivered` `dnssec=` ([Section 7.6](#76-final-delivery-mail-delivered)), so the recipient's mail client can show it.

**What DNSSEC adds:**

| Without DNSSEC | With DNSSEC |
|---|---|
| A forged `_mail` key is useless without a matching CA certificate, but the forged answer itself goes undetected. | Forged answers are detected and rejected. |
| An attacker who blocks or strips SRV records can hide a policy until the persistence period expires ([Section 4.8](#48-policy)). | Authenticated denial proves whether records exist, so policies cannot be hidden, and can be removed early by the domain. |
| SRV redirection to a rogue server fails the key check, but costs a delivery attempt. | SRV answers cannot be forged. |
| A CA that validates domain control by DNS can be fooled by DNS spoofing. | The DNS used for CA validation is itself authenticated. |

## 5. Certificate Binding

DMS uses the existing public certificate infrastructure as a second, independent trust anchor alongside DNS.

1. Every key with `u` containing `mail`, `relay` or `any` MUST have its `SubjectPublicKeyInfo` contained in an X.509 certificate [RFC5280] that:
   - chains to a root in the verifier's Web PKI trust store;
   - contains a `dNSName` SubjectAltName equal to the domain at which the `_mail` record was found, or a wildcard covering it;
   - is currently valid and not revoked;
   - carries at least two valid Signed Certificate Timestamps [RFC9162].
2. The certificate MAY be the same certificate the domain already uses for HTTPS (`u=web`), so a domain can reuse what it already has. Separate keys per use are RECOMMENDED; see [Section 14.4](#144-key-reuse).
3. A forged DNS record is useless without a CA-issued certificate for the same key. A mis-issued certificate is useless without control of the domain's DNS. An attacker must compromise both.
4. Every **user key** ([Section 4.10](#410-user-keys-_user_mail)) MUST have its `SubjectPublicKeyInfo` contained in an X.509 certificate that:
   - contains an `rfc822Name` SubjectAltName, or an `SmtpUTF8Mailbox` for internationalised addresses [RFC9598], equal to the user's address;
   - permits email protection, as an S/MIME certificate does [RFC8550];
   - chains to a root that the verifier trusts for email;
   - is currently valid and not revoked.

   This is the existing S/MIME certificate infrastructure, and CAA for email addresses [RFC9495] applies. The same certificate MAY also be used for S/MIME.

The signer includes the leaf certificate in the `c=` tag of `Mail-Signature`, `Mail-User-Signature` or `Mail-Hop`, so verifiers do not need to fetch it. Intermediate certificates MAY be included in `c=` as a comma-separated list, leaf first.

## 6. The `Mail-Signature` Header Field

### 6.1. Purpose

`Mail-Signature` asserts that the Signing Domain originated the message. Exactly one valid `Mail-Signature` MUST be present, apart from the `Original-Mail-Signature` case in [Section 11](#11-forwarding-and-mailing-lists).

### 6.2. Syntax

```abnf
mail-signature = "Mail-Signature:" [FWS] ms-tag-list CRLF
ms-tag-list    = ms-tag *( [FWS] ";" [FWS] ms-tag ) [ [FWS] ";" ]
ms-tag         = %s"v=1" / sig-d / sig-k / sig-a / sig-t / sig-h / sig-bh
               / sig-c / sig-b / ext-tag
sig-d  = %s"d="  domain-name     ; Signing Domain
sig-k  = %s"k="  key-id          ; matches k= in the _mail record
sig-a  = %s"a="  alg
sig-t  = %s"t="  1*12DIGIT       ; signing time, Unix epoch seconds
sig-h  = %s"h="  hdr-name *( ":" hdr-name )   ; signed header fields
sig-bh = %s"bh=" base64          ; SHA-256 of the canonical body
sig-c  = %s"c="  base64-der *( "," base64-der )   ; certificate(s)
sig-b  = %s"b="  base64          ; signature
```

### 6.3. Signed Content

- `h=` MUST include `From`, `To`, `Cc` (if present), `Date`, `Subject`, `Message-ID`, `MIME-Version` and `Content-Type`. If a listed header field is absent, it is signed as absent, as in Section 5.4 of [RFC6376].
- The body is hashed after normalising line endings to CRLF only. No other canonicalisation is applied. Hops MUST NOT modify the body or any signed header field; see [Section 11](#11-forwarding-and-mailing-lists).
- The signature input is the octet string `"DMS1 message\0"`, followed by the signed header fields in `h=` order, followed by the `Mail-Signature` field itself with an empty `b=` value. This context string separates DMS signatures from TLS and other uses of the same key.

### 6.4. Alignment

The domain in the `From:` header field MUST equal `d=` or be a subdomain of `d=`, subject to `s=`. The envelope `MAIL FROM` domain [RFC5321], if non-null, MUST satisfy the same rule. When `MAIL FROM` is null, as it is for bounces ([Section 10.1](#101-failure-reporting-and-bounces)), only the `From:` rule applies. There is no relaxed mode. This replaces DMARC identifier alignment.

### 6.5. User Signatures: `Mail-User-Signature`

A user MAY sign their own message, in addition to the domain's mandatory `Mail-Signature`. The user's mail client adds the user signature before submission, using the user's own private key. The domain cannot produce or alter it.

```abnf
mail-user-signature = "Mail-User-Signature:" [FWS] mus-tag-list CRLF
mus-tag   = %s"v=1" / mus-u / sig-k / sig-a / sig-t / sig-h / sig-bh
          / sig-c / sig-b / ext-tag
mus-u     = %s"u=" addr-spec          ; the signing user's address
```

- **Signed content** is the same as for `Mail-Signature` ([Section 6.3](#63-signed-content)), but the context string is `"DMS1 user\0"`.
- **Alignment.** `u=` MUST equal the address in the `From:` header field. A message with more than one `From:` address MUST NOT carry a user signature.
- **Key lookup.** The verifier looks up `<hash>._user._mail.<domain of u=>`, selects the record with matching `k=`, and validates the certificate as in [Section 5](#5-certificate-binding), item 4.
- **Binding to the domain signature.** When `Mail-User-Signature` is present, the domain's `Mail-Signature` `h=` MUST include `Mail-User-Signature`. This ties the user signature to the domain signature.
- **Optional, but checked if present.** Messages without a user signature are valid. If a user signature is present, the receiver MUST verify it, and failure is a permanent rejection with reason `user-signature-invalid` ([Section 10.1](#101-failure-reporting-and-bounces)).
- **Display.** The receiving MDA keeps the header field. A user's mail client MAY re-verify it and show the message as signed by that individual, as distinct from merely sent from the domain.

User signatures prove *who* wrote a message. They do not encrypt it. End-to-end encryption, so that providers and Hubs cannot read the content, remains the job of S/MIME [RFC8551] and OpenPGP [RFC9580], which can use the same certificate.

## 7. The `Mail-Hop` Header Field

### 7.1. Purpose

`Mail-Hop` records each transfer of the message in the existing header-field model. It sits alongside `Received:` [RFC5321] but, unlike `Received:`, it is signed and verifiable. Every server that transmits a message to another server MUST prepend exactly one `Mail-Hop` before transmitting. That includes the originating MTA, every Hub and every forwarder.

Alongside its `Mail-Hop`, each such server MUST also prepend:

- a `Mail-Retention` field declaring what it keeps from the message ([Section 7.5](#75-data-retention-mail-retention));
- if it redirected the message to another domain, a `Mail-Redirect` field ([Section 11.1](#111-redirection-mail-redirect)).

The final receiving server adds `Mail-Delivered` and its own `Mail-Retention` ([Section 7.6](#76-final-delivery-mail-delivered)). Together these give mail clients a complete, signed account of who handled the message and what each party kept.

### 7.2. Syntax

```abnf
mail-hop  = "Mail-Hop:" [FWS] hop-tag-list CRLF
hop-tag   = hop-i / sig-d / sig-k / sig-a / sig-t / hop-to / hop-tls
          / sig-c / sig-b / ext-tag
hop-i     = %s"i="   1*3DIGIT        ; 1 for the first hop, then 2, 3, …
hop-to    = %s"to="  domain-name     ; domain authenticated as the TLS peer
hop-tls   = %s"tls=" token           ; e.g. TLSv1.3
```

### 7.3. Signed Content

The `Mail-Hop` signature is made with a `u=relay` key of the hop's own domain (`d=`). It covers the following, in order:

1. the octet string `"DMS1 hop\0"`;
2. the `Mail-Signature` field, then the `Mail-User-Signature` field if present;
3. for each earlier hop, in order of `i=`: its `Mail-Hop`, its `Mail-Retention` and any `Mail-Redirect`;
4. the current hop's `Mail-Retention` and any `Mail-Redirect`;
5. the current `Mail-Hop` field with an empty `b=` value.

Each hop therefore commits to the whole chain before it, and to its own data declaration. A server cannot later deny what it declared.

### 7.4. Hop Authorisation

A hop `i` with domain `d` is **authorised** when one of the following holds:

| Hop | Authorised if `d` is … |
|-----|------------------------|
| `i=1` | the Signing Domain or one of its subdomains, **or** a Hub listed with `h=` in the Signing Domain's `_mail` records |
| `i>1` | the `to=` domain of hop `i-1`, **or** a Hub listed with `h=` in the `_mail` records of that `to=` domain |

This lets a domain authorise its outbound Hubs, and lets a recipient domain authorise its own inbound gateways, without any party listing IP addresses.

### 7.5. Data Retention: `Mail-Retention`

Every server that handles a message MUST declare, in the message itself, what information it keeps once it has finished processing the message. That includes the originating server connecting directly, every Hub, every forwarder and the final receiving server. Logging is therefore transparent to everyone who can read the message.

#### 7.5.1. Syntax

```abnf
mail-retention = "Mail-Retention:" [FWS] ret-tag-list CRLF
ret-tag     = hop-i / sig-d / ret-cat / ret-purpose / ret-loc
            / ret-share / ret-policy / ext-tag
ret-cat     = category "=" holding
category    = %s"sender" / %s"recipients" / %s"subject" / %s"headers"
            / %s"body" / %s"attachments" / %s"connection"
holding     = %s"none" / "0" / 1*5DIGIT %s"d" / %s"indef" / %s"mailbox"
ret-purpose = %s"purpose=" token *( "," token )
ret-loc     = %s"loc=" country *( "," country )   ; ISO 3166-1 alpha-2
ret-share   = %s"share=" ( %s"none" / domain-name *( "," domain-name ) )
ret-policy  = %s"policy=" https-uri
```

#### 7.5.2. Categories

All seven categories MUST be declared. Omitting one is an error, so that silence can never be read as "not kept".

| Category | Covers |
|---|---|
| `sender` | Envelope `MAIL FROM`, and the `From:`, `Sender:` and `Reply-To:` addresses |
| `recipients` | Envelope `RCPT TO`, and the `To:`, `Cc:` and `Bcc:` addresses |
| `subject` | The `Subject:` header field |
| `headers` | All other header fields, including `Message-ID` and `Date` |
| `body` | Message content, meaning the text and HTML parts |
| `attachments` | Attached files and other non-body MIME parts |
| `connection` | Connection metadata: IP addresses, TLS parameters, timestamps, sizes and verification results |

#### 7.5.3. Holding Values

| Value | Meaning |
|---|---|
| `none` | Not accessed beyond passing it on. Not inspected and not retained. |
| `0` | Inspected during processing, for example scanned for malware, but not retained once the message has left the server. |
| `<n>d` | Retained for up to `n` days after processing, in logs, queues, archives or backups. |
| `indef` | Retained with no fixed limit. |
| `mailbox` | Final receiving server only. Delivered to the recipient's mailbox and kept under the recipient's control. |

#### 7.5.4. Other Tags

| Tag | Required | Meaning |
|---|---|---|
| `i` | Yes | The hop index this declaration belongs to. It equals the `i=` of the server's `Mail-Hop`, or of `Mail-Delivered` for the final server. |
| `d` | Yes | The declaring server's domain. It MUST equal `d=` of the matching `Mail-Hop` or `Mail-Delivered`. |
| `purpose` | Yes, if anything is retained | Why data is retained, using values from the DMS Retention Purposes registry ([Section 13.9](#139-dms-retention-purposes)), for example `delivery`, `security`, `abuse`, `legal` or `billing`. |
| `loc` | Yes, if anything is retained | The countries where retained data is stored. |
| `share` | Yes | Third parties that receive any retained data, or `none`. |
| `policy` | RECOMMENDED | An HTTPS URL for the server's full retention and logging policy. |

#### 7.5.5. Example

```
Mail-Retention: i=2; d=amazonses.com;
  sender=30d; recipients=30d; subject=none; headers=30d;
  body=0; attachments=0; connection=90d;
  purpose=delivery,abuse,security; loc=IE,US; share=none;
  policy=https://hub.example/mail-retention
```

This reads: the Hub keeps the sender and recipient addresses and other header fields for 30 days, and connection data for 90 days. It never looks at the subject. It scans the body and attachments but keeps neither. Data is stored in Ireland and the United States and is not shared with anyone else.

#### 7.5.6. Rules

1. A declaration covers **everything** the server's operator keeps from the message: logs, queues, archives, backups, analytics and copies held by its subprocessors. Data passed to a party listed in `share=` is covered by that party's own policy, which SHOULD be linked from `policy=`.
2. A declaration MUST describe actual practice, and an operator MUST update it before changing that practice. Each declaration is covered by the server's hop signature ([Section 7.3](#73-signed-content)), so it is attributable to the declaring domain and cannot later be denied.
3. A receiver MUST reject a message in which any `Mail-Hop` has no matching `Mail-Retention`, or in which a `Mail-Retention` is malformed or omits a category. The failure reasons are `retention-missing` and `retention-invalid` ([Section 13.7](#137-dms-failure-reasons)).
4. Receivers MAY apply local policy to declarations, for example refusing mail relayed by a server that declares `body=indef` with `share=` third parties. They MUST still use the standard failure reporting ([Section 10.1](#101-failure-reporting-and-bounces)).
5. Mail clients SHOULD make declarations visible to users ([Section 10.2](#102-verification-and-display-by-mail-clients)).

### 7.6. Final Delivery: `Mail-Delivered`

After a message passes verification ([Section 10](#10-verification-procedure)), the final receiving server MUST prepend a `Mail-Delivered` field and its own `Mail-Retention` before handing the message to the mailbox. This is the receiving domain's signed confirmation that it received and verified the message. It lets the recipient's mail client confirm the authenticity of the receiving domain as well as the sender.

```abnf
mail-delivered = "Mail-Delivered:" [FWS] del-tag-list CRLF
del-tag     = hop-i / sig-d / sig-k / sig-a / sig-t / del-dnssec
            / sig-c / sig-b / ext-tag
del-dnssec  = %s"dnssec=" dom-state *( "," dom-state )
dom-state   = domain-name ":" ( %s"secure" / %s"insecure" )
```

- `i=` is one more than the last `Mail-Hop`.
- `d=` is the receiving domain. If the message was redirected, this is the **new** domain.
- `dnssec=` records, for every domain whose records were used in verification, whether those records were DNSSEC-validated ([Section 4.11](#411-dnssec)).
- The signature uses a `u=relay` key of `d=` with the context string `"DMS1 delivered\0"`. It covers everything a `Mail-Hop` signature would, plus the receiver's own `Mail-Retention`.

```
Mail-Delivered: i=3; d=recipient.example; k=mx1; a=ecdsa-p256-sha256;
  t=1794571263; dnssec=domain.uk:secure,amazonses.com:secure,recipient.example:secure;
  c=MIIC…; b=MEQCIF…
```

## 8. Delivery Paths: Peer-to-Peer and Hub

### 8.1. Peer to Peer

The originating MTA resolves the recipient domain's `_dms-smtp._tcp` SRV records ([Section 4.6](#46-receiving-servers-_dms-smtp_tcp)). It connects directly over mutual TLS ([Section 9](#9-mandatory-encryption)) and confirms the receiving server before sending. MX records [RFC5321] are consulted only during transition, and only when no DMS delivery server is published ([Section 4.6](#46-receiving-servers-_dms-smtp_tcp)). The message carries `Mail-Signature` and one `Mail-Hop` (`i=1`, `d=domain.uk`, `to=recipient.example`).

### 8.2. Via a Hub

A domain that uses a delivery service publishes `h=<hub domain>` in its `_mail` records. Hubs include existing services such as Amazon SES on AWS and the email services on Azure. The domain then either:

- **(a) Signs locally.** The domain's own MSA/MTA adds `Mail-Signature` and `Mail-Hop i=1 to=<hub>`, and the Hub adds `Mail-Hop i=2`. Or:
- **(b) Delegates signing.** The domain publishes, under its own `_mail` name, a `u=mail` key whose private half is held by the Hub. The certificate for that key MUST still name the domain. The Hub then adds both `Mail-Signature` and `Mail-Hop i=1`.

The Hub authenticates to the next server with its own certificate and signs its `Mail-Hop` with its own `u=relay` key published at `_mail.<hub domain>`. The Hub's sending hosts are listed in `_dms-send._tcp.<hub domain>`.

A recipient domain that uses an inbound Hub, such as a filtering gateway, lists the Hub's host names as targets in its own `_dms-smtp._tcp` records and authorises the Hub with `h=`.

Hubs MAY chain: a Hub may relay to another Hub authorised by the recipient domain, such as an inbound filtering gateway. Every link must satisfy [Section 7.4](#74-hop-authorisation).

## 9. Mandatory Encryption

DMS removes cleartext from every part of the mail system.

1. **Relay (MTA to MTA, MTA to Hub, Hub to MX).** Connections are made to the dedicated DMS port ([Section 13.4](#134-service-names-and-port)), not port 25. They MUST use TLS 1.3 [RFC8446] or later from the first octet ("implicit TLS"). The TLS ALPN identifier `dms-smtp` is used ([Section 13](#13-iana-considerations)). Both sides MUST present certificates:
   - The server presents a certificate for its `_dms-smtp._tcp` target host name, confirmed as described in [Section 4.6](#46-receiving-servers-_dms-smtp_tcp).
   - The client presents a certificate for one of its domain's `_dms-send._tcp` targets, whose key appears in a `u=relay` record of that domain. The receiver confirms it as described in [Section 4.7](#47-sending-servers-_dms-send_tcp).

   STARTTLS MUST NOT be used. A server MUST NOT accept SMTP commands before the TLS handshake completes.
2. **Client connections.** Mail clients submit and retrieve mail only through the connections listed in [Section 9.1](#91-permitted-connections). Each one is encrypted from the first octet.
3. **Authentication.** Credentials are only ever sent inside TLS. Servers MUST NOT offer mechanisms that are weak even inside TLS ([Section 9.2](#92-prohibited-mechanisms)).
4. **No fallback.** If a TLS connection cannot be established or authenticated, the sender MUST NOT try any less secure alternative. It MUST queue the message and retry, and after the retry period MUST generate a delivery status notification [RFC3464].
5. **Minimum parameters.** Cipher suites and parameters follow [RFC9325].

Encryption is a property of the protocol, not a policy a domain opts into. This makes mechanisms that exist only to signal or enforce TLS redundant.

### 9.1. Permitted Connections

Mail MUST only be communicated over the connections in this table. This is an allow-list: a server MUST NOT accept or relay mail over any other connection, and a client MUST NOT use one.

| Path | Protocol | Transport | Port |
|------|----------|-----------|------|
| Server to server (MTA, Hub, MX) | SMTP, DMS relay ([RFC5321] as updated by this document) | Implicit TLS 1.3+, mutually authenticated | Dedicated DMS port, given by `_dms-smtp._tcp` |
| Client submission | SMTP submission with `AUTH` ([RFC6409], [RFC4954]) | Implicit TLS ([RFC8314]) | 465 |
| Client access | IMAP4rev2 ([RFC9051]) | Implicit TLS ([RFC8314]) | 993 |
| Client access | POP3 ([RFC1939]) | Implicit TLS ([RFC8314]) | 995 |
| Client access and submission | Exchange: MAPI over HTTP, Exchange ActiveSync, and Exchange Web Services or Microsoft Graph (informative: [MS-OXCMAPIHTTP], [MS-ASHTTP]) | HTTPS (TLS) | 443 |
| Client access and submission | JMAP ([RFC8620], [RFC8621]) | HTTPS (TLS) | 443 |

Exchange protocols are vendor specifications, not IETF standards, and are referenced informatively only. This document does not specify them. It places only transport requirements on them: HTTPS, the authentication rules in [Section 9.2](#92-prohibited-mechanisms), and no RPC over HTTP. Conformance to DMS does not depend on implementing them.

On these ports:

- IMAP servers MUST NOT advertise `STARTTLS` or `LOGINDISABLED`, because the session is already encrypted.
- POP3 servers MUST NOT advertise `STLS`.
- Exchange servers MUST NOT offer RPC over HTTP ("Outlook Anywhere").

Management protocols that do not carry mail, such as ManageSieve [RFC5804], MUST also run over implicit TLS.

### 9.2. Prohibited Mechanisms

The following MUST NOT be offered or used on any connection in [Section 9.1](#91-permitted-connections):

| Mechanism | Why |
|-----------|-----|
| Cleartext ports: 25 (legacy SMTP, closed at Full Adoption), 587 with STARTTLS, 143, 110 | Mail or credentials are exposed before, or instead of, encryption. |
| `STARTTLS` (SMTP), `STARTTLS` (IMAP), `STLS` (POP3) | Opportunistic upgrade can be stripped. Implicit TLS replaces it. |
| POP3 `APOP` | Relies on MD5. |
| SASL `CRAM-MD5`, `DIGEST-MD5` | Rely on MD5, and the server must store reusable password equivalents. |
| SASL `ANONYMOUS` [RFC4505] | Unauthenticated access has no place on submission or access connections. |
| NTLM, and HTTP Basic authentication to Exchange | NTLM is weak and relay-prone. Basic authentication sends a reusable password on every request. |
| RPC over HTTP (Outlook Anywhere) | A legacy Exchange transport, replaced by MAPI over HTTP. |
| TLS 1.2 and earlier on server-to-server relay | Below the minimum set in item 1 of [Section 9](#9-mandatory-encryption). |

The permitted authentication mechanisms are `OAUTHBEARER` [RFC7628], `SCRAM-SHA-256` and `SCRAM-SHA-256-PLUS` [RFC7677], `GSSAPI`/Kerberos [RFC4752], OAuth 2.0 for Exchange and JMAP, and `PLAIN` [RFC4616]. Because `PLAIN` is only ever carried inside TLS, it is acceptable, but `OAUTHBEARER` or `SCRAM` is RECOMMENDED.

## 10. Verification Procedure

A receiving server (MX), before accepting responsibility for a message (that is, before replying `250` to end-of-data), MUST:

1. **Check the transport.** It MUST have reached this step over TLS 1.3 or later with a valid client certificate. The sending host MUST have been confirmed against `_dms-send._tcp` ([Section 4.7](#47-sending-servers-_dms-send_tcp)).
2. **Locate the signature.** It extracts exactly one `Mail-Signature`. Missing or duplicate signatures fail with `550 5.7.TBD1`.
3. **Fetch the key.** It resolves `_mail.<d>` using the walk in [Section 4.5](#45-discovery-and-the-domain-tree) and selects the record with matching `k=`, a `u` that includes `mail` or `any`, no expiry in the past and a non-empty `p=`.
4. **Check the certificate.** It validates the certificate in `c=` as described in [Section 5](#5-certificate-binding) and confirms that its SPKI equals `p=`.
5. **Verify the signature.** It verifies `b=` and `bh=`, then checks alignment ([Section 6.4](#64-alignment)). If the Signing Domain publishes `_dms-send._tcp` with target `.`, it rejects the message.
6. **Verify the hop chain.** It verifies every `Mail-Hop` in turn:
   - `i=` values are contiguous from 1;
   - each signature is valid under a `u=relay` key of `d=`, with the certificate checked as in step 4;
   - each hop is authorised ([Section 7.4](#74-hop-authorisation));
   - the final hop's `d=` equals the identity authenticated by the current TLS client certificate;
   - the final hop's `to=` equals the receiving domain or a domain that authorises the receiver as a Hub.
7. **Verify the user signature, if present.** It verifies `Mail-User-Signature` as described in [Section 6.5](#65-user-signatures-mail-user-signature).
8. **Check declarations and redirects.** Every `Mail-Hop` has a valid `Mail-Retention` ([Section 7.5](#75-data-retention-mail-retention)), and every `Mail-Redirect` is valid ([Section 11.1](#111-redirection-mail-redirect)).
9. **Check freshness.** It rejects signatures with `t=` more than 15 minutes in the future, and MAY reject messages whose `t=` is older than a locally configured limit (RECOMMENDED: 7 days).

For a Signing Domain whose policy is enforcing ([Section 4.8](#48-policy)), any failure is a permanent rejection during the SMTP transaction, reported as described in [Section 10.1](#101-failure-reporting-and-bounces). Because the policy comes from the domain's SRV records and the result is binary and enforced at the border, receivers do not need to consult a separate policy record, generate aggregate reports or stamp `Authentication-Results` for downstream filters. A receiver MAY still record the verification result internally.

### 10.1. Failure Reporting and Bounces

DMS reports every failure to the **sending server**, with a clear reason. The sending server then decides how to report it to the person who sent the message. Receivers never send bounces to addresses taken from an unauthenticated message.

**1. Reject in the session.** A receiver MUST reject a failing message during the SMTP transaction. It MUST NOT accept a message and bounce it later. The failure therefore goes straight back over the authenticated connection to the server that presented it, and forged sender addresses never receive backscatter.

**2. Give a clear reason.** Every DMS rejection MUST use this reply format:

```
<code> <enhanced-code> DMS <reason>: <detail>; d=<domain>; k=<key-id>; hop=<i>
```

- `<reason>` is a value from the DMS Failure Reasons registry ([Section 13.7](#137-dms-failure-reasons)).
- `<detail>` is a short human-readable explanation.
- The `d=`, `k=` and `hop=` parts identify what failed, and are omitted when they do not apply.

For example:

```
550 5.7.TBD2 DMS cert-key-mismatch: certificate key does not match _mail record; d=domain.uk; k=2026a
550 5.7.TBD2 DMS hop-unauthorised: relay.example is not authorised by domain.uk; d=relay.example; hop=2
550 5.7.TBD3 DMS sender-host-not-listed: out9.domain.uk is not in _dms-send._tcp.domain.uk
451 4.7.TBD4 DMS dns-temporary: _mail.domain.uk lookup timed out; d=domain.uk
```

Temporary conditions, such as DNS timeouts, use `4.7.TBD4`, and the sender retries. Everything else is permanent.

**3. If the connected server is the origin**, meaning the server that applied `Mail-Signature`, it has the failure directly. It reports to its own user by whatever means it normally uses, translating `<reason>` into plain language using the registry's descriptions.

**4. If the connected server is a Hub or forwarder**, it MUST pass the failure back towards the origin as a delivery status notification [RFC3464]. The DSN:

- is sent with a null `MAIL FROM`, to the original `MAIL FROM` address;
- is delivered **directly to the server that sent the message**, at the host and port given by the sender domain's `_dms-send._tcp` record for that host. It goes to the domain's `_dms-smtp._tcp` servers only if that record's port is `0`;
- is itself a DMS message. It is signed by the Hub's domain, `From:` is an address at the Hub's domain, and it is delivered over DMS relay;
- carries the receiver's reply verbatim in `Diagnostic-Code: smtp; …`, together with `Status:` and `Action: failed`;
- includes the original message's header fields as `text/rfc822-headers` [RFC6522], so the origin can identify the message.

**5. When the origin receives a DSN**, it verifies the DSN's DMS signature like any other message. It MUST confirm that the DSN refers to a message it actually sent, by matching `Message-ID`, the `Mail-Signature` `b=` value or the DSN `ENVID` [RFC3461]. It MUST discard DSNs that match nothing. It then reports to its user as in step 3.

**6. Failures before any message is sent**, such as a TLS failure or a receiving server that cannot be confirmed ([Section 4.6](#46-receiving-servers-_dms-smtp_tcp)), are detected by the sending server itself. It treats them as temporary until its retry period expires, then reports to its user with the matching reason (`tls-server-auth-failed` or `receiver-not-confirmed`).

### 10.2. Verification and Display by Mail Clients

The receiving MDA MUST keep every DMS header field when storing the message:

- `Mail-Signature` and `Mail-User-Signature`;
- every `Mail-Hop`, `Mail-Retention` and `Mail-Redirect`;
- `Mail-Delivered`.

A mail client can therefore re-verify the whole chain itself, using the same DNS lookups and certificates, without trusting the server that stored the message.

Mail clients SHOULD offer the user a delivery summary built from these fields, showing for each party its domain, whether its signature verified, whether its DNS records were DNSSEC-validated, and what it declared it keeps. For example:

```
✔ Sent by        domain.uk            DNSSEC ✔   keeps: sender, recipients, headers 365d; body, attachments none
✔ Signed by      alice@domain.uk      (personal signature)
✔ Relayed by     amazonses.com        DNSSEC ✔   keeps: addresses & headers 30d; connection 90d; body scanned, not kept
✔ Redirected by  old.example → new.example       keeps: addresses 7d; nothing else
✔ Delivered by   new.example          DNSSEC ✔   keeps: mailbox; connection 30d
```

Where a party declares that it keeps `body` or `attachments` beyond `0`, keeps anything `indef`, or shares data with third parties, clients SHOULD highlight it.

## 11. Forwarding and Mailing Lists

**Unmodified forwarding and redirection** (aliases, `.forward`, domain moves, inbound gateways) keep the original `Mail-Signature` valid. The forwarder is the `to=` domain of the previous hop, so it is authorised for the next hop by [Section 7.4](#74-hop-authorisation). It adds its own `Mail-Hop` and `Mail-Retention`. When it sends the message on to a **different domain**, it also adds a `Mail-Redirect` ([Section 11.1](#111-redirection-mail-redirect)).

**Modifying intermediaries** (mailing lists that add footers or change the subject) become the originator of a new message:

1. The list MUST rename the existing `Mail-Signature` to `Original-Mail-Signature`, keeping it verbatim. It MUST keep existing `Mail-Hop` fields and rename them `Original-Mail-Hop`.
2. The list MUST rewrite `From:` to an address in its own domain. It SHOULD add the original author's address to `Reply-To:` or `Author:` [RFC9057].
3. The list signs with its own domain key and starts a new hop chain at `i=1`.

Verifiers MUST NOT use `Original-*` fields to decide acceptance. They MAY show them to users as provenance information.

### 11.1. Redirection: `Mail-Redirect`

When a server accepts a message for one domain and sends it on to another, for example `bob@old.example` redirecting to `bob@new.example`, both domains MUST be recorded clearly in the message. Mail clients can then see and verify both.

```abnf
mail-redirect = "Mail-Redirect:" [FWS] rdr-tag-list CRLF
rdr-tag    = hop-i / sig-d / rdr-to / rdr-orig / rdr-new / sig-k / sig-a
           / sig-t / sig-c / sig-b / ext-tag
rdr-to     = %s"to="   domain-name   ; the new domain
rdr-orig   = %s"orig=" addr-spec     ; original recipient (optional)
rdr-new    = %s"new="  addr-spec     ; new recipient (optional)
```

```
Mail-Redirect: i=2; d=old.example; to=new.example;
  orig=bob@old.example; new=bob@new.example;
  k=r1; a=ecdsa-p256-sha256; t=1794571261; c=MIIC…; b=MEUCIQ…
```

**Rules:**

1. The redirecting server MUST add exactly one `Mail-Redirect` for each redirect it performs. A message redirected several times carries one per redirect, so the full sequence is visible.
2. `d=` is the **redirecting domain**. It MUST equal `d=` of the `Mail-Hop` with the same `i=`, and it MUST equal the `to=` of the previous hop. In other words, the redirecting domain must genuinely have been a recipient.
3. `to=` is the **new domain**. It MUST equal the `to=` of the redirecting server's own `Mail-Hop`, or be a domain that authorises that `to=` as its Hub.
4. `orig=` and `new=` MAY carry the full addresses. A redirecting server SHOULD include them when the recipient has configured the redirect personally, as with an alias or forwarding rule. It MAY omit them for organisation-wide redirects where the addresses would reveal internal routing.
5. The `Mail-Redirect` is signed with the redirecting domain's `u=relay` key, using the context string `"DMS1 redirect\0"` over the same content as its `Mail-Hop` ([Section 7.3](#73-signed-content)). It is also covered by that `Mail-Hop` signature.
6. The **redirecting domain** is authenticated by the `Mail-Redirect` signature. The **new domain** is authenticated by its `Mail-Delivered` signature ([Section 7.6](#76-final-delivery-mail-delivered)), whose `d=` MUST match the last `Mail-Redirect`'s `to=`, or the new domain's own onward redirect. A mail client can therefore confirm both.
7. A receiver MUST reject a message whose `Mail-Redirect` is missing where a hop's `d=` differs from the next hop's destination domain because of a redirect, or whose `Mail-Redirect` fails any of these checks (`redirect-invalid`).

Mail clients SHOULD show redirects prominently, for example "Redirected by old.example to new.example", next to the verified sender. The user can then tell that the message reached them through another domain and confirm that both domains were genuine.

## 12. Transition and Coexistence

DMS is designed to be deployed alongside the existing stack and then to replace it.

| Phase | DNS published | Sender | Receiver |
|-------|---------------|--------|----------|
| 1. Publish | `_mail` | Adds `Mail-Signature` and `Mail-Hop` alongside existing DKIM signatures. | Verifies DMS when present and logs the result. Existing SPF/DKIM/DMARC evaluation continues. |
| 2. Prefer | `_mail` + `_dms-smtp._tcp` | Delivers over DMS, on the dedicated port, to any domain that publishes `_dms-smtp._tcp`. Falls back to MX on port 25 only for domains that publish no DMS delivery server. | Accepts DMS relay on the dedicated port. Keeps legacy MX on port 25 open for senders that are not yet ready. |
| 3. Require | `_mail` + `_dms-smtp._tcp` + `_dms-send._tcp`, in a DNSSEC-signed zone (RECOMMENDED) | Sends DMS only. | Rejects mail without valid DMS. Removes MX records and closes port 25. Publishes `.` targets for cleartext SRV services and closes cleartext ports. |

A domain reaches **Full Adoption** when it is in phase 3 for both sending and receiving. The mechanisms that become unnecessary at that point are listed in [`thefix.md`](thefix.md).

## 13. IANA Considerations

### 13.1. Underscored DNS Node Name

IANA is requested to add the following entry to the "Underscored and Globally Scoped DNS Node Names" registry [RFC8552]:

| RR Type | `_NODE NAME` | Reference |
|---------|--------------|-----------|
| TXT | `_mail` | This document |

### 13.2. Message Header Fields

IANA is requested to add the following entries to the "Permanent Message Header Field Names" registry [RFC3864]:

| Header Field Name | Protocol | Status | Reference |
|-------------------|----------|--------|-----------|
| `Mail-Signature` | mail | standard | This document |
| `Mail-Hop` | mail | standard | This document |
| `Mail-User-Signature` | mail | standard | This document |
| `Mail-Retention` | mail | standard | This document |
| `Mail-Redirect` | mail | standard | This document |
| `Mail-Delivered` | mail | standard | This document |
| `Original-Mail-Signature` | mail | standard | This document |
| `Original-Mail-Hop` | mail | standard | This document |

### 13.3. TLS ALPN Protocol ID

IANA is requested to register the ALPN identifier `dms-smtp` in the "TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs" registry.

### 13.4. Service Names and Port

IANA is requested to register the following entries in the "Service Name and Transport Protocol Port Number Registry", and to **assign a dedicated system port** for `dms-smtp`. This document writes that port as `<dms-port>`.

| Service Name | Port | Transport | Description | Reference |
|--------------|------|-----------|-------------|-----------|
| `dms-smtp` | TBD (`<dms-port>`) | tcp | Implicit-TLS, mutually authenticated server-to-server mail relay with DMS | This document |
| `dms-send` | TBD (`<dms-port>`) | tcp | DMS sending hosts for a domain. The port accepts return traffic (failure reports and DSNs). Priority and weight have the meanings given in Section 4.7. | This document |

A dedicated port keeps the new sending method entirely separate from legacy SMTP:

- Port 25 continues to carry legacy SMTP during transition and is closed at Full Adoption.
- On `<dms-port>`, the server waits for the client's TLS ClientHello rather than sending an SMTP greeting. Once TLS is established, the server sends its `220` greeting inside the encrypted session.
- Firewalls and monitoring can tell DMS traffic from legacy traffic by port alone.

SRV records ([Section 4.6](#46-receiving-servers-_dms-smtp_tcp)) MAY name a different port where an operator needs one, but SHOULD use `<dms-port>`.

### 13.5. Enhanced Status Codes

IANA is requested to register the following codes in the "Enumerated Status Codes" registry [RFC5248]:

| Code | Text |
|------|------|
| `X.7.TBD1` | DMS signature missing or duplicated |
| `X.7.TBD2` | DMS signature, certificate or hop verification failed |
| `X.7.TBD3` | DMS transport not authenticated |
| `X.7.TBD4` | DMS verification temporarily unavailable (used with `4.x.x` only) |

### 13.6. DMS Key Usage Values

IANA is requested to create a "DMS Key Usage Values" registry. Registration policy is First Come First Served [RFC8126]. Values are case-insensitive and must match the `use` ABNF in [Section 4.2](#42-syntax). Values containing `:` are reserved for private use under a domain name the registrant controls, and are not registered.

The registry is advisory. Unregistered values are valid in `_mail` records, and the registry exists only to prevent two specifications from giving one value different meanings.

Initial contents:

| Value | Description | Reference |
|-------|-------------|-----------|
| `mail` | Message signing (`Mail-Signature`) | This document |
| `relay` | Hop signing (`Mail-Hop`) and relay TLS authentication | This document |
| `any` | All uses, including future ones | This document |
| `web` | Key also serves the domain's HTTPS servers (informational) | This document |
| `user` | Individual user signing key (`Mail-User-Signature`), valid only at `_user._mail` names | This document |

### 13.7. DMS Failure Reasons

IANA is requested to create a "DMS Failure Reasons" registry, with the registration policy Specification Required [RFC8126]. Each entry has a reason token, an enhanced status code, and a plain-language description that sending servers can show to users ([Section 10.1](#101-failure-reporting-and-bounces)).

| Reason | Code | Description for users |
|--------|------|-----------------------|
| `signature-missing` | 5.7.TBD1 | The message was not signed by the sending domain. |
| `signature-duplicate` | 5.7.TBD1 | The message carried more than one domain signature. |
| `key-not-found` | 5.7.TBD2 | The sending domain's key could not be found in DNS. |
| `key-revoked` | 5.7.TBD2 | The key used has been revoked or has expired. |
| `key-usage` | 5.7.TBD2 | The key used is not permitted for this purpose (`u=`). |
| `cert-invalid` | 5.7.TBD2 | The signing certificate is invalid, expired, revoked or untrusted. |
| `cert-key-mismatch` | 5.7.TBD2 | The certificate does not match the key published in DNS. |
| `signature-invalid` | 5.7.TBD2 | The domain signature does not verify. The message may have been altered. |
| `body-hash-mismatch` | 5.7.TBD2 | The message body was altered after signing. |
| `alignment-failed` | 5.7.TBD2 | The From address does not belong to the signing domain. |
| `signature-time` | 5.7.TBD2 | The signature time is in the future or too old. |
| `domain-sends-no-mail` | 5.7.TBD2 | The sending domain declares that it sends no mail. |
| `hop-gap` | 5.7.TBD2 | The delivery path record is incomplete. |
| `hop-signature-invalid` | 5.7.TBD2 | A server on the delivery path has an invalid signature. |
| `hop-unauthorised` | 5.7.TBD2 | A server on the delivery path was not authorised to handle this mail. |
| `hop-peer-mismatch` | 5.7.TBD2 | The connecting server does not match the last recorded hop. |
| `user-key-not-found` | 5.7.TBD2 | The sender's personal key could not be found. |
| `user-signature-invalid` | 5.7.TBD2 | The sender's personal signature does not verify. |
| `sender-host-not-listed` | 5.7.TBD3 | The sending server is not listed for its domain. |
| `tls-client-auth-failed` | 5.7.TBD3 | The sending server's certificate could not be verified. |
| `tls-server-auth-failed` | 4.7.TBD4 | The receiving server's certificate could not be verified. Reported to the user only after retries. |
| `receiver-not-confirmed` | 4.7.TBD4 | The receiving server is not confirmed by the recipient's DNS. Reported to the user only after retries. |
| `dns-temporary` | 4.7.TBD4 | A DNS lookup failed temporarily. The message will be retried. |
| `dnssec-bogus` | 5.7.TBD2 | The sending domain's DNS records failed DNSSEC validation. |
| `retention-missing` | 5.7.TBD2 | A server that handled the message did not declare what data it keeps. |
| `retention-invalid` | 5.7.TBD2 | A server's data retention declaration is malformed or incomplete. |
| `redirect-invalid` | 5.7.TBD2 | The message was redirected, but the redirect record is missing or does not verify. |

### 13.8. DMS Retention Categories

IANA is requested to create a "DMS Retention Categories" registry, with the registration policy Specification Required [RFC8126]. Its initial contents are the seven categories in [Section 7.5.2](#752-categories): `sender`, `recipients`, `subject`, `headers`, `body`, `attachments` and `connection`. Categories added later are OPTIONAL in declarations. Only the initial seven are mandatory.

### 13.9. DMS Retention Purposes

IANA is requested to create a "DMS Retention Purposes" registry, with the registration policy First Come First Served [RFC8126]. Initial contents:

| Purpose | Meaning |
|---|---|
| `delivery` | Operating delivery: queues, retries and delivery status |
| `security` | Malware and phishing detection, incident response |
| `abuse` | Spam and abuse handling and complaints |
| `legal` | Legal or regulatory retention obligations |
| `billing` | Charging customers for service |
| `support` | Customer support and troubleshooting |
| `analytics` | Aggregate statistics about the service |
| `archive` | Archiving on behalf of the sender or recipient organisation |
| `training` | Training or improving automated systems, including machine-learning models |
| `other` | Any purpose not listed. The `policy=` URL MUST explain it. |

## 14. Security Considerations

### 14.1. DNS Compromise

An attacker who controls a domain's DNS but cannot obtain a CA-issued certificate for its key cannot produce valid signatures. CAs that validate domain control through DNS weaken this property. DNSSEC is therefore strongly RECOMMENDED, and CAA records [RFC8659] SHOULD restrict which CAs may issue certificates.

### 14.2. CA Mis-issuance

A mis-issued certificate does not help an attacker who cannot also publish the matching key in `_mail`. Certificate Transparency makes mis-issuance detectable after the fact.

### 14.3. Key Compromise and Rotation

A compromised key is revoked by removing its record, or by publishing it with an empty `p=`, and by revoking its certificate. Domains SHOULD rotate keys at least as often as their certificates, pre-publishing the next key as shown in [Section 4.4](#44-example).

### 14.4. Key Reuse

This document allows one key to serve web TLS (`u=web`) and mail signing (`u=mail`). The domain-separation strings in Sections 6.3 and 7.3 prevent cross-protocol signature confusion. However, reuse increases the impact of a single key compromise, so separate keys are RECOMMENDED.

### 14.5. Replay

A validly signed message can be re-sent to other recipients. The hop chain limits this: a replayed message carries a final hop that the replaying server cannot sign as the original path. Receivers MAY also de-duplicate on `Message-ID` together with `Mail-Signature` `b=`.

### 14.6. Hub Trust

Authorising a Hub with `h=` lets that Hub send mail that appears to come from the domain (delegated signing) or relay it. Domains SHOULD list only Hubs they actively use.

### 14.7. Denial of Service

Verifiers SHOULD cap the number of `Mail-Hop` fields (RECOMMENDED: 32), the size of `c=` and the number of DNS queries per message. They SHOULD also cap the number of SRV targets examined per domain (RECOMMENDED: 16).

### 14.8. SRV Spoofing and Policy Downgrade

An attacker who can forge SRV responses could redirect mail to its own server, or hide a domain's enforcing policy.

- **Redirection by an attacker** fails, because the sender confirms every receiving server against both the Web PKI and the recipient's `_mail` keys ([Section 4.6](#46-receiving-servers-_dms-smtp_tcp)). A forged target cannot present a certificate whose key is published in the real domain's `_mail` record. Legitimate redirection by a recipient domain is always recorded in a signed `Mail-Redirect` naming both domains ([Section 11.1](#111-redirection-mail-redirect)), so a silent redirect cannot pass verification.
- **Policy hiding** is limited by the domain-set persistence period in [Section 4.8](#48-policy), and is prevented entirely when the zone is signed with DNSSEC, because DNSSEC provides authenticated denial of existence.

### 14.9. Free-Form Usage Values

Because `u=` accepts any text, the security of a key used for something other than mail depends on the application that defines that use.

- **No privilege by accident.** A key published for an unrelated use, for example `u=iot` or `u=domain.uk:invoices`, never authorises mail. Only `mail`, `relay` and `any` do. Domains SHOULD NOT publish `any`, because it grants every use that anyone defines in the future, including uses the domain did not foresee.
- **Collisions.** Two applications could choose the same unprefixed value with different meanings. The domain-name prefix convention and the registry in [Section 13.6](#136-dms-key-usage-values) reduce this risk. Applications MUST NOT assume that a key carrying their value was published for them unless the value is registered or prefixed.
- **Cross-protocol signatures.** Each application MUST sign with its own domain-separation string, as DMS does with `"DMS1 message\0"` and `"DMS1 hop\0"`. Otherwise a signature produced for one use could be replayed as valid for another.
- **Record size.** Many keys at one name enlarge the `_mail` RRset. User keys live at their own names (`<hash>._user._mail`) for this reason. Responses over 1232 octets need DNS over TCP. Domains with many uses MAY delegate a subdomain, such as `_mail.api.domain.uk`, so that mail verifiers do not have to fetch large record sets.

### 14.10. User Keys and the Domain

The domain controls the DNS zone in which user keys are published, and usually controls the mailbox an email-validated certificate is issued to. A domain could therefore replace a user's key and obtain a certificate for it. User signatures protect against Hubs, relays and outsiders, not against a malicious domain operator. Users who need protection from their own provider SHOULD use a certificate whose issuance they control and SHOULD check its Certificate Transparency log entries where available.

### 14.11. Bounces

Rejecting in the session ([Section 10.1](#101-failure-reporting-and-bounces)) means DMS never generates backscatter to forged addresses. Hubs send DSNs only for messages that passed DMS at the Hub, so the DSN's recipient is an authenticated sender. Origins discard DSNs that do not match a message they sent, so forged DSNs cannot be used to flood users.

### 14.12. Truthfulness of Retention Declarations

A `Mail-Retention` declaration is an assertion. DMS cannot technically prove that a server deletes what it says it deletes. What DMS does provide:

- **Attributability.** Every declaration is signed by the declaring domain ([Section 7.3](#73-signed-content)), so a false declaration is a signed, provable misstatement by an identifiable party.
- **Visibility.** Declarations travel with every message and are shown to users, so differences between operators, and changes over time, are easy to see.
- **Enforceability elsewhere.** Signed declarations can support audits, contracts and data-protection obligations, for example transparency duties under data-protection law, that apply outside the protocol.

Operators SHOULD declare conservatively. If there is doubt about whether something is retained, for example in backups, it SHOULD be declared as retained.

## 15. Privacy Considerations

`Mail-Retention` is designed to improve privacy. It tells senders and recipients what every party that handled a message keeps, for how long, where and for what purpose. Today that information is usually unavailable, or buried in policy documents. `Mail-Redirect` may reveal a recipient's previous or alternative address when `orig=` and `new=` are included, which is why they are optional ([Section 11.1](#111-redirection-mail-redirect)).

`Mail-Hop` reveals the delivery path and the services a domain uses, as `Received:` already does. `_mail` records reveal which Hubs a domain authorises, as SPF `include:` records do today. Domain-level DMS adds no per-user identifiers. User keys ([Section 4.10](#410-user-keys-_user_mail)) are published under hashed local parts. This prevents trivial listing of a domain's users, but does not stop an observer who guesses an address from confirming that it has a key. Zones using NSEC can also be walked to collect the hashes. Mandatory encryption removes the cleartext exposure of message content and metadata on the wire.

## 16. References

### 16.1. Normative References

- [RFC1035] Mockapetris, P., "Domain names - implementation and specification", STD 13, RFC 1035.
- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
- [RFC1939] Myers, J. and M. Rose, "Post Office Protocol - Version 3", STD 53, RFC 1939. — [local copy](../rfc/rfc1939.txt)
- [RFC2782] Gulbrandsen, A., Vixie, P., and L. Esibov, "A DNS RR for specifying the location of services (DNS SRV)", RFC 2782.
- [RFC3464] Moore, K. and G. Vaudreuil, "An Extensible Message Format for Delivery Status Notifications", RFC 3464. — [local copy](../rfc/rfc3464.txt)
- [RFC4033] Arends, R., et al., "DNS Security Introduction and Requirements", RFC 4033.
- [RFC4034] Arends, R., et al., "Resource Records for the DNS Security Extensions", RFC 4034.
- [RFC4035] Arends, R., et al., "Protocol Modifications for the DNS Security Extensions", RFC 4035.
- [RFC5248] Hansen, T. and J. Klensin, "A Registry for SMTP Enhanced Mail System Status Codes", BCP 138, RFC 5248. — [local copy](../rfc/rfc5248.txt)
- [RFC5280] Cooper, D., et al., "Internet X.509 Public Key Infrastructure Certificate and CRL Profile", RFC 5280.
- [RFC5321] Klensin, J., "Simple Mail Transfer Protocol", RFC 5321. — [local copy](../rfc/rfc5321.txt)
- [RFC5322] Resnick, P., Ed., "Internet Message Format", RFC 5322. — [local copy](../rfc/rfc5322.txt)
- [RFC4616] Zeilenga, K., Ed., "The PLAIN Simple Authentication and Security Layer (SASL) Mechanism", RFC 4616. — [local copy](../rfc/rfc4616.txt)
- [RFC4752] Melnikov, A., Ed., "The Kerberos V5 ("GSSAPI") SASL Mechanism", RFC 4752. — [local copy](../rfc/rfc4752.txt)
- [RFC4954] Siemborski, R., Ed. and A. Melnikov, Ed., "SMTP Service Extension for Authentication", RFC 4954. — [local copy](../rfc/rfc4954.txt)
- [RFC6409] Gellens, R. and J. Klensin, "Message Submission for Mail", STD 72, RFC 6409. — [local copy](../rfc/rfc6409.txt)
- [RFC7628] Mills, W., Showalter, T., and H. Tschofenig, "A Set of SASL Mechanisms for OAuth", RFC 7628. — [local copy](../rfc/rfc7628.txt)
- [RFC7677] Hansen, T., "SCRAM-SHA-256 and SCRAM-SHA-256-PLUS SASL Mechanisms", RFC 7677. — [local copy](../rfc/rfc7677.txt)
- [RFC8126] Cotton, M., Leiba, B., and T. Narten, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 8126.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
- [RFC8314] Moore, K. and C. Newman, "Cleartext Considered Obsolete: Use of TLS for Email Submission and Access", RFC 8314. — [local copy](../rfc/rfc8314.txt)
- [RFC8446] Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446.
- [RFC8552] Crocker, D., "Scoped Interpretation of DNS Resource Records through Underscored Naming of Attribute Leaves", BCP 222, RFC 8552.
- [RFC3461] Moore, K., "SMTP Service Extension for Delivery Status Notifications (DSNs)", RFC 3461. — [local copy](../rfc/rfc3461.txt)
- [RFC6522] Kucherawy, M., Ed., "The Multipart/Report Media Type for the Reporting of Mail System Administrative Messages", STD 73, RFC 6522. — [local copy](../rfc/rfc6522.txt)
- [RFC7929] Wouters, P., "DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP", RFC 7929. — [local copy](../rfc/rfc7929.txt)
- [RFC8550] Schaad, J., Ramsdell, B., and S. Turner, "S/MIME Version 4.0 Certificate Handling", RFC 8550. — [local copy](../rfc/rfc8550.txt)
- [RFC9051] Melnikov, A. and B. Leiba, "Internet Message Access Protocol (IMAP) - Version 4rev2", RFC 9051. — [local copy](../rfc/rfc9051.txt)
- [RFC9162] Laurie, B., et al., "Certificate Transparency Version 2.0", RFC 9162.
- [RFC9325] Sheffer, Y., et al., "Recommendations for Secure Use of TLS and DTLS", BCP 195, RFC 9325.
- [RFC9495] Gallagher, C. and R. Ryan, "Certification Authority Authorization (CAA) Processing for Email Addresses", RFC 9495. — [local copy](../rfc/rfc9495.txt)
- [RFC9598] Melnikov, A., et al., "Internationalized Email Addresses in X.509 Certificates", RFC 9598. — [local copy](../rfc/rfc9598.txt)

### 16.2. Informative References

- [MS-ASHTTP] Microsoft, "Exchange ActiveSync: HTTP Protocol", Open Specifications.
- [MS-OXCMAPIHTTP] Microsoft, "Messaging Application Programming Interface (MAPI) Extensions for HTTP", Open Specifications.
- [RFC3207] STARTTLS for SMTP. — [local copy](../rfc/rfc3207.txt)
- [RFC4505] Anonymous Simple Authentication and Security Layer (SASL) Mechanism. — [local copy](../rfc/rfc4505.txt)
- [RFC5804] A Protocol for Remotely Managing Sieve Scripts. — [local copy](../rfc/rfc5804.txt)
- [RFC3864] Registration Procedures for Message Header Fields.
- [RFC5598] Internet Mail Architecture. — [local copy](../rfc/rfc5598.txt)
- [RFC6186] Use of SRV Records for Locating Email Submission/Access Services. — [local copy](../rfc/rfc6186.txt)
- [RFC6376] DomainKeys Identified Mail (DKIM) Signatures. — [local copy](../rfc/rfc6376.txt)
- [RFC7208] Sender Policy Framework (SPF). — [local copy](../rfc/rfc7208.txt)
- [RFC7505] A "Null MX" No Service Resource Record for Domains That Accept No Mail. — [local copy](../rfc/rfc7505.txt)
- [RFC7672] SMTP Security via Opportunistic DANE TLS. — [local copy](../rfc/rfc7672.txt)
- [RFC8460] SMTP TLS Reporting. — [local copy](../rfc/rfc8460.txt)
- [RFC8461] SMTP MTA Strict Transport Security (MTA-STS). — [local copy](../rfc/rfc8461.txt)
- [RFC8617] The Authenticated Received Chain (ARC) Protocol. — [local copy](../rfc/rfc8617.txt)
- [RFC8620] The JSON Meta Application Protocol (JMAP). — [local copy](../rfc/rfc8620.txt)
- [RFC8621] The JSON Meta Application Protocol (JMAP) for Mail. — [local copy](../rfc/rfc8621.txt)
- [RFC8659] DNS Certification Authority Authorization (CAA) Resource Record.
- [RFC8689] SMTP Require TLS Option. — [local copy](../rfc/rfc8689.txt)
- [RFC9276] Guidance for NSEC3 Parameter Settings.
- [RFC8551] S/MIME Version 4.0 Message Specification. — [local copy](../rfc/rfc8551.txt)
- [RFC9057] Email Author Header Field. — [local copy](../rfc/rfc9057.txt)
- [RFC9580] OpenPGP. — [local copy](../rfc/rfc9580.txt)
- [RFC9989] Domain-Based Message Authentication, Reporting, and Conformance (DMARC). — [local copy](../rfc/rfc9989.txt)

---

## Appendix A. Complete Example

`alice@domain.uk` sends to `bob@recipient.example`. `domain.uk` signs locally and relays through a Hub, `amazonses.com`. Key, certificate and signature values are truncated.

**DNS**

```dns
; Sender
_mail.domain.uk.                   IN TXT "v=DMS1; k=2026a; a=ecdsa-p256-sha256; u=mail,relay; p=MFkwEw…"
_mail.domain.uk.                   IN TXT "v=DMS1; h=amazonses.com"
_dms-send._tcp.domain.uk.          IN SRV 90 10 <dms-port> mail.domain.uk.

; Hub
_mail.amazonses.com.               IN TXT "v=DMS1; k=r7; a=ecdsa-p256-sha256; u=relay; p=MFkwEw…"
_dms-send._tcp.amazonses.com.      IN SRV 30 10 <dms-port> smtp-out.amazonses.com.

; Recipient
_mail.recipient.example.           IN TXT "v=DMS1; k=mx1; a=ecdsa-p256-sha256; u=relay; p=MFkwEw…"
_dms-smtp._tcp.recipient.example.  IN SRV 10 0 <dms-port> mx.recipient.example.
_dms-send._tcp.recipient.example.  IN SRV 30 10 <dms-port> out.recipient.example.
```

**Sending side**

1. `mail.domain.uk` connects to the Hub's inbound server and confirms it against the Hub's SRV records and `_mail` key.
2. `smtp-out.amazonses.com` resolves `_dms-smtp._tcp.recipient.example`, which gives `mx.recipient.example` on the dedicated DMS port. It connects with TLS 1.3 and confirms that the server certificate names `mx.recipient.example` and that its key matches `k=mx1` at `_mail.recipient.example`.

**Message as stored in Bob's mailbox** (the top two fields are added by `mx.recipient.example` after verification)

```
Mail-Retention: i=3; d=recipient.example;
  sender=mailbox; recipients=mailbox; subject=mailbox; headers=mailbox;
  body=mailbox; attachments=mailbox; connection=30d;
  purpose=delivery,security; loc=GB; share=none;
  policy=https://recipient.example/privacy/mail
Mail-Delivered: i=3; d=recipient.example; k=mx1; a=ecdsa-p256-sha256;
  t=1794571263; dnssec=domain.uk:secure,amazonses.com:secure,recipient.example:secure;
  c=MIIC…; b=MEQCIF…
Mail-Retention: i=2; d=amazonses.com;
  sender=30d; recipients=30d; subject=none; headers=30d;
  body=0; attachments=0; connection=90d;
  purpose=delivery,abuse,security; loc=IE,US; share=none;
  policy=https://hub.example/mail-retention
Mail-Hop: i=2; d=amazonses.com; k=r7; a=ecdsa-p256-sha256;
  t=1794571262; to=recipient.example; tls=TLSv1.3;
  c=MIIC…; b=MEUCIQ…
Mail-Retention: i=1; d=domain.uk;
  sender=365d; recipients=365d; subject=365d; headers=365d;
  body=none; attachments=none; connection=90d;
  purpose=delivery,legal; loc=GB; share=none
Mail-Hop: i=1; d=domain.uk; k=2026a; a=ecdsa-p256-sha256;
  t=1794571260; to=amazonses.com; tls=TLSv1.3;
  c=MIIB…; b=MEQCIA…
Mail-Signature: v=1; d=domain.uk; k=2026a; a=ecdsa-p256-sha256;
  t=1794571259;
  h=from:to:cc:date:subject:message-id:mime-version:content-type;
  bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
  c=MIIB…; b=MEYCIQ…
Received: from smtp-out.amazonses.com by mx.recipient.example
  with DMS-SMTP (TLSv1.3); Fri, 13 Nov 2026 19:21:02 +0000
Received: from mail.domain.uk by smtp-out.amazonses.com
  with DMS-SMTP (TLSv1.3); Fri, 13 Nov 2026 19:21:00 +0000
From: Alice <alice@domain.uk>
To: Bob <bob@recipient.example>
Date: Fri, 13 Nov 2026 19:20:59 +0000
Subject: Lunch?
Message-ID: <20261113192059.a1b2@domain.uk>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Are you free on Tuesday?
```

**Verification at `mx.recipient.example`**

1. The TLS client certificate names `smtp-out.amazonses.com`, which is a target of `_dms-send._tcp.amazonses.com`, and its key matches `k=r7`. ✔ `domain.uk` publishes `_dms-send._tcp`, so its policy is enforcing. ✔
2. `Mail-Signature` `d=domain.uk`, `k=2026a`: the key is found at `_mail.domain.uk`, the certificate is valid for `domain.uk` with a matching SPKI, the signature verifies, and `From:` aligns. ✔
3. Hop 1, `d=domain.uk`, is the Signing Domain. ✔ Its `to=amazonses.com` is authorised by `h=amazonses.com`. ✔
4. Hop 2, `d=amazonses.com`, equals hop 1's `to=`. ✔ It matches the TLS peer, and its `to=recipient.example` is the receiving domain. ✔
5. Hops 1 and 2 each have a complete `Mail-Retention`, covered by their hop signatures. ✔ All records were DNSSEC-validated. ✔
6. Result: the message is accepted. `mx.recipient.example` adds its own `Mail-Retention` and a signed `Mail-Delivered`, then stores the message.

Bob's mail client can now show: sent by `domain.uk` (keeps addresses and subject for a year, never the content), relayed by `amazonses.com` (scanned, not kept), delivered by `recipient.example`, all DNSSEC-secured.

### A.1. Redirect Example

Bob later moves to `new.example`, and `recipient.example` redirects his mail there. The message arriving at `new.example` additionally carries:

```
Mail-Retention: i=3; d=recipient.example;
  sender=7d; recipients=7d; subject=none; headers=7d;
  body=0; attachments=0; connection=30d;
  purpose=delivery; loc=GB; share=none
Mail-Redirect: i=3; d=recipient.example; to=new.example;
  orig=bob@recipient.example; new=bob@new.example;
  k=mx1; a=ecdsa-p256-sha256; t=1794571263; c=MIIC…; b=MEUCIQ…
Mail-Hop: i=3; d=recipient.example; k=mx1; a=ecdsa-p256-sha256;
  t=1794571263; to=new.example; tls=TLSv1.3; c=MIIC…; b=MEQCIB…
```

Once verified, `new.example` adds `Mail-Delivered: i=4; d=new.example; …`. Bob's client shows **"Redirected by recipient.example to new.example"**. The redirect is verified by `recipient.example`'s signature and the delivery by `new.example`'s, so both domains are confirmed authentic.

## Appendix B. Open Issues

- Should the hop chain cover the envelope (`MAIL FROM`/`RCPT TO`) explicitly, to bind messages more tightly against replay?
- How should local parts be normalised before hashing for user keys ([Section 4.10](#410-user-keys-_user_mail))? Case, Unicode normalisation for internationalised addresses, and sub-addressing (`alice+tag`) all affect which record is looked up.
- Should a domain be able to *require* user signatures for some or all of its addresses, for example with a tag in `_mail`?

### B.1. Resolved in this revision

| Issue | Resolution |
|---|---|
| Should DMS relay share port 25 with legacy SMTP? | No. DMS uses a dedicated IANA-assigned port ([Section 13.4](#134-service-names-and-port)). Senders fall back to legacy delivery only when the recipient publishes no DMS delivery server ([Section 4.6](#46-receiving-servers-_dms-smtp_tcp)). |
| Normative or informative reference for Exchange? | Informative only ([Section 9.1](#91-permitted-connections)). |
| Fixed or domain-set policy persistence? | Set by the domain in the `_dms-send._tcp` SRV priority field ([Section 4.8](#48-policy)). |
| How should bounces work? | Reject in the session. The sending server is informed, using registered failure reasons, and reports to its user. Hubs pass failures back as DMS-signed DSNs ([Section 10.1](#101-failure-reporting-and-bounces)). |
| How are redirects shown? | A signed `Mail-Redirect` names the redirecting and new domains. The new domain signs `Mail-Delivered`, so mail clients can verify both ([Section 11.1](#111-redirection-mail-redirect)). |
| What do servers keep? | Every server declares what it retains, per field, in a signed `Mail-Retention` header field ([Section 7.5](#75-data-retention-mail-retention)). |
| DNSSEC? | RECOMMENDED for all DMS zones, mandatory validation for verifiers, and results shown to mail clients ([Section 4.11](#411-dnssec)). |
| Should Ed25519 be allowed? | Yes, for future use. Verifiers must support it now. Signers should pair it with an ECDSA key until CAs issue Ed25519 certificates widely ([Section 4.3.2](#432-algorithms)). |
| Is SRV the right record for sending hosts? | Yes, using every field. Service and protocol identify the sending service. Priority is the policy persistence period, and weight is each host's share of outbound mail. Port is where the host accepts returned failure reports ([Section 4.7](#47-sending-servers-_dms-send_tcp)). |
| Can individual users sign? | Yes. Personal keys go at `<hash>._user._mail.<domain>`, are bound to S/MIME certificates, and produce a `Mail-User-Signature` ([Sections 4.10](#410-user-keys-_user_mail) and [6.5](#65-user-signatures-mail-user-signature)). |
