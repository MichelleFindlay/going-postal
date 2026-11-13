# going-postal

## About
- A stupid idea ive had in my head to de-cluster-f*ck the e-mail stack for a few years.
- I am aware it wont ever get better. But I can dream.
- This is just a weird thought in my head i wanted to write down.

## The fix

The proposed fix is **Domain Mail Signing (DMS)**, written up as an Internet-Draft in [`thefix/`](thefix/):

- **[The proposed RFC](thefix/draft-findlay-mail-domain-signing-00.md)** has seven parts:
  - **Domain keys:** each domain publishes its keys at `_mail.<domain>`, and each key is bound to a normal CA certificate.
  - **SRV records:** they name the sending and receiving servers and carry the domain's policy.
  - **Signed delivery path:** every hop adds a signed record to the message.
  - **Retention declarations:** every server states what it keeps from the message.
  - **Redirects:** both the redirecting domain and the new domain are recorded.
  - **Optional user signatures:** individual users can sign their own mail.
  - **Encryption only:** mail is only ever carried over encrypted connections.
- **[What goes away](thefix/thefix.md)** lists the RFCs, DNS records and insecure mechanisms that stop being needed once everyone has switched. That includes SPF, DKIM, DMARC, ARC, STARTTLS, MTA-STS and DANE for SMTP, taking the stack from 161 RFCs to 140.

## The problem

Sending an email looks simple. Doing it *correctly* in 2026 means implementing, or at least understanding, the documents listed below:

- **161 RFCs** that are all still current, none of them obsoleted
- **~1 million words**, or about **3,700 pages** of plain text
- **31 years** of layering, from RFC 1847 (October 1995) to RFC 10080 (October 2026)
- **Only 9** have reached full Internet Standard; **123** are still Proposed Standards and **7** are Experimental

No single document describes "email". The core format (RFC 5322) and transport (RFC 5321) date from 2008 and are built on designs from 1982. Everything since has been bolted on as an optional extension: encryption in transit, sender authentication, binary attachments, Unicode addresses and modern client sync. Each one has to be negotiated, has a fallback and comes with its own failure modes. Security in particular is opportunistic. SPF, DKIM and DMARC are three separate mechanisms that only work together. MTA-STS and DANE are two competing answers to the same question. S/MIME and OpenPGP are two incompatible answers to another.

Every RFC is checked in as plain text under [`rfc/`](rfc/) so the whole problem can be read, grepped and diffed offline. Statuses come from the RFC Editor index (`rfc-index.xml`) as of **13 November 2026**.

### The stack at a glance

```
            ┌──────────────── MUA (mail client) ────────────────┐
            │  compose / read: RFC 5322 + MIME, S/MIME, OpenPGP │
            └───────┬───────────────────────────────▲───────────┘
   submission       │ SMTP + AUTH (587 / 465)       │ IMAP4rev2 · JMAP · POP3
   RFC 6409, 8314   ▼                               │ RFC 9051, 8620/8621, 1939
            ┌───────────────┐   SMTP (25)    ┌──────┴────────┐
            │   MSA / MTA   │ ─────────────▶ │  MTA → MDA    │──▶ Sieve filters
            │ DKIM signing  │  STARTTLS,     │ SPF/DKIM/DMARC│    RFC 5228
            └───────────────┘  MTA-STS, DANE │ ARC, Auth-Res │
                               RFC 5321      └───────────────┘
```

### RFCs by layer

#### Architecture & Message Format

What an email *is*: the overall architecture, the message format, and its core header fields.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [5598](rfc/rfc5598.txt) | Internet Mail Architecture | Informational | Reference model: MUA, MSA, MTA, MDA, ADMDs and how they fit together |
| [5322](rfc/rfc5322.txt) | Internet Message Format | Draft Standard | The Internet Message Format — headers, addresses, dates, body |
| [6854](rfc/rfc6854.txt) | Update to Internet Message Format to Allow Group Syntax in the "From:" and "Sender:" Header Fields | Proposed Standard | Allows group syntax in `From:`/`Sender:` |
| [10080](rfc/rfc10080.txt) | Updated Use of the Expires Message Header Field | Proposed Standard | Updated semantics for the `Expires:` header field |

#### MIME

Multipart bodies, attachments, non-ASCII text and media types.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [2045](rfc/rfc2045.txt) | Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies | Draft Standard | Part 1 — body format, `Content-Type`, `Content-Transfer-Encoding` |
| [2046](rfc/rfc2046.txt) | Multipurpose Internet Mail Extensions (MIME) Part Two: Media Types | Draft Standard | Part 2 — media types, `multipart/*`, `message/*` |
| [2047](rfc/rfc2047.txt) | MIME (Multipurpose Internet Mail Extensions) Part Three: Message Header Extensions for Non-ASCII Text | Draft Standard | Part 3 — encoded-words for non-ASCII headers |
| [4289](rfc/rfc4289.txt) | Multipurpose Internet Mail Extensions (MIME) Part Four: Registration Procedures | BCP | Part 4 — registration procedures |
| [2049](rfc/rfc2049.txt) | Multipurpose Internet Mail Extensions (MIME) Part Five: Conformance Criteria and Examples | Draft Standard | Part 5 — conformance and examples |
| [2231](rfc/rfc2231.txt) | MIME Parameter Value and Encoded Word Extensions: Character Sets, Languages, and Continuations | Proposed Standard | Parameter charsets, languages and continuations |
| [6657](rfc/rfc6657.txt) | Update to MIME regarding "charset" Parameter Handling in Textual Media Types | Proposed Standard | `charset` parameter handling for `text/*` |
| [2183](rfc/rfc2183.txt) | Communicating Presentation Information in Internet Messages: The Content-Disposition Header Field | Proposed Standard | `Content-Disposition` (inline vs. attachment) |
| [2387](rfc/rfc2387.txt) | The MIME Multipart/Related Content-type | Proposed Standard | `multipart/related` |
| [2392](rfc/rfc2392.txt) | Content-ID and Message-ID Uniform Resource Locators | Proposed Standard | `cid:` and `mid:` URLs |
| [3676](rfc/rfc3676.txt) | The Text/Plain Format and DelSp Parameters | Proposed Standard | `format=flowed` plain text |
| [8255](rfc/rfc8255.txt) | Multiple Language Content Type | Proposed Standard | `multipart/multilingual` |
| [6838](rfc/rfc6838.txt) | Media Type Specifications and Registration Procedures | BCP | Media type registration (BCP 13) |

#### SMTP — Transport & Submission

Moving messages between servers (port 25) and from clients into the system (ports 587/465).

| RFC | Title | Status | Notes |
|---|---|---|---|
| [5321](rfc/rfc5321.txt) | Simple Mail Transfer Protocol | Draft Standard | SMTP core protocol |
| [6409](rfc/rfc6409.txt) | Message Submission for Mail | Internet Standard | Message Submission (MSA, port 587) |
| [1870](rfc/rfc1870.txt) | SMTP Service Extension for Message Size Declaration | Internet Standard | `SIZE` |
| [6152](rfc/rfc6152.txt) | SMTP Service Extension for 8-bit MIME Transport | Internet Standard | `8BITMIME` |
| [3030](rfc/rfc3030.txt) | SMTP Service Extensions for Transmission of Large and Binary MIME Messages | Proposed Standard | `CHUNKING` / `BINARYMIME` (`BDAT`) |
| [2920](rfc/rfc2920.txt) | SMTP Service Extension for Command Pipelining | Internet Standard | `PIPELINING` |
| [2034](rfc/rfc2034.txt) | SMTP Service Extension for Returning Enhanced Error Codes | Proposed Standard | `ENHANCEDSTATUSCODES` |
| [3463](rfc/rfc3463.txt) | Enhanced Mail System Status Codes | Draft Standard | Enhanced status code definitions (`5.1.1` etc.) |
| [5248](rfc/rfc5248.txt) | A Registry for SMTP Enhanced Mail System Status Codes | BCP | Registry for enhanced status codes |
| [7504](rfc/rfc7504.txt) | SMTP 521 and 556 Reply Codes | Proposed Standard | `521` / `556` reply codes |
| [7372](rfc/rfc7372.txt) | Email Authentication Status Codes | Proposed Standard | Status codes for SPF/DKIM/DMARC failures |
| [9422](rfc/rfc9422.txt) | The LIMITS SMTP Service Extension | Proposed Standard | `LIMITS` — advertise recipient/transaction limits |
| [2852](rfc/rfc2852.txt) | Deliver By SMTP Service Extension | Proposed Standard | `DELIVERBY` |
| [4468](rfc/rfc4468.txt) | Message Submission BURL Extension | Proposed Standard | `BURL` — submit by reference to IMAP |
| [7293](rfc/rfc7293.txt) | The Require-Recipient-Valid-Since Header Field and SMTP Service Extension | Proposed Standard | `RRVS` — Require-Recipient-Valid-Since |
| [6758](rfc/rfc6758.txt) | Tunneling of SMTP Message Transfer Priorities | Informational | Message transfer priorities (informational) |
| [7505](rfc/rfc7505.txt) | A "Null MX" No Service Resource Record for Domains That Accept No Mail | Proposed Standard | Null MX — domains that accept no mail |
| [6186](rfc/rfc6186.txt) | Use of SRV Records for Locating Email Submission/Access Services | Proposed Standard | SRV records for locating submission/IMAP/POP servers |

#### Delivery Status, Notifications & Feedback

Bounces, read receipts and abuse reports.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [3461](rfc/rfc3461.txt) | Simple Mail Transfer Protocol (SMTP) Service Extension for Delivery Status Notifications (DSNs) | Draft Standard | SMTP `DSN` extension (`NOTIFY=`, `RET=`, `ENVID=`) |
| [3464](rfc/rfc3464.txt) | An Extensible Message Format for Delivery Status Notifications | Draft Standard | `message/delivery-status` format |
| [6522](rfc/rfc6522.txt) | The Multipart/Report Media Type for the Reporting of Mail System Administrative Messages | Internet Standard | `multipart/report` |
| [8098](rfc/rfc8098.txt) | Message Disposition Notification | Internet Standard | Message Disposition Notifications (read receipts) |
| [5965](rfc/rfc5965.txt) | An Extensible Format for Email Feedback Reports | Proposed Standard | ARF — abuse/feedback report format |
| [3834](rfc/rfc3834.txt) | Recommendations for Automatic Responses to Electronic Mail | Proposed Standard | Auto-responder etiquette (`Auto-Submitted:`) |

#### Transport Security (TLS)

Encrypting hops and authenticating servers.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [3207](rfc/rfc3207.txt) | SMTP Service Extension for Secure SMTP over Transport Layer Security | Proposed Standard | `STARTTLS` for SMTP |
| [8314](rfc/rfc8314.txt) | Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access | Proposed Standard | Cleartext considered obsolete — implicit TLS for submission/IMAP/POP |
| [8997](rfc/rfc8997.txt) | Deprecation of TLS 1.1 for Email Submission and Access | Proposed Standard | Deprecates TLS 1.1 for submission and access |
| [7817](rfc/rfc7817.txt) | Updated Transport Layer Security (TLS) Server Identity Check Procedure for Email-Related Protocols | Proposed Standard | TLS server identity checks for mail protocols |
| [2595](rfc/rfc2595.txt) | Using TLS with IMAP, POP3 and ACAP | Proposed Standard | `STARTTLS` for IMAP/POP3 (largely superseded by 8314, still current) |
| [8461](rfc/rfc8461.txt) | SMTP MTA Strict Transport Security (MTA-STS) | Proposed Standard | MTA-STS — strict transport policy via HTTPS |
| [8460](rfc/rfc8460.txt) | SMTP TLS Reporting | Proposed Standard | SMTP TLS Reporting (TLS-RPT) |
| [7672](rfc/rfc7672.txt) | SMTP Security via Opportunistic DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) | Proposed Standard | DANE for SMTP (TLSA records) |
| [8689](rfc/rfc8689.txt) | SMTP Require TLS Option | Proposed Standard | `REQUIRETLS` |
| [8996](rfc/rfc8996.txt) | Deprecating TLS 1.0 and TLS 1.1 | BCP | Deprecates TLS 1.0 and 1.1 (BCP 195) |

#### Sender Authentication & Anti-Abuse

Proving who sent a message and what to do when that fails.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [7208](rfc/rfc7208.txt) | Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1 | Proposed Standard | SPF |
| [6376](rfc/rfc6376.txt) | DomainKeys Identified Mail (DKIM) Signatures | Internet Standard | DKIM signatures |
| [8301](rfc/rfc8301.txt) | Cryptographic Algorithm and Key Usage Update to DomainKeys Identified Mail (DKIM) | Proposed Standard | DKIM crypto update — RSA-SHA256, ≥1024-bit keys |
| [8463](rfc/rfc8463.txt) | A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM) | Proposed Standard | DKIM Ed25519-SHA256 |
| [8616](rfc/rfc8616.txt) | Email Authentication for Internationalized Mail | Proposed Standard | SPF/DKIM/DMARC with internationalised mail |
| [6377](rfc/rfc6377.txt) | DomainKeys Identified Mail (DKIM) and Mailing Lists | BCP | DKIM and mailing lists (BCP) |
| [9989](rfc/rfc9989.txt) | Domain-Based Message Authentication, Reporting, and Conformance (DMARC) | Proposed Standard | DMARC (DMARCbis — replaces RFC 7489 and RFC 9091) |
| [9990](rfc/rfc9990.txt) | Domain-Based Message Authentication, Reporting, and Conformance (DMARC) Aggregate Reporting | Proposed Standard | DMARC aggregate reporting (`rua`) |
| [9991](rfc/rfc9991.txt) | Domain-Based Message Authentication, Reporting, and Conformance (DMARC) Failure Reporting | Proposed Standard | DMARC failure reporting (`ruf`) |
| [7960](rfc/rfc7960.txt) | Interoperability Issues between Domain-based Message Authentication, Reporting, and Conformance (DMARC) and Indirect Email Flows | Informational | DMARC and indirect mail flows (forwarders, lists) |
| [8601](rfc/rfc8601.txt) | Message Header Field for Indicating Message Authentication Status | Proposed Standard | `Authentication-Results:` header |
| [8617](rfc/rfc8617.txt) | The Authenticated Received Chain (ARC) Protocol | Experimental | ARC — Authenticated Received Chain (experimental) |
| [8553](rfc/rfc8553.txt) | DNS Attrleaf Changes: Fixing Specifications That Use Underscored Node Names | BCP | Underscored DNS names (`_dmarc`, `_domainkey`, …) |
| [5782](rfc/rfc5782.txt) | DNS Blacklists and Whitelists | Informational | DNS block/allow lists (DNSBL/DNSWL) |

#### SASL Authentication

How clients log in to SMTP submission, IMAP, POP3 and ManageSieve.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [4954](rfc/rfc4954.txt) | SMTP Service Extension for Authentication | Proposed Standard | SMTP `AUTH` |
| [4422](rfc/rfc4422.txt) | Simple Authentication and Security Layer (SASL) | Proposed Standard | SASL framework |
| [4616](rfc/rfc4616.txt) | The PLAIN Simple Authentication and Security Layer (SASL) Mechanism | Proposed Standard | `PLAIN` |
| [5802](rfc/rfc5802.txt) | Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms | Proposed Standard | `SCRAM` |
| [7677](rfc/rfc7677.txt) | SCRAM-SHA-256 and SCRAM-SHA-256-PLUS Simple Authentication and Security Layer (SASL) Mechanisms | Proposed Standard | `SCRAM-SHA-256` |
| [9266](rfc/rfc9266.txt) | Channel Bindings for TLS 1.3 | Proposed Standard | TLS 1.3 channel bindings (`-PLUS` mechanisms) |
| [7628](rfc/rfc7628.txt) | A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth | Proposed Standard | `OAUTHBEARER` / OAuth 2.0 |
| [4505](rfc/rfc4505.txt) | Anonymous Simple Authentication and Security Layer (SASL) Mechanism | Proposed Standard | `ANONYMOUS` |
| [4752](rfc/rfc4752.txt) | The Kerberos V5 ("GSSAPI") Simple Authentication and Security Layer (SASL) Mechanism | Proposed Standard | `GSSAPI` (Kerberos) |

#### IMAP

Mailbox access. IMAP4rev2 is the current base; the extensions listed are the ones commonly implemented or recently published.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [9051](rfc/rfc9051.txt) | Internet Message Access Protocol (IMAP) - Version 4rev2 | Proposed Standard | IMAP4rev2 (obsoletes 3501) |
| [2177](rfc/rfc2177.txt) | IMAP4 IDLE command | Proposed Standard | `IDLE` |
| [5161](rfc/rfc5161.txt) | The IMAP ENABLE Extension | Proposed Standard | `ENABLE` |
| [7888](rfc/rfc7888.txt) | IMAP4 Non-synchronizing Literals | Proposed Standard | `LITERAL+` / `LITERAL-` |
| [4959](rfc/rfc4959.txt) | IMAP Extension for Simple Authentication and Security Layer (SASL) Initial Client Response | Proposed Standard | `SASL-IR` |
| [2971](rfc/rfc2971.txt) | IMAP4 ID extension | Proposed Standard | `ID` |
| [4315](rfc/rfc4315.txt) | Internet Message Access Protocol (IMAP) - UIDPLUS extension | Proposed Standard | `UIDPLUS` |
| [6851](rfc/rfc6851.txt) | Internet Message Access Protocol (IMAP) - MOVE Extension | Proposed Standard | `MOVE` |
| [7162](rfc/rfc7162.txt) | IMAP Extensions: Quick Flag Changes Resynchronization (CONDSTORE) and Quick Mailbox Resynchronization (QRESYNC) | Proposed Standard | `CONDSTORE` / `QRESYNC` |
| [8474](rfc/rfc8474.txt) | IMAP Extension for Object Identifiers | Proposed Standard | `OBJECTID` |
| [6154](rfc/rfc6154.txt) | IMAP LIST Extension for Special-Use Mailboxes | Proposed Standard | `SPECIAL-USE` mailboxes (`\Sent`, `\Trash`, …) |
| [5256](rfc/rfc5256.txt) | Internet Message Access Protocol - SORT and THREAD Extensions | Proposed Standard | `SORT` / `THREAD` |
| [4731](rfc/rfc4731.txt) | IMAP4 Extension to SEARCH Command for Controlling What Kind of Information Is Returned | Proposed Standard | `ESEARCH` |
| [5032](rfc/rfc5032.txt) | WITHIN Search Extension to the IMAP Protocol | Proposed Standard | `WITHIN` |
| [6203](rfc/rfc6203.txt) | IMAP4 Extension for Fuzzy Search | Proposed Standard | `SEARCH=FUZZY` |
| [5530](rfc/rfc5530.txt) | IMAP Response Codes | Proposed Standard | IMAP response codes |
| [4978](rfc/rfc4978.txt) | The IMAP COMPRESS Extension | Proposed Standard | `COMPRESS=DEFLATE` |
| [5464](rfc/rfc5464.txt) | The IMAP METADATA Extension | Proposed Standard | `METADATA` |
| [9590](rfc/rfc9590.txt) | IMAP Extension for Returning Mailbox METADATA in Extended LIS | Proposed Standard | `LIST-METADATA` |
| [5465](rfc/rfc5465.txt) | The IMAP NOTIFY Extension | Proposed Standard | `NOTIFY` |
| [9208](rfc/rfc9208.txt) | IMAP QUOTA Extension | Proposed Standard | `QUOTA` (obsoletes 2087) |
| [8970](rfc/rfc8970.txt) | IMAP4 Extension: Message Preview Generation | Proposed Standard | `PREVIEW` |
| [9394](rfc/rfc9394.txt) | IMAP PARTIAL Extension for Paged SEARCH and FETCH | Proposed Standard | `PARTIAL` — paged SEARCH/FETCH |
| [9585](rfc/rfc9585.txt) | IMAP Response Code for Command Progress Notifications | Proposed Standard | `INPROGRESS` response code |
| [9586](rfc/rfc9586.txt) | IMAP Extension for Using and Returning Unique Identifiers (UIDs) Only | Experimental | `UIDONLY` (experimental) |
| [9738](rfc/rfc9738.txt) | IMAP MESSAGELIMIT Extension | Experimental | `MESSAGELIMIT` (experimental) |
| [10022](rfc/rfc10022.txt) | IMAP UIDBATCHES Extension | Proposed Standard | `UIDBATCHES` |
| [9698](rfc/rfc9698.txt) | The JMAPACCESS Extension for IMAP | Proposed Standard | `JMAPACCESS` |
| [9979](rfc/rfc9979.txt) | Registration of Further IMAP/JMAP Keywords and Mailbox Name Attributes | Informational | Further IMAP/JMAP keywords and mailbox attributes |

#### POP3

The older download-and-delete access protocol.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [1939](rfc/rfc1939.txt) | Post Office Protocol - Version 3 | Internet Standard | POP3 |
| [2449](rfc/rfc2449.txt) | POP3 Extension Mechanism | Proposed Standard | `CAPA` extension mechanism |
| [5034](rfc/rfc5034.txt) | The Post Office Protocol (POP3) Simple Authentication and Security Layer (SASL) Authentication Mechanism | Proposed Standard | SASL for POP3 |

#### JMAP

JSON-over-HTTP successor to IMAP for clients.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [8620](rfc/rfc8620.txt) | The JSON Meta Application Protocol (JMAP) | Proposed Standard | JMAP core |
| [8621](rfc/rfc8621.txt) | The JSON Meta Application Protocol (JMAP) for Mail | Proposed Standard | JMAP for Mail |
| [8887](rfc/rfc8887.txt) | A JSON Meta Application Protocol (JMAP) Subprotocol for WebSocket | Proposed Standard | JMAP over WebSocket |
| [9007](rfc/rfc9007.txt) | Handling Message Disposition Notification with the JSON Meta Application Protocol (JMAP) | Proposed Standard | MDN handling |
| [9219](rfc/rfc9219.txt) | S/MIME Signature Verification Extension to the JSON Meta Application Protocol (JMAP) | Proposed Standard | S/MIME signature verification |
| [9404](rfc/rfc9404.txt) | JSON Meta Application Protocol (JMAP) Blob Management Extension | Proposed Standard | Blob management |
| [9425](rfc/rfc9425.txt) | JSON Meta Application Protocol (JMAP) for Quotas | Proposed Standard | Quotas |
| [9661](rfc/rfc9661.txt) | The JSON Meta Application Protocol (JMAP) for Sieve Scripts | Proposed Standard | Sieve scripts |
| [9670](rfc/rfc9670.txt) | JSON Meta Application Protocol (JMAP) Sharing | Proposed Standard | Sharing |
| [9749](rfc/rfc9749.txt) | Use of Voluntary Application Server Identification (VAPID) in JSON Meta Application Protocol (JMAP) Web Push | Proposed Standard | VAPID for Web Push |
| [9610](rfc/rfc9610.txt) | JSON Meta Application Protocol (JMAP) for Contacts | Proposed Standard | Contacts |

#### Sieve Filtering

Server-side mail filtering language and its management protocol.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [5228](rfc/rfc5228.txt) | Sieve: An Email Filtering Language | Proposed Standard | Sieve core language |
| [5804](rfc/rfc5804.txt) | A Protocol for Remotely Managing Sieve Scripts | Proposed Standard | ManageSieve protocol |
| [5229](rfc/rfc5229.txt) | Sieve Email Filtering: Variables Extension | Proposed Standard | `variables` |
| [5230](rfc/rfc5230.txt) | Sieve Email Filtering: Vacation Extension | Proposed Standard | `vacation` |
| [5232](rfc/rfc5232.txt) | Sieve Email Filtering: Imap4flags Extension | Proposed Standard | `imap4flags` |
| [5233](rfc/rfc5233.txt) | Sieve Email Filtering: Subaddress Extension | Proposed Standard | `subaddress` (`user+tag@`) |
| [5173](rfc/rfc5173.txt) | Sieve Email Filtering: Body Extension | Proposed Standard | `body` |
| [5293](rfc/rfc5293.txt) | Sieve Email Filtering: Editheader Extension | Proposed Standard | `editheader` |
| [5429](rfc/rfc5429.txt) | Sieve Email Filtering: Reject and Extended Reject Extensions | Proposed Standard | `reject` / `ereject` |
| [5235](rfc/rfc5235.txt) | Sieve Email Filtering: Spamtest and Virustest Extensions | Proposed Standard | `spamtest` / `virustest` |
| [3894](rfc/rfc3894.txt) | Sieve Extension: Copying Without Side Effects | Proposed Standard | `copy` |
| [5435](rfc/rfc5435.txt) | Sieve Email Filtering: Extension for Notifications | Proposed Standard | `enotify` |
| [5436](rfc/rfc5436.txt) | Sieve Notification Mechanism: mailto | Proposed Standard | `enotify` mailto method |
| [9042](rfc/rfc9042.txt) | Sieve Email Filtering: Delivery by MAILBOXID | Proposed Standard | `mailboxid` |
| [9671](rfc/rfc9671.txt) | Sieve Email Filtering: Extension for Processing Calendar Attachments | Proposed Standard | Processing calendar attachments |

#### Internationalised Email (EAI / SMTPUTF8)

UTF-8 in addresses and headers end to end.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [6530](rfc/rfc6530.txt) | Overview and Framework for Internationalized Email | Proposed Standard | Overview and framework |
| [6531](rfc/rfc6531.txt) | SMTP Extension for Internationalized Email | Proposed Standard | `SMTPUTF8` |
| [6532](rfc/rfc6532.txt) | Internationalized Email Headers | Proposed Standard | UTF-8 headers |
| [6533](rfc/rfc6533.txt) | Internationalized Delivery Status and Disposition Notifications | Proposed Standard | Internationalised DSNs/MDNs |
| [9755](rfc/rfc9755.txt) | IMAP Support for UTF-8 | Proposed Standard | IMAP `UTF8=ACCEPT` (obsoletes 6855) |
| [6856](rfc/rfc6856.txt) | Post Office Protocol Version 3 (POP3) Support for UTF-8 | Proposed Standard | POP3 `UTF8` |
| [6857](rfc/rfc6857.txt) | Post-Delivery Message Downgrading for Internationalized Email Messages | Proposed Standard | Post-delivery downgrading |
| [6858](rfc/rfc6858.txt) | Simplified POP and IMAP Downgrading for Internationalized Email | Proposed Standard | Simplified POP/IMAP downgrading |

#### End-to-End Security (S/MIME & OpenPGP)

Signing and encrypting message content.

| RFC | Title | Status | Notes |
|---|---|---|---|
| [9787](rfc/rfc9787.txt) | Guidance on End-to-End Email Security | Informational | Guidance on end-to-end email security |
| [9788](rfc/rfc9788.txt) | Header Protection for Cryptographically Protected Email | Proposed Standard | Header protection for signed/encrypted mail |
| [1847](rfc/rfc1847.txt) | Security Multiparts for MIME: Multipart/Signed and Multipart/Encrypted | Proposed Standard | `multipart/signed` and `multipart/encrypted` |
| [8551](rfc/rfc8551.txt) | Secure/Multipurpose Internet Mail Extensions (S/MIME) Version 4.0 Message Specification | Proposed Standard | S/MIME 4.0 message specification |
| [8550](rfc/rfc8550.txt) | Secure/Multipurpose Internet Mail Extensions (S/MIME) Version 4.0 Certificate Handling | Proposed Standard | S/MIME 4.0 certificate handling |
| [5652](rfc/rfc5652.txt) | Cryptographic Message Syntax (CMS) | Internet Standard | Cryptographic Message Syntax (CMS) |
| [9598](rfc/rfc9598.txt) | Internationalized Email Addresses in X.509 Certificates | Proposed Standard | Internationalised email addresses in X.509 |
| [9495](rfc/rfc9495.txt) | Certification Authority Authorization (CAA) Processing for Email Addresses | Proposed Standard | CAA for email-address certificates |
| [9216](rfc/rfc9216.txt) | S/MIME Example Keys and Certificates | Informational | S/MIME example keys and certificates |
| [9580](rfc/rfc9580.txt) | OpenPGP | Proposed Standard | OpenPGP (obsoletes 4880) |
| [9980](rfc/rfc9980.txt) | Post-Quantum Cryptography in OpenPGP | Proposed Standard | Post-quantum cryptography in OpenPGP |
| [3156](rfc/rfc3156.txt) | MIME Security with OpenPGP | Proposed Standard | PGP/MIME |
| [7929](rfc/rfc7929.txt) | DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP | Experimental | OpenPGP keys in DNS via DANE (experimental) |

#### Mailing Lists, URIs & Miscellaneous Headers

| RFC | Title | Status | Notes |
|---|---|---|---|
| [2369](rfc/rfc2369.txt) | The Use of URLs as Meta-Syntax for Core Mail List Commands and their Transport through Message Header Fields | Proposed Standard | `List-Unsubscribe`, `List-Post`, `List-Help`, … |
| [2919](rfc/rfc2919.txt) | List-Id: A Structured Field and Namespace for the Identification of Mailing Lists | Proposed Standard | `List-Id` |
| [8058](rfc/rfc8058.txt) | Signaling One-Click Functionality for List Email Headers | Proposed Standard | One-click `List-Unsubscribe-Post` |
| [5064](rfc/rfc5064.txt) | The Archived-At Message Header Field | Proposed Standard | `Archived-At` |
| [6068](rfc/rfc6068.txt) | The 'mailto' URI Scheme | Proposed Standard | `mailto:` URI scheme |
| [9057](rfc/rfc9057.txt) | Email Author Header Field | Experimental | `Author:` header (experimental) |
| [9228](rfc/rfc9228.txt) | Delivered-To Email Header Field | Experimental | `Delivered-To:` header (experimental) |
| [9078](rfc/rfc9078.txt) | Reaction: Indicating Summary Reaction to a Message | Experimental | Reactions (experimental) |

### Superseded RFCs (not included)

These are still widely cited but have been obsoleted; the replacement is in the table above.

| Obsolete | Replaced by |
|---|---|
| 3501 | 9051 |
| 2087 | 9208 |
| 6855 | 9755 |
| 7489 | 9989–9991 |
| 9091 | 9989 |
| 3798 | 8098 |
| 4880 | 9580 |
| 5751 | 8551 |
| 2821 | 5321 |
| 2822 | 5322 |

## Refreshing the library

Every file in `rfc/` is the canonical text from the RFC Editor:

```sh
curl -fsSo rfc/rfc5321.txt https://www.rfc-editor.org/rfc/rfc5321.txt
```

To check whether anything here has since been obsoleted, look for an `obsoleted-by` element for the RFC in <https://www.rfc-editor.org/rfc-index.xml>, or see the "Obsoleted by" line on its `https://www.rfc-editor.org/rfc/rfcNNNN` page.
