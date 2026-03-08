# uDNS -- UTF-8 DNS Server

## Complete Documentation for Usage

------------------------------------------------------------------------

# 1. Overview

uDNS is an experimental DNS server that can process domain names
**directly in UTF-8**.

While traditional DNS servers only support ASCII and encode
international domains using **Punycode (IDNA)**, uDNS allows the direct
use of Unicode domains.

Example:

ä.example → xn--4ca.example

The server automatically converts between UTF-8 and Punycode when
communicating with classical DNS servers.

------------------------------------------------------------------------

# 2. Architecture

The server is implemented in **Rust** and consists of several modules.

  Module                 Function
  ---------------------- -------------------------------------------------------
  main.rs                Starts the DNS server and processes incoming requests
  dns.rs                 DNS parsing and creation of responses
  dnssec.rs              DNSSEC support
  config.rs              Loading and processing configuration files
  record_handling.rs     Processing zone files
  punycode_handling.rs   UTF-8 ↔ Punycode conversion

------------------------------------------------------------------------

# 3. Requirements

Required software:

-   Rust
-   Cargo
-   Linux / macOS / Windows

Install Rust:

``` bash
curl https://sh.rustup.rs -sSf | sh
```

------------------------------------------------------------------------

# 4. Installation

Clone the repository:

``` bash
git clone https://github.com/Otzie2023/uDNS-UTF8-DNS-
cd uDNS-UTF8-DNS-
```

Compile the project:

``` bash
cargo build --release
```

The executable will then be located at:

    target/release/udns

------------------------------------------------------------------------

# 5. Start the Server

``` bash
cargo run
```

or

``` bash
./target/release/udns
```

Default port:

    UDP 1025

Example output:

    DNS Server (UTF-8, JSON config, PTR support, DNSSEC) running on port 1025...

------------------------------------------------------------------------

# 6. Configuration

The central configuration file is:

    zones.json

It defines:

-   DNS zones
-   external DNS forwarders
-   DNSSEC settings

------------------------------------------------------------------------

# 7. zones.json

Example:

``` json
{
  "zones": [
    {
      "domain": "example.dkr",
      "zone_file": "zones/example.dkr.json",
      "enabled": true
    }
  ],
  "forwarders": [
    { "address": "1.1.1.1:53", "punny_weiterleitung": true },
    { "address": "[2606:4700:4700::1001]:53", "punny_weiterleitung": true }
  ]
}
```

------------------------------------------------------------------------

# 8. Explanation of the `punny_weiterleitung` Parameter

The parameter

    "punny_weiterleitung": true

controls **whether Unicode domains are automatically converted into
Punycode** before a request is forwarded to an external DNS server.

## Background

The traditional DNS protocol supports only **ASCII characters**.

Unicode domains are therefore normally encoded using **Punycode
(IDNA)**.

Example:

  Unicode      Punycode
  ------------ -------------------
  ä.example    xn--4ca.example
  münchen.de   xn--mnchen-3ya.de

## How It Works in the uDNS Server

When a client requests a UTF-8 domain:

    ä.dkr

The process is as follows:

1.  uDNS checks local zones
2.  If not found → the request is forwarded
3.  If `punny_weiterleitung = true`:
    -   the domain is automatically converted to Punycode
4.  The request is sent to an external DNS server
5.  The response is returned

### Example

Client request:

    münchen.example

Forwarded to a classical DNS server:

    xn--mnchen-3ya.example

## Behavior with `false`

If

    "punny_weiterleitung": false

is set:

-   Domains are **not automatically converted**
-   The request is forwarded unchanged
-   This only works if the destination server also supports UTF-8 DNS

------------------------------------------------------------------------

# 9. Zone Files

Zones are located in the directory:

    zones/

Example:

    zones/example.dkr.json

### Structure

``` json
{
  "domain": "example.dkr",
  "ttl": 3600,
  "soa": {
    "primary_ns": "ns1.example.dkr.",
    "admin_email": "admin.example.dkr.",
    "serial": 2025091001,
    "refresh": 3600,
    "retry": 600,
    "expire": 1209600,
    "minimum": 3600
  },
  "records": [
    {
      "type": "A",
      "name": "@",
      "value": "192.0.2.1"
    }
  ]
}
```

------------------------------------------------------------------------

# 10. Supported DNS Records

  Record   Description
  -------- --------------
  A        IPv4 address
  AAAA     IPv6 address
  CNAME    Alias
  MX       Mail server
  TXT      Text record
  NS       Nameserver
  PTR      Reverse DNS

------------------------------------------------------------------------

# 11. UTF-8 Domains

The server allows domains directly in Unicode.

Example:

    ä.dkr

or

    münchen.dkr

These can be used directly in zone files.

------------------------------------------------------------------------

# 12. Forwarders

If a domain does not exist locally, the request is forwarded to external
DNS servers.

Example:

``` json
"forwarders": [
  { "address": "1.1.1.1:53", "punny_weiterleitung": true }
]
```

The server then acts as a **DNS forwarder / resolver**.

------------------------------------------------------------------------

# 13. PTR Records

Reverse DNS entries are defined via

    ptrs.json

Example:

``` json
[
  {
    "ip": "192.168.1.10",
    "ptr": "server.example.dkr",
    "ttl": 3600
  }
]
```

------------------------------------------------------------------------

# 14. DNSSEC

The server supports DNSSEC with:

-   KSK (Key Signing Key)
-   ZSK (Zone Signing Key)

Example configuration:

``` json
{
  "domain": "hessen.dkr",
  "dnssec_enabled": true,
  "ZSK-private": "keys/hessen.dkr/zsk.private",
  "KSK-private": "keys/hessen.dkr/ksk.private"
}
```

------------------------------------------------------------------------

# 15. Testing the Server

Server running on:

    127.0.0.1:1025

Test with dig:

``` bash
dig @127.0.0.1 -p 1025 example.dkr
```

Unicode test:

``` bash
dig @127.0.0.1 -p 1025 ä.dkr
```

------------------------------------------------------------------------

# 16. Project Structure

    uDNS-UTF8-DNS
    │
    ├─ src/
    │   ├─ main.rs
    │   ├─ dns.rs
    │   ├─ dnssec.rs
    │   ├─ config.rs
    │   ├─ record_handling.rs
    │   └─ punycode_handling.rs
    │
    ├─ zones/
    ├─ keys/
    ├─ ptrs.json
    ├─ zones.json
    └─ tester_AAAA-Rekord.py

------------------------------------------------------------------------

# 17. Summary

uDNS is an experimental DNS server with the following features:

-   Native UTF-8 domain names
-   Automatic Punycode conversion
-   JSON-based zone configuration
-   DNSSEC support
-   DNS forwarder functionality
-   PTR reverse DNS support

The parameter **punny_weiterleitung** ensures that Unicode domains are
automatically converted into Punycode during forwarding so that
traditional DNS servers remain compatible.
