// src/dns.rs
//! DNS handling, records, encoding and local response generation (inkl. DNSSEC RRSIG-Erzeugung).
//! Diese Datei ersetzt/überarbeitet deine alte dns.rs komplett.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use pem;
use base64::{engine::general_purpose, Engine as _};
use simple_asn1::{from_der, ASN1Block};
use ed25519_dalek::{SecretKey, PublicKey};
use rsa::RsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey, EncodePublicKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
// ring is used in dnssec.rs for Ed25519 operations

use crate::config::Expire;
use crate::config::ForwarderEntry;

use crate::dnssec;

pub fn try_forward_to_upstreams(
    forwarders: &[ForwarderEntry],
    request: &[u8],
    _q: &Question,
    _original_qname: &str,
    _punny_flag: bool,
    timeout: Duration,
) -> Result<(Vec<u8>, String, bool), Box<dyn Error>> {
    // Try forwarders over UDP. Return first successful response along with used forwarder and TC flag.
    for f in forwarders {
        let (addr, wants_dnssec) = match f {
            ForwarderEntry::Simple(s) => (if s.contains(':') { s.clone() } else { format!("{}:53", s) }, false),
            ForwarderEntry::WithFlag { address, punny_weitergabe: _, dnssec } => (if address.contains(':') { address.clone() } else { format!("{}:53", address) }, dnssec.unwrap_or(false)),
        };
        // prepare outgoing request; if forwarder requests DNSSEC ensure DO bit is set on the OPT RR
        let mut outgoing = request.to_vec();
        if wants_dnssec {
            if outgoing.len() >= 12 {
                let arcount = u16::from_be_bytes([outgoing[10], outgoing[11]]);
                let mut opt_found = false;
                let mut pos = 12usize + _q.qlength;
                for _ in 0..arcount {
                    if pos >= outgoing.len() { break; }
                    match decode_name(&outgoing, pos) {
                        Ok((_name, newpos)) => {
                            pos = newpos;
                            if pos + 10 > outgoing.len() { break; }
                            let rtype = u16::from_be_bytes([outgoing[pos], outgoing[pos+1]]);
                            if rtype == 41 {
                                // OPT RR: set DO bit in Z field (bytes pos+6..pos+8)
                                let z = u16::from_be_bytes([outgoing[pos+6], outgoing[pos+7]]);
                                let newz = z | 0x8000u16;
                                let nz = newz.to_be_bytes();
                                outgoing[pos+6] = nz[0]; outgoing[pos+7] = nz[1];
                                opt_found = true;
                                break;
                            } else {
                                // skip class(2) ttl(4) rdlen(2) rdata
                                let rdlen = u16::from_be_bytes([outgoing[pos+8], outgoing[pos+9]]) as usize;
                                pos += 10 + rdlen;
                            }
                        }
                        Err(_) => { break; }
                    }
                }
                if !opt_found {
                    // append an OPT RR with DO bit set
                    let new_ar = arcount.wrapping_add(1);
                    let new_ar_b = new_ar.to_be_bytes();
                    outgoing[10] = new_ar_b[0]; outgoing[11] = new_ar_b[1];
                    // owner name = root (0)
                    outgoing.push(0u8);
                    // type = 41 (OPT)
                    outgoing.extend_from_slice(&41u16.to_be_bytes());
                    // UDP payload size = 1232
                    outgoing.extend_from_slice(&1232u16.to_be_bytes());
                    // extended RCODE (1), version (1)
                    outgoing.push(0u8); outgoing.push(0u8);
                    // Z field with DO bit
                    outgoing.extend_from_slice(&0x8000u16.to_be_bytes());
                    // RDLEN = 0
                    outgoing.extend_from_slice(&0u16.to_be_bytes());
                }
            }
        }

        match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(sock) => {
                let _ = sock.set_read_timeout(Some(timeout));
                if wants_dnssec {
                    println!("[forward] forwarding to {} with DNSSEC (DO set)", addr);
                } else {
                    println!("[forward] forwarding to {}", addr);
                }
                let _ = sock.send_to(&outgoing, &addr);
                let mut buf = [0u8; 4096];
                match sock.recv_from(&mut buf) {
                    Ok((amt, _peer)) => {
                        let resp = buf[..amt].to_vec();
                        // If caller wanted DNSSEC, check whether upstream returned RRSIG (type 46)
                        let ancount = if resp.len() >= 8 { u16::from_be_bytes([resp[6], resp[7]]) } else { 0 };
                        let nscount = if resp.len() >= 10 { u16::from_be_bytes([resp[8], resp[9]]) } else { 0 };
                        let arcount = if resp.len() >= 12 { u16::from_be_bytes([resp[10], resp[11]]) } else { 0 };
                        if wants_dnssec {
                            let has_rrsig = response_has_rrtype(&resp, 46u16);
                            println!("[forward] upstream {} responded: AN={} NS={} AR={} RRSIG={}", addr, ancount, nscount, arcount, has_rrsig);
                        } else {
                            println!("[forward] upstream {} responded: AN={} NS={} AR={}", addr, ancount, nscount, arcount);
                        }
                        let truncated = if resp.len() >= 3 { (resp[2] & 0x02) != 0 } else { false };
                        return Ok((resp, addr, truncated));
                    }
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        }
    }
    Err("all forwarders failed".into())
}


/// DNS Question and Record definitions
#[derive(Debug, Clone)]
pub struct Question {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub qlength: usize,
}

#[derive(Debug, Clone)]
pub enum RecordKind {
    A(String),
    AAAA(String),
    CNAME(String),
    NS(String),
    MX { pref: u16, exchange: String },
    TXT(String),
    SOA { mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: Expire, minimum: u32 },
    PTR(String),
    SRV { priority: u16, weight: u16, port: u16, target: String },
    NAPTR { order: u16, preference: u16, flags: String, services: String, regexp: String, replacement: String },
    CAA { flags: u8, tag: String, value: String },
    TLSA { usage: u8, selector: u8, matching_type: u8, cert_assoc_data: Vec<u8> },
    SSHFP { algorithm: u8, fptype: u8, fingerprint: Vec<u8> },
    DNAME(String),
    HINFO { cpu: String, os: String },
    RP { mbox: String, txt: String },
    DNSKEY { flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8> },
    RRSIG { type_covered: u16, algorithm: u8, labels: u8, original_ttl: u32,
            signature_expiration: u32, signature_inception: u32, key_tag: u16,
            signer_name: String, signature: Vec<u8> },
    DS { key_tag: u16, algorithm: u8, digest_type: u8, digest: Vec<u8> },
    NSEC { next_domain_name: String, type_bit_maps: Vec<u16> },
    NSEC3 { hash_algorithm: u8, flags: u8, iterations: u16, salt: Vec<u8>,
            next_hashed_owner_name: Vec<u8>, type_bit_maps: Vec<u16> },
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub kind: RecordKind,
    pub ttl: u32,
    pub class: u16,
}

#[derive(Debug, Clone)]
pub struct DnssecKey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    pub private_key_pem: Vec<u8>, // store PEM bytes so we can reload with dnssec module
    pub key_tag: u16,
}

//
// Utilities: name encoding/decoding
//

pub fn decode_name(data: &[u8], mut pos: usize) -> Result<(String, usize), Box<dyn Error>> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut original_pos = pos;
    let mut visited: HashSet<usize> = HashSet::new();

    loop {
        if pos >= data.len() { return Err("decode_name: out of bounds".into()); }
        let len = data[pos];
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() { return Err("decode_name: invalid pointer".into()); }
            let pointer = (((len & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            if visited.contains(&pointer) { return Err("decode_name: pointer loop".into()); }
            visited.insert(pointer);
            if !jumped {
                original_pos = pos + 2;
                jumped = true;
            }
            pos = pointer;
            continue;
        }
        if len == 0 {
            if !jumped { original_pos = pos + 1; }
            break;
        }
        let l = len as usize;
        pos += 1;
        if pos + l > data.len() { return Err("decode_name: label overrun".into()); }
        let slice = &data[pos .. pos + l];
        let label = str::from_utf8(slice)?.to_string();
        labels.push(label);
        pos += l;
    }

    Ok((labels.join("."), original_pos))
}

pub fn encode_name(name: &str) -> Vec<u8> {
    if name.is_empty() { return vec![0]; }
    let mut out = Vec::new();
    for label in name.split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
    out
}

//
// RDATA encoding (wire format) for supported types
//
pub fn encode_rdata_for_record(rec: &DnsRecord) -> Result<Vec<u8>, Box<dyn Error>> {
    match &rec.kind {
        RecordKind::A(ip) => {
            let v: Ipv4Addr = ip.parse()?;
            Ok(v.octets().to_vec())
        }
        RecordKind::AAAA(ip) => {
            let v: Ipv6Addr = ip.parse()?;
            Ok(v.octets().to_vec())
        }
        RecordKind::CNAME(t) | RecordKind::NS(t) | RecordKind::PTR(t) => {
            Ok(encode_name(&t.to_lowercase()))
        }
        RecordKind::MX { pref, exchange } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&pref.to_be_bytes());
            buf.extend_from_slice(&encode_name(&exchange.to_lowercase()));
            Ok(buf)
        }
        RecordKind::TXT(s) => {
            let bytes = s.as_bytes();
            if bytes.len() > 255 { return Err("TXT too long".into()); }
            let mut buf = Vec::new();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
            Ok(buf)
        }
        RecordKind::SRV { priority, weight, port, target } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&priority.to_be_bytes());
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
            buf.extend_from_slice(&encode_name(&target.to_lowercase()));
            Ok(buf)
        }
        RecordKind::NAPTR { order, preference, flags, services, regexp, replacement } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&order.to_be_bytes());
            buf.extend_from_slice(&preference.to_be_bytes());
            let fb = flags.as_bytes();
            buf.push(fb.len() as u8); buf.extend_from_slice(fb);
            let sb = services.as_bytes();
            buf.push(sb.len() as u8); buf.extend_from_slice(sb);
            let rb = regexp.as_bytes();
            buf.push(rb.len() as u8); buf.extend_from_slice(rb);
            buf.extend_from_slice(&encode_name(&replacement.to_lowercase()));
            Ok(buf)
        }
        RecordKind::CAA { flags, tag, value } => {
            let mut buf = Vec::new();
            buf.push(*flags);
            let tb = tag.as_bytes();
            buf.push(tb.len() as u8);
            buf.extend_from_slice(tb);
            buf.extend_from_slice(value.as_bytes());
            Ok(buf)
        }
        RecordKind::TLSA { usage, selector, matching_type, cert_assoc_data } => {
            let mut buf = Vec::new();
            buf.push(*usage);
            buf.push(*selector);
            buf.push(*matching_type);
            buf.extend_from_slice(cert_assoc_data);
            Ok(buf)
        }
        RecordKind::SSHFP { algorithm, fptype, fingerprint } => {
            let mut buf = Vec::new();
            buf.push(*algorithm);
            buf.push(*fptype);
            buf.extend_from_slice(fingerprint);
            Ok(buf)
        }
        RecordKind::DNAME(t) => Ok(encode_name(&t.to_lowercase())),
        RecordKind::HINFO { cpu, os } => {
            let cb = cpu.as_bytes(); let ob = os.as_bytes();
            if cb.len()>255 || ob.len()>255 { return Err("HINFO token too long".into()); }
            let mut buf = Vec::new();
            buf.push(cb.len() as u8); buf.extend_from_slice(cb);
            buf.push(ob.len() as u8); buf.extend_from_slice(ob);
            Ok(buf)
        }
        RecordKind::RP { mbox, txt } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&encode_name(&mbox.to_lowercase()));
            buf.extend_from_slice(&encode_name(&txt.to_lowercase()));
            Ok(buf)
        }
        RecordKind::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&encode_name(&mname.to_lowercase()));
            buf.extend_from_slice(&encode_name(&rname.to_lowercase()));
            buf.extend_from_slice(&serial.to_be_bytes());
            buf.extend_from_slice(&refresh.to_be_bytes());
            buf.extend_from_slice(&retry.to_be_bytes());
            let expire_u32 = expire.as_seconds_or_max();
            buf.extend_from_slice(&expire_u32.to_be_bytes());
            buf.extend_from_slice(&minimum.to_be_bytes());
            Ok(buf)
        }
        RecordKind::DNSKEY { flags, protocol, algorithm, public_key } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&flags.to_be_bytes());
            buf.push(*protocol);
            buf.push(*algorithm);
            buf.extend_from_slice(public_key);
            Ok(buf)
        }
        RecordKind::RRSIG { type_covered, algorithm, labels, original_ttl,
                           signature_expiration, signature_inception, key_tag,
                           signer_name, signature } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&type_covered.to_be_bytes());
            buf.push(*algorithm);
            buf.push(*labels);
            buf.extend_from_slice(&original_ttl.to_be_bytes());
            buf.extend_from_slice(&signature_expiration.to_be_bytes());
            buf.extend_from_slice(&signature_inception.to_be_bytes());
            buf.extend_from_slice(&key_tag.to_be_bytes());
            buf.extend_from_slice(&encode_name(&signer_name.to_lowercase()));
            buf.extend_from_slice(signature);
            Ok(buf)
        }
        RecordKind::DS { key_tag, algorithm, digest_type, digest } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&key_tag.to_be_bytes());
            buf.push(*algorithm);
            buf.push(*digest_type);
            buf.extend_from_slice(digest);
            Ok(buf)
        }
        RecordKind::NSEC { next_domain_name, type_bit_maps } => {
            // Simplified: encode next_domain_name and a bitmap generation
            let mut buf = Vec::new();
            buf.extend_from_slice(&encode_name(&next_domain_name.to_lowercase()));
            // Build type bitmap windows
            let mut windows: HashMap<u8, Vec<u8>> = HashMap::new();
            for &t in type_bit_maps {
                let w = (t >> 8) as u8;
                let bit = (t & 0xFF) as u8;
                let entry = windows.entry(w).or_insert_with(|| vec![0u8; 32]);
                let idx = (bit / 8) as usize;
                let pos = 7 - (bit % 8);
                if idx < entry.len() { entry[idx] |= 1u8 << pos; }
            }
            let mut wbytes = Vec::new();
            for (w, data) in windows {
                // trim trailing zeros
                let mut len = data.len();
                while len > 0 && data[len-1] == 0 { len -= 1; }
                if len == 0 { continue; }
                wbytes.push(w);
                wbytes.push(len as u8);
                wbytes.extend_from_slice(&data[..len]);
            }
            buf.extend_from_slice(&wbytes);
            Ok(buf)
        }
        RecordKind::NSEC3 { hash_algorithm, flags, iterations, salt, next_hashed_owner_name, type_bit_maps } => {
            let mut buf = Vec::new();
            buf.push(*hash_algorithm);
            buf.push(*flags);
            buf.extend_from_slice(&iterations.to_be_bytes());
            buf.push(salt.len() as u8);
            buf.extend_from_slice(salt);
            buf.push(next_hashed_owner_name.len() as u8);
            buf.extend_from_slice(next_hashed_owner_name);
            // type bitmap logic similar to NSEC
            let mut windows: HashMap<u8, Vec<u8>> = HashMap::new();
            for &t in type_bit_maps {
                let w = (t >> 8) as u8;
                let bit = (t & 0xFF) as u8;
                let entry = windows.entry(w).or_insert_with(|| vec![0u8; 32]);
                let idx = (bit / 8) as usize;
                let pos = 7 - (bit % 8);
                if idx < entry.len() { entry[idx] |= 1u8 << pos; }
            }
            for (w, data) in windows {
                let mut len = data.len();
                while len > 0 && data[len-1] == 0 { len -= 1; }
                if len == 0 { continue; }
                buf.push(w);
                buf.push(len as u8);
                buf.extend_from_slice(&data[..len]);
            }
            Ok(buf)
        }
    }
}

pub fn record_type_number(kind: &RecordKind) -> u16 {
    match kind {
        RecordKind::A(_) => 1,
        RecordKind::NS(_) => 2,
        RecordKind::CNAME(_) => 5,
        RecordKind::SOA { .. } => 6,
        RecordKind::PTR(_) => 12,
        RecordKind::HINFO { .. } => 13,
        RecordKind::MX { .. } => 15,
        RecordKind::TXT(_) => 16,
        RecordKind::RP { .. } => 17,
        RecordKind::AAAA(_) => 28,
        RecordKind::SRV { .. } => 33,
        RecordKind::NAPTR { .. } => 35,
        RecordKind::TLSA { .. } => 52,
        RecordKind::SSHFP { .. } => 44,
        RecordKind::CAA { .. } => 257,
        RecordKind::DNSKEY { .. } => 48,
        RecordKind::RRSIG { .. } => 46,
        RecordKind::DS { .. } => 43,
        RecordKind::NSEC { .. } => 47,
        RecordKind::NSEC3 { .. } => 50,
        RecordKind::DNAME(_) => 39,
    }
}

//
// Parse question (from wire)
//
pub fn parse_question(data: &[u8]) -> Result<Question, Box<dyn Error>> {
    if data.len() < 12 { return Err("short DNS message".into()); }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    let mut visited = HashSet::new();
    let mut jumped = false;
    let mut original_pos = pos;

    loop {
        if pos >= data.len() { return Err("question parse OOB".into()); }
        let len = data[pos];
        if (len & 0xC0) == 0xC0 {
            if pos +1 >= data.len() { return Err("pointer OOB".into()); }
            let ptr = (((len & 0x3F) as usize) << 8) | (data[pos+1] as usize);
            if visited.contains(&ptr) { return Err("pointer loop".into()); }
            visited.insert(ptr);
            if !jumped {
                original_pos = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            if !jumped { original_pos = pos + 1; }
            break;
        }
        let l = len as usize;
        pos +=1;
        if pos + l > data.len() { return Err("label overrun".into()); }
        labels.push(str::from_utf8(&data[pos..pos+l])?.to_string());
        pos += l;
    }

    if original_pos + 4 > data.len() { return Err("qtype/class truncated".into()); }
    let qtype = u16::from_be_bytes([data[original_pos], data[original_pos+1]]);
    let qclass = u16::from_be_bytes([data[original_pos+2], data[original_pos+3]]);
    let qname = labels.join(".");
    let qlength = (original_pos + 4) - 12;
    Ok(Question { qname, qtype, qclass, qlength })
}

// Scan a DNS response buffer for any RR of the given type (searches Answer, Authority, Additional sections).
// Returns true if at least one RR with `rtype` is present.
pub fn response_has_rrtype(resp: &[u8], rtype_to_find: u16) -> bool {
    if resp.len() < 12 { return false; }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    let arcount = u16::from_be_bytes([resp[10], resp[11]]) as usize;
    let mut pos = 12usize;
    // skip questions
    for _ in 0..qdcount {
        match decode_name(resp, pos) {
            Ok((_name, newpos)) => {
                pos = newpos + 4; // qtype(2) qclass(2)
                if pos > resp.len() { return false; }
            }
            Err(_) => return false,
        }
    }

    // helper to scan n RRs and return true if found
    let scan_rrs = |count: usize, mut pos: usize| -> Option<bool> {
        let mut i = 0usize;
        while i < count {
            if pos >= resp.len() { return None; }
            match decode_name(resp, pos) {
                Ok((_name, newpos)) => {
                    pos = newpos;
                    if pos + 10 > resp.len() { return None; }
                    let rtype = u16::from_be_bytes([resp[pos], resp[pos+1]]);
                    let rdlen = u16::from_be_bytes([resp[pos+8], resp[pos+9]]) as usize;
                    if rtype == rtype_to_find { return Some(true); }
                    pos += 10 + rdlen;
                }
                Err(_) => return None,
            }
            i += 1;
        }
        Some(false)
    };

    if let Some(found) = scan_rrs(ancount, pos) { if found { return true; } }
    // advance pos past answers
    for _ in 0..ancount {
        if let Ok((_name, newpos)) = decode_name(resp, pos) {
            pos = newpos;
            if pos + 10 > resp.len() { return false; }
            let rdlen = u16::from_be_bytes([resp[pos+8], resp[pos+9]]) as usize;
            pos += 10 + rdlen;
        } else { return false; }
    }
    // authority
    if let Some(found) = scan_rrs(nscount, pos) { if found { return true; } }
    // advance pos past authority
    for _ in 0..nscount {
        if let Ok((_name, newpos)) = decode_name(resp, pos) {
            pos = newpos;
            if pos + 10 > resp.len() { return false; }
            let rdlen = u16::from_be_bytes([resp[pos+8], resp[pos+9]]) as usize;
            pos += 10 + rdlen;
        } else { return false; }
    }
    // additional
    if let Some(found) = scan_rrs(arcount, pos) { if found { return true; } }
    false
}

//
// DNSSEC signing helpers used by build_response_local
//

/// Canonicalize an owner name for wire form: lowercase labels, no compression
fn canonical_owner_wire(name: &str) -> Vec<u8> {
    encode_name(&name.to_lowercase())
}

/// Canonicalize RDATA where rdata contains domain names (we lower-case them).
/// This function handles the common rdata types where names appear; for other types it returns rdata unchanged.
fn canonicalize_rdata_for_type(rtype: u16, rdata: &[u8]) -> Vec<u8> {
    match rtype {
        1 | 28 | 16 | 6 | 12 | 33 | 35 | 52 | 44 | 2 | 5 | 39 | 257 => {
            // these types either are pure names or include name(s) stored in wire format.
            // For types that already contain names in wire form (like MX, NS, CNAME, PTR, SRV, SOA),
            // we must lowercase label bytes. We do that by parsing the wire name(s) and re-encoding.
            // For simplicity, decode/encode each name occurrence.
            // We'll attempt to decode; if it fails, return original bytes.
            // Common patterns:
            // NS/CNAME/PTR: single domain name
            // MX: 2 bytes pref + domain name
            // SRV: 6 bytes header + domain name
            // SOA: two domain names + fixed fields
            let mut out = Vec::new();
            match rtype {
                2 | 5 | 12 | 39 => { // NS, CNAME, PTR, DNAME
                    // rdata is a single domain name in wire form
                    if let Ok((nm, _)) = decode_name(rdata, 0) {
                        out.extend_from_slice(&encode_name(&nm.to_lowercase()));
                    } else {
                        out.extend_from_slice(rdata);
                    }
                }
                15 => { // MX
                    if rdata.len() >= 2 {
                        out.extend_from_slice(&rdata[0..2]); // pref
                        if let Ok((nm, _)) = decode_name(rdata, 2) {
                            out.extend_from_slice(&encode_name(&nm.to_lowercase()));
                        } else {
                            out.extend_from_slice(&rdata[2..]);
                        }
                    } else { out.extend_from_slice(rdata); }
                }
                33 => { // SRV
                    if rdata.len() >= 6 {
                        out.extend_from_slice(&rdata[0..6]);
                        if let Ok((nm, _)) = decode_name(rdata, 6) {
                            out.extend_from_slice(&encode_name(&nm.to_lowercase()));
                        } else {
                            out.extend_from_slice(&rdata[6..]);
                        }
                    } else { out.extend_from_slice(rdata); }
                }
                6 => { // SOA: mname rname serial refresh retry expire minimum
                    // We decode two names, then copy remaining u32s
                    let mut pos = 0usize;
                    if let Ok((mname, p1)) = decode_name(rdata, pos) {
                        out.extend_from_slice(&encode_name(&mname.to_lowercase()));
                        pos = p1;
                        if let Ok((rname, p2)) = decode_name(rdata, pos) {
                            out.extend_from_slice(&encode_name(&rname.to_lowercase()));
                            pos = p2;
                            if pos + 20 <= rdata.len() {
                                out.extend_from_slice(&rdata[pos..pos+20]);
                            } else {
                                // fallback
                                out.extend_from_slice(&rdata[pos..]);
                            }
                        } else { out.extend_from_slice(rdata); }
                    } else { out.extend_from_slice(rdata); }
                }
                48 => { // DNSKEY: flags(2) protocol(1) algorithm(1) publickey(n)
                    out.extend_from_slice(rdata); // DNSKEY canonicalization = rdata as-is except name-case not relevant
                }
                257 => { // CAA contains tag (not name) -> as-is
                    out.extend_from_slice(rdata);
                }
                16 => { // TXT -> as-is (but octet-wise)
                    out.extend_from_slice(rdata);
                }
                52 | 44 => { // TLSA, SSHFP -> as-is
                    out.extend_from_slice(rdata);
                }
                _ => { out.extend_from_slice(rdata); }
            }
            out
        }
        _ => rdata.to_vec()
    }
}

/// Build canonical RR wire for a RR: owner (canonical wire), type, class, origin TTL, rdlength, canonical rdata
fn build_canonical_rr_wire(owner: &str, rtype: u16, rclass: u16, orig_ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&canonical_owner_wire(owner));
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&rclass.to_be_bytes());
    out.extend_from_slice(&orig_ttl.to_be_bytes());
    let crepr = canonicalize_rdata_for_type(rtype, rdata);
    out.extend_from_slice(&(crepr.len() as u16).to_be_bytes());
    out.extend_from_slice(&crepr);
    out
}

/// Sign a canonical RRset using dnssec::sign_message_pkcs1v15_sha256
/// The `rrsighdr` bytes are the RRSIG RDATA fields prior to the signature (i.e. all RRSIG fields except signature).
/// Per RFC4034 you sign: RRSIG RDATA (excluding signature) || canonical RRset (each RR in canonical wire form concatenated).
fn sign_rrset_bytes(
    priv_pem: &[u8],
    rrsighdr: &[u8],
    rr_wires: &[Vec<u8>],
    algorithm: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // concat header + rr_wires
    let mut data = Vec::new();
    data.extend_from_slice(rrsighdr);
    // RRs must be in canonical order (bytewise ascending) — we assume caller sorted rr_wires.
    for r in rr_wires {
        data.extend_from_slice(r);
    }

    // Dispatch signing by algorithm; helper accepts raw private bytes or PEM text
    let sig = dnssec::sign_by_algorithm_bytes(priv_pem, algorithm, &data)?;
    Ok(sig) // Sign
}

//
// build_response_local: uses the DNS records in the in-memory store and optionally DNSSEC keys
// - If DNSSEC requested via DO bit and zone has key, produce DNSKEY in additional and RRSIGs for RRsets
//
pub fn build_response_local(
    request: &[u8],
    q: &Question,
    domain_norm: &str,
    dns_records: &HashMap<String, Vec<DnsRecord>>,
    dnssec_enabled: bool,
    dnssec_key: &Option<DnssecKey>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Header
    let mut out = Vec::new();
    if request.len() < 12 { return Err("request too short".into()); }
    out.push(request[0]); out.push(request[1]);
    let mut flags1 = request[2];
    flags1 |= 0x80; // QR
    flags1 |= 0x04; // AA
    out.push(flags1);
    let mut flags2 = request[3];
    flags2 &= !(0x80);
    flags2 &= 0x0F;
    out.push(flags2);
    out.push(request[4]); out.push(request[5]);

    // Collect answers (matching qtype) for domain_norm
    let mut answers: Vec<(DnsRecord, u16, u16, u32, Vec<u8>)> = Vec::new();
    if let Some(recs) = dns_records.get(domain_norm) {
        if q.qtype == 255 { // ANY
            for rec in recs {
                let rtype = record_type_number(&rec.kind);
                let rdata = encode_rdata_for_record(rec)?;
                answers.push((rec.clone(), rtype, rec.class, rec.ttl, rdata));
            }
        } else {
            for rec in recs {
                let rtype = record_type_number(&rec.kind);
                if rtype == q.qtype {
                    let rdata = encode_rdata_for_record(rec)?;
                    answers.push((rec.clone(), rtype, rec.class, rec.ttl, rdata));
                }
            }
        }
    }

    // Authority (SOA if no answers)
    let mut authority: Vec<(u16,u16,u32,Vec<u8>)> = Vec::new();
    if answers.is_empty() {
        if let Some(recs) = dns_records.get(domain_norm) {
            // add SOA if present
            for rec in recs {
                if let RecordKind::SOA { .. } = &rec.kind {
                    let rdata = encode_rdata_for_record(rec)?;
                    authority.push((6u16, rec.class, rec.ttl, rdata));
                    break;
                }
            }

            // also produce NSEC for this owner listing existing types (authenticated denial for no-data)
            let mut types: Vec<u16> = Vec::new();
            let mut class_to_use: u16 = 1;
            let mut ttl_to_use: u32 = 3600;
            for rec in recs {
                let rtype = record_type_number(&rec.kind);
                if !types.contains(&rtype) { types.push(rtype); }
                class_to_use = rec.class; ttl_to_use = rec.ttl;
            }
            // compute next domain name in zone (simple lexicographic of keys)
            let mut keys: Vec<String> = dns_records.keys().map(|k| k.to_lowercase()).collect();
            keys.sort();
            let mut next_domain = domain_norm.to_string();
            if let Some(idx) = keys.iter().position(|k| k == &domain_norm.to_lowercase()) {
                let next_idx = (idx + 1) % keys.len();
                next_domain = keys[next_idx].clone();
            }
            let nsec_rec = DnsRecord { kind: RecordKind::NSEC { next_domain_name: next_domain.clone(), type_bit_maps: types.clone() }, ttl: ttl_to_use, class: class_to_use };
            let nsec_rdata = encode_rdata_for_record(&nsec_rec)?;
            authority.push((47u16, class_to_use, ttl_to_use, nsec_rdata));
        }
    }

    // Additional records container (owner_bytes, type, class, ttl, rdata)
    let mut additional: Vec<(Vec<u8>, u16, u16, u32, Vec<u8>)> = Vec::new();

    // Parse EDNS OPT from request additional section to detect DO bit and preserve OPT in response
    let qstart = 12usize;
    let mut opt_present = false;
    let mut _opt_udp_size: u16 = 512;
    let mut opt_z: u16 = 0;
    // ARCOUNT is at bytes 10..12
    if request.len() >= 12 {
        let arcount = u16::from_be_bytes([request[10], request[11]]);
        let mut pos = qstart + q.qlength;
        for _ in 0..arcount {
            if pos >= request.len() { break; }
            // decode owner name
            match decode_name(request, pos) {
                Ok((_name, newpos)) => {
                    pos = newpos;
                    if pos + 10 > request.len() { break; }
                    let rtype = u16::from_be_bytes([request[pos], request[pos+1]]);
                    if rtype == 41 {
                        // OPT RR
                        opt_present = true;
                        _opt_udp_size = u16::from_be_bytes([request[pos+2], request[pos+3]]);
                        // ext rcode (1), version (1), z (2)
                        opt_z = u16::from_be_bytes([request[pos+6], request[pos+7]]);
                        // rdlen
                        let rdlen = u16::from_be_bytes([request[pos+8], request[pos+9]]) as usize;
                        pos += 10 + rdlen;
                    } else {
                        // skip class(2) ttl(4) rdlen(2) rdata(rdlen)
                        if pos + 10 > request.len() { break; }
                        let rdlen = u16::from_be_bytes([request[pos+8], request[pos+9]]) as usize;
                        pos += 10 + rdlen;
                    }
                }
                Err(_) => { break; }
            }
        }
    }

    let do_bit_set = opt_present && (opt_z & 0x8000) != 0;

    println!("[dns] build_response_local: DO={} dnssec_enabled={} dnssec_key_present={}", do_bit_set, dnssec_enabled, dnssec_key.is_some());

    // If DNSSEC requested and enabled, add RRSIGs for RRsets
    if dnssec_enabled && do_bit_set {
        println!("[dns] DNSSEC block: answers_before={}", answers.len());
        if let Some(key) = dnssec_key {
            // Build RRset groups by type (answers for this owner)
            let mut groups: HashMap<u16, Vec<(Vec<u8>, u32, u16)>> = HashMap::new();
            for (_rec, rtype, rclass, ttl, rdata) in &answers {
                groups.entry(*rtype).or_default().push((rdata.clone(), *ttl, *rclass));
            }

            // For each group, build canonical RR wires, sort them, build RRSIG header and sign
            for (rtype, rrlist) in groups.iter() {
                // Build canonical RR wires
                let mut rr_wires: Vec<Vec<u8>> = Vec::new();
                for (rdata, ttl, rclass) in rrlist {
                    let wire = build_canonical_rr_wire(domain_norm, *rtype, *rclass, *ttl, rdata);
                    rr_wires.push(wire);
                }
                // sort canonical wire octetwise
                rr_wires.sort();

                // Prepare RRSIG header (type covered, algorithm, labels, original ttl, sig expiration/inception, key tag, signer name)
                let type_covered = *rtype;
                let algorithm = key.algorithm;
                let labels = domain_norm.split('.').filter(|s| !s.is_empty()).count() as u8;
                let original_ttl = if let Some(first) = rrlist.get(0) { first.1 } else { 3600u32 };
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
                let sig_inception = now;
                let sig_expiration = now + 3600; // 1 hour validity - you can adjust
                let key_tag = key.key_tag;
                let signer_name_wire = encode_name(&domain_norm.to_lowercase());

                // Build RRSIG RDATA header (without signature)
                let mut rrsig_hdr: Vec<u8> = Vec::new();
                rrsig_hdr.extend_from_slice(&type_covered.to_be_bytes());
                rrsig_hdr.push(algorithm);
                rrsig_hdr.push(labels);
                rrsig_hdr.extend_from_slice(&original_ttl.to_be_bytes());
                rrsig_hdr.extend_from_slice(&sig_expiration.to_be_bytes());
                rrsig_hdr.extend_from_slice(&sig_inception.to_be_bytes());
                rrsig_hdr.extend_from_slice(&key_tag.to_be_bytes());
                rrsig_hdr.extend_from_slice(&signer_name_wire);

                // Sign using the key's algorithm
                let sig = sign_rrset_bytes(&key.private_key_pem, &rrsig_hdr, &rr_wires, key.algorithm)?;
                // Build RRSIG record rdata
                let mut rrsig_rdata = Vec::new();
                rrsig_rdata.extend_from_slice(&type_covered.to_be_bytes());
                rrsig_rdata.push(algorithm);
                rrsig_rdata.push(labels);
                rrsig_rdata.extend_from_slice(&original_ttl.to_be_bytes());
                rrsig_rdata.extend_from_slice(&sig_expiration.to_be_bytes());
                rrsig_rdata.extend_from_slice(&sig_inception.to_be_bytes());
                rrsig_rdata.extend_from_slice(&key_tag.to_be_bytes());
                rrsig_rdata.extend_from_slice(&signer_name_wire);
                // signature length will be appended as raw bytes (not length-prefix here)
                rrsig_rdata.extend_from_slice(&sig);

                // Attach RRSIG to answers if the rrset is being returned in answers
                if *rtype == q.qtype || q.qtype == 255 {
                    // push as answer-like tuple (owner pointer will be used when writing)
                    let rrsig_rec = DnsRecord { kind: RecordKind::RRSIG { type_covered: type_covered, algorithm, labels, original_ttl, signature_expiration: sig_expiration, signature_inception: sig_inception, key_tag, signer_name: domain_norm.to_string(), signature: sig.clone() }, ttl: original_ttl, class: 1 };
                    answers.push((rrsig_rec, 46u16, 1u16, original_ttl, rrsig_rdata));
                } else {
                    // Otherwise place in additional
                    additional.push((encode_name(domain_norm), 46, 1, original_ttl, rrsig_rdata));
                }
            }

            // Ensure DNSKEY RRset (if present in zone) is signed and optionally include DNSKEY in additional
            if let Some(recs) = dns_records.get(domain_norm) {
                let mut dnskey_rrs: Vec<(Vec<u8>, u32, u16)> = Vec::new();
                for rec in recs {
                    if let RecordKind::DNSKEY { .. } = &rec.kind {
                        let rdata = encode_rdata_for_record(rec)?;
                        dnskey_rrs.push((rdata, rec.ttl, rec.class));
                    }
                }
                if !dnskey_rrs.is_empty() {
                    // build canonical wires and sign
                    let mut rr_wires: Vec<Vec<u8>> = Vec::new();
                    for (rdata, ttl, class) in &dnskey_rrs {
                        rr_wires.push(build_canonical_rr_wire(domain_norm, 48u16, *class, *ttl, rdata));
                    }
                    rr_wires.sort();
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
                    let sig_inception = now;
                    let sig_expiration = now + 3600;
                    let key_tag = key.key_tag;
                    let signer_name_wire = encode_name(&domain_norm.to_lowercase());

                    let mut rrsig_hdr: Vec<u8> = Vec::new();
                    rrsig_hdr.extend_from_slice(&48u16.to_be_bytes());
                    rrsig_hdr.push(key.algorithm);
                    rrsig_hdr.push(domain_norm.split('.').filter(|s| !s.is_empty()).count() as u8);
                    rrsig_hdr.extend_from_slice(&dnskey_rrs[0].1.to_be_bytes());
                    rrsig_hdr.extend_from_slice(&sig_expiration.to_be_bytes());
                    rrsig_hdr.extend_from_slice(&sig_inception.to_be_bytes());
                    rrsig_hdr.extend_from_slice(&key_tag.to_be_bytes());
                    rrsig_hdr.extend_from_slice(&signer_name_wire);

                    let sig = sign_rrset_bytes(&key.private_key_pem, &rrsig_hdr, &rr_wires, key.algorithm)?;

                    // Build RRSIG rdata and push to additional
                    let mut rrsig_rdata = Vec::new();
                    rrsig_rdata.extend_from_slice(&48u16.to_be_bytes());
                    rrsig_rdata.push(key.algorithm);
                    rrsig_rdata.push(domain_norm.split('.').filter(|s| !s.is_empty()).count() as u8);
                    rrsig_rdata.extend_from_slice(&dnskey_rrs[0].1.to_be_bytes());
                    rrsig_rdata.extend_from_slice(&sig_expiration.to_be_bytes());
                    rrsig_rdata.extend_from_slice(&sig_inception.to_be_bytes());
                    rrsig_rdata.extend_from_slice(&key_tag.to_be_bytes());
                    rrsig_rdata.extend_from_slice(&signer_name_wire);
                    rrsig_rdata.extend_from_slice(&sig);
                    additional.push((encode_name(domain_norm), 46, 1, dnskey_rrs[0].1, rrsig_rdata));

                    // Optionally include DS records when requested (qtype==DS or ANY)
                    if q.qtype == 43 || q.qtype == 255 {
                        for (rdata, _ttl, class) in dnskey_rrs.iter() {
                            // compute key_tag and digest
                            let key_tag_local = key.key_tag;
                            let digest = dnssec::compute_ds_sha256(rdata);
                            let mut ds_rdata = Vec::new();
                            ds_rdata.extend_from_slice(&key_tag_local.to_be_bytes());
                            ds_rdata.push(key.algorithm);
                            ds_rdata.push(2u8); // SHA-256 digest type
                            ds_rdata.extend_from_slice(&digest);
                            additional.push((encode_name(domain_norm), 43, *class, dnskey_rrs[0].1, ds_rdata));
                        }
                    }
                }
                println!("[dns] DNSSEC block end: answers_after={} additional_after={}", answers.len(), additional.len());
            }
        }
    }

    // now write counts
    let ancount = answers.len() as u16;
    let nscount = authority.len() as u16;
    let arcount = additional.len() as u16;
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&nscount.to_be_bytes());
    out.extend_from_slice(&arcount.to_be_bytes());

    // copy question
    let qstart = 12usize;
    let qend = qstart + q.qlength;
    if qend > request.len() { return Err("question length mismatch".into()); }
    out.extend_from_slice(&request[qstart .. qend]);

    // write answers
    for (_rec, rtype, rclass, ttl, rdata) in &answers {
        // owner pointer to 0xC00C
        out.push(0xC0); out.push(0x0C);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&rclass.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }

    // write authority
    for (rtype, rclass, ttl, rdata) in &authority {
        out.push(0xC0); out.push(0x0C);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&rclass.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }

    // write additional (owner raw, not pointer)
    for (owner_bytes, atype, aclass, attl, ardata) in &additional {
        out.extend_from_slice(owner_bytes);
        out.extend_from_slice(&atype.to_be_bytes());
        out.extend_from_slice(&aclass.to_be_bytes());
        out.extend_from_slice(&attl.to_be_bytes());
        out.extend_from_slice(&(ardata.len() as u16).to_be_bytes());
        out.extend_from_slice(&ardata);
    }

    // set RCODE if empty answer
    if ancount == 0 && nscount == 0 {
        let rcode = if dns_records.get(domain_norm).is_none() { 3u8 } else { 0u8 };
        out[3] = (out[3] & 0xF0) | (rcode & 0x0F);
    }

    Ok(out)
}

//
// Helper to produce DNSKEY public-key raw bytes (the RFC3110 exponent+modulus formatting).
// The DnssecKey.public_key used in the rest of the code is expected to contain exactly this byte sequence.
// Here we provide a function to reconstruct the sequence from a real RsaPublicKey.
pub fn dnskey_rdata_from_public_bytes(pubkey_bytes: &[u8]) -> Vec<u8> {
    // Return clone — kept for compatibility but may be unused in current flow.
    pubkey_bytes.to_vec()
}

//
// Load RSA private key path and build DnssecKey
//
pub fn load_dnssec_key(key_path: &str, is_ksk: bool) -> Result<DnssecKey, Box<dyn Error>> {
    let pem_bytes = fs::read(key_path)?;

    // The key file may be PEM text, BIND-style private-key-format (OpenSSL/BIND produced),
    // or binary DER (PKCS#8 or PKCS#1). Try to detect BIND private format first, then PEM/DER.
    let (maybe_pem_string, priv_key_obj, detected_algorithm, bind_seed): (Option<String>, Option<RsaPrivateKey>, Option<u8>, Option<Vec<u8>>) =
        match std::str::from_utf8(&pem_bytes) {
            Ok(s) => {
                if s.contains("Private-key-format:") {
                    // parse the simple header-like format
                    let mut alg: Option<u8> = None;
                    let mut priv_b64: Option<String> = None;
                    for line in s.lines() {
                        let l = line.trim();
                        if l.starts_with("Algorithm:") {
                            if let Some(idx) = l.find(':') {
                                let val = l[idx+1..].trim();
                                if let Ok(n) = val.split_whitespace().next().unwrap_or("").parse::<u8>() {
                                    alg = Some(n);
                                }
                            }
                        }
                        if l.starts_with("PrivateKey:") {
                            if let Some(idx) = l.find(':') {
                                let val = l[idx+1..].trim();
                                priv_b64 = Some(val.to_string());
                            }
                        }
                    }
                    if let (Some(a), Some(b64)) = (alg, priv_b64) {
                        let seed = general_purpose::STANDARD.decode(b64.trim())?;
                        if a == 15 {
                            // For BIND-format Ed25519, keep raw seed bytes so we can derive public key and sign directly.
                            (None, None, Some(15u8), Some(seed))
                        } else {
                            return Err("Unsupported BIND private-key algorithm (only Ed25519 supported via this path)".into());
                        }
                    } else {
                        return Err("Malformed BIND private-key-format file".into());
                    }
                } else {
                    // treat as PEM text
                    (Some(s.to_string()), None, None, None)
                }
            }
            Err(_) => {
                // binary DER path
                if let Ok(k) = RsaPrivateKey::from_pkcs8_der(&pem_bytes) {
                    let der = k.to_pkcs8_der()?;
                    let pem = pem::Pem { tag: "PRIVATE KEY".to_string(), contents: der.as_bytes().to_vec() };
                    (Some(pem::encode(&pem)), Some(k), None, None)
                } else if let Ok(k) = RsaPrivateKey::from_pkcs1_der(&pem_bytes) {
                    let der = k.to_pkcs8_der()?;
                    let pem = pem::Pem { tag: "PRIVATE KEY".to_string(), contents: der.as_bytes().to_vec() };
                    (Some(pem::encode(&pem)), Some(k), None, None)
                } else {
                    return Err("Unsupported key format: not PEM, BIND private-key-format, PKCS#8 DER or PKCS#1 DER".into());
                }
            }
        };

    // Now obtain public key bytes and decide algorithm. For RSA use exponent/modulus formatting,
    // for Ed25519 use raw public key bytes derived from seed or SPKI.
    let mut pk_bytes: Vec<u8> = Vec::new();
    let flags: u16 = if is_ksk { 257u16 } else { 256u16 };
    let protocol: u8 = 3;
    let algorithm: u8;

    if let Some(k) = priv_key_obj {
        let pubk = rsa::RsaPublicKey::from(&k);
        let pub_der = pubk.to_public_key_der()?;
        let pub_pem = pem::Pem { tag: "PUBLIC KEY".to_string(), contents: pub_der.as_bytes().to_vec() };
        let parsed = pem::parse(pem::encode(&pub_pem).as_str())?;
        let pub_key = RsaPublicKey::from_public_key_der(&parsed.contents)?;
        let e_bytes = pub_key.e().to_bytes_be();
        let n = pub_key.n().to_bytes_be();
        if e_bytes.len() < 256 {
            pk_bytes.push(e_bytes.len() as u8);
        } else {
            pk_bytes.push(0);
            pk_bytes.extend_from_slice(&(e_bytes.len() as u16).to_be_bytes());
        }
        pk_bytes.extend_from_slice(&e_bytes);
        pk_bytes.extend_from_slice(&n);
        algorithm = 8;
    } else if detected_algorithm == Some(15u8) {
        // Ed25519 from BIND-format: derive public key from seed (bind_seed present)
        if let Some(seed) = &bind_seed {
            // derive public key using ed25519-dalek from seed reference
            let secret = SecretKey::from_bytes(seed).map_err(|e| format!("ed25519 secret parse error: {:?}", e))?;
            let public = PublicKey::from(&secret);
            pk_bytes = public.to_bytes().to_vec();
            algorithm = 15;
            // ensure private_pem_bytes will hold raw seed bytes later (clone below)
        } else {
            // fallback: try to extract SPKI from PEM
            let pub_pem = dnssec::extract_public_key(&maybe_pem_string.clone().unwrap_or_default())?;
            let parsed = pem::parse(pub_pem.as_str())?;
            let blocks = from_der(&parsed.contents)?;
            let mut found = None;
            for b in blocks {
                if let ASN1Block::Sequence(_, inner) = b {
                    for ib in inner {
                        if let ASN1Block::BitString(_, _, bits) = ib {
                            found = Some(bits);
                            break;
                        }
                    }
                }
                if found.is_some() { break; }
            }
            if let Some(pubbytes) = found {
                pk_bytes = pubbytes;
                algorithm = 15;
            } else {
                return Err("Unable to extract Ed25519 public key bytes from SPKI".into());
            }
        }
    } else {
        // Fallback: ask dnssec to extract public and try RSA or Ed25519 SPKI parsing
        let pub_pem = dnssec::extract_public_key(&maybe_pem_string.clone().unwrap_or_default())?;
        let parsed = pem::parse(pub_pem.as_str())?;
        if let Ok(pub_key) = RsaPublicKey::from_public_key_der(&parsed.contents) {
            let e_bytes = pub_key.e().to_bytes_be();
            let n = pub_key.n().to_bytes_be();
            if e_bytes.len() < 256 {
                pk_bytes.push(e_bytes.len() as u8);
            } else {
                pk_bytes.push(0);
                pk_bytes.extend_from_slice(&(e_bytes.len() as u16).to_be_bytes());
            }
            pk_bytes.extend_from_slice(&e_bytes);
            pk_bytes.extend_from_slice(&n);
            algorithm = 8;
        } else {
            let blocks = from_der(&parsed.contents)?;
            let mut found = None;
            for b in blocks {
                if let ASN1Block::Sequence(_, inner) = b {
                    for ib in inner {
                        if let ASN1Block::BitString(_, _, bits) = ib {
                            found = Some(bits);
                            break;
                        }
                    }
                }
                if found.is_some() { break; }
            }
            if let Some(pubbytes) = found {
                pk_bytes = pubbytes;
                algorithm = 15;
            } else {
                return Err("Unsupported public key type or failed to extract public key bytes".into());
            }
        }
    }

    // build DNSKEY RDATA and key tag
    let mut dnskey_rdata = Vec::new();
    dnskey_rdata.extend_from_slice(&flags.to_be_bytes());
    dnskey_rdata.push(protocol);
    dnskey_rdata.push(algorithm);
    dnskey_rdata.extend_from_slice(&pk_bytes);

    let key_tag = dnssec::compute_key_tag(&dnskey_rdata);

    // Determine private key bytes to store: prefer raw bind seed if present, else PEM string bytes.
    let private_bytes: Vec<u8> = match &bind_seed {
        Some(v) => v.clone(),
        None => maybe_pem_string.clone().map(|s| s.into_bytes()).unwrap_or_default(),
    };

    Ok(DnssecKey {
        flags,
        protocol,
        algorithm,
        public_key: pk_bytes,
        private_key_pem: private_bytes,
        key_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_sign_dnskey_rrset() {
        // generate a private key PEM using dnssec helper
        let pem = dnssec::generate_rsa_private_pem(2048).unwrap();
        // create a fake DNSKEY RDATA using public key extracted
        let pub_pem = dnssec::extract_public_key(&pem).unwrap();
        let parsed = pem::parse(pub_pem.as_str()).unwrap();
        let pub_key = RsaPublicKey::from_public_key_der(&parsed.contents).unwrap();
        let e = pub_key.e().to_bytes_be();
        let n = pub_key.n().to_bytes_be();
        let mut pk = Vec::new();
        if e.len() < 256 { pk.push(e.len() as u8); } else { pk.push(0); pk.extend_from_slice(&(e.len() as u16).to_be_bytes()); }
        pk.extend_from_slice(&e); pk.extend_from_slice(&n);
        let mut dnskey_rdata = Vec::new();
        dnskey_rdata.extend_from_slice(&256u16.to_be_bytes());
        dnskey_rdata.push(3); dnskey_rdata.push(8);
        dnskey_rdata.extend_from_slice(&pk);

        // Build canonical wire for a DNSKEY RR
        let wire = build_canonical_rr_wire("example.com", 48u16, 1u16, 3600u32, &dnskey_rdata);
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&48u16.to_be_bytes());
        hdr.push(8);
        hdr.push(2);
        hdr.extend_from_slice(&3600u32.to_be_bytes());
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&0u32.to_be_bytes());
        hdr.extend_from_slice(&0u16.to_be_bytes());
        hdr.extend_from_slice(&encode_name("example.com"));
        let sig = sign_rrset_bytes(pem.as_bytes(), &hdr[..], &[wire], 8).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn basic_encode_and_keytag() {
        // generate a test rsa key and check dnskey rdata/keytag functions
        let mut rng = OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pubk = RsaPublicKey::from(&key);
        let e = pubk.e().to_bytes_be();
        let n = pubk.n().to_bytes_be();
        let mut pk = Vec::new();
        if e.len() < 256 {
            pk.push(e.len() as u8);
        } else {
            pk.push(0);
            pk.extend_from_slice(&(e.len() as u16).to_be_bytes());
        }

        pk.extend_from_slice(&e);
        pk.extend_from_slice(&n);

        let mut dnskey_rdata = Vec::new();
        dnskey_rdata.extend_from_slice(&256u16.to_be_bytes());
        dnskey_rdata.push(3);
        dnskey_rdata.push(8);
        dnskey_rdata.extend_from_slice(&pk);

        let tag = dnssec::compute_key_tag(&dnskey_rdata);
        assert!(tag > 0);
    }
}
