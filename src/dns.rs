use std::collections::HashSet;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;
use crate::config::{Expire, ForwarderEntry};
use std::fs;
use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

use rsa::pkcs1::EncodeRsaPublicKey; 
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};


use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding}; // Hinzufügen

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
//use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
// für Signatur traits


// PSS signing key
use rsa::pss::BlindedSigningKey;

// RNG
use rand::rngs::OsRng;
use rand; 



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
    pub private_key: RsaPrivateKey,
    pub key_tag: u16,
}

pub fn decode_name(data: &[u8], mut pos: usize) -> Result<(String, usize), Box<dyn Error>> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut original_pos = pos;
    let mut visited: HashSet<usize> = HashSet::new();

    loop {
        if pos >= data.len() {
            return Err("decode_name: außerhalb des Puffers".into());
        }
        let len = data[pos];
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() { return Err("decode_name: ungültiger pointer".into()); }
            let pointer = (((len & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            if visited.contains(&pointer) { return Err("decode_name: pointerloop".into()); }
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
        if pos + l > data.len() { return Err("decode_name: label über Puffer".into()); }
        let slice = &data[pos .. pos + l];
        let label = str::from_utf8(slice)?.to_string();
        labels.push(label);
        pos += l;
    }

    let name = labels.join(".");
    Ok((name, original_pos))
}

pub fn encode_name(name: &str) -> Vec<u8> {
    if name.is_empty() {
        return vec![0];
    }
    let mut out: Vec<u8> = Vec::new();
    for label in name.split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len();
        out.push(len as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out
}

pub fn encode_rdata_for_record(rec: &DnsRecord) -> Result<Vec<u8>, Box<dyn Error>> {
    match &rec.kind {
        RecordKind::A(ipv4) => {
            let v: Ipv4Addr = ipv4.parse()?;
            Ok(v.octets().to_vec())
        }
        RecordKind::AAAA(ipv6) => {
            let v: Ipv6Addr = ipv6.parse()?;
            Ok(v.octets().to_vec())
        }
        RecordKind::CNAME(target) | RecordKind::NS(target) | RecordKind::PTR(target) => {
            Ok(encode_name(target))
        }
        RecordKind::MX { pref, exchange } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&pref.to_be_bytes());
            buf.extend_from_slice(&encode_name(exchange));
            Ok(buf)
        }
        RecordKind::TXT(text) => {
            let bytes = text.as_bytes();
            if bytes.len() > 255 {
                return Err("TXT string zu lang (max 255)".into());
            }
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
            buf.extend_from_slice(&encode_name(target));
            Ok(buf)
        }
        RecordKind::NAPTR { order, preference, flags, services, regexp, replacement } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&order.to_be_bytes());
            buf.extend_from_slice(&preference.to_be_bytes());
            let flags_b = flags.as_bytes();
            buf.push(flags_b.len() as u8);
            buf.extend_from_slice(flags_b);
            let services_b = services.as_bytes();
            buf.push(services_b.len() as u8);
            buf.extend_from_slice(services_b);
            let regexp_b = regexp.as_bytes();
            buf.push(regexp_b.len() as u8);
            buf.extend_from_slice(regexp_b);
            buf.extend_from_slice(&encode_name(replacement));
            Ok(buf)
        }
        RecordKind::CAA { flags, tag, value } => {
            let mut buf = Vec::new();
            buf.push(*flags);
            let tag_b = tag.as_bytes();
            buf.push(tag_b.len() as u8);
            buf.extend_from_slice(tag_b);
            let value_b = value.as_bytes();
            buf.extend_from_slice(value_b);
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
        RecordKind::DNAME(target) => {
            Ok(encode_name(target))
        }
        RecordKind::HINFO { cpu, os } => {
            let cpu_b = cpu.as_bytes();
            let os_b = os.as_bytes();
            if cpu_b.len() > 255 || os_b.len() > 255 { return Err("HINFO token zu lang".into()); }
            let mut buf = Vec::new();
            buf.push(cpu_b.len() as u8);
            buf.extend_from_slice(cpu_b);
            buf.push(os_b.len() as u8);
            buf.extend_from_slice(os_b);
            Ok(buf)
        }
        RecordKind::RP { mbox, txt } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&encode_name(mbox));
            buf.extend_from_slice(&encode_name(txt));
            Ok(buf)
        }
        RecordKind::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
            let mut buf = Vec::new();
            buf.extend_from_slice(&encode_name(mname));
            buf.extend_from_slice(&encode_name(rname));
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
            buf.extend_from_slice(&encode_name(signer_name));
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
            let mut buf = Vec::new();
            buf.extend_from_slice(&encode_name(next_domain_name));
            
            let mut window_blocks: Vec<u8> = Vec::new();
            let mut current_window = 0;
            let mut window_data: Vec<u8> = Vec::new();
            
            for &rtype in type_bit_maps {
                let window = (rtype >> 8) as u8;
                if window != current_window {
                    if !window_data.is_empty() {
                        window_blocks.push(current_window);
                        window_blocks.push(window_data.len() as u8);
                        window_blocks.extend(&window_data);
                    }
                    current_window = window;
                    window_data = vec![0; 32];
                }
                
                let bit_position = (rtype & 0xFF) as usize;
                let byte_index = bit_position / 8;
                let bit_index = 7 - (bit_position % 8);
                if byte_index < window_data.len() {
                    window_data[byte_index] |= 1 << bit_index;
                }
            }
            
            if !window_data.is_empty() {
                window_blocks.push(current_window);
                window_blocks.push(window_data.len() as u8);
                window_blocks.extend(&window_data);
            }
            
            buf.extend_from_slice(&window_blocks);
            Ok(buf)
        }
        RecordKind::NSEC3 { hash_algorithm, flags, iterations, salt, 
                           next_hashed_owner_name, type_bit_maps } => {
            let mut buf = Vec::new();
            buf.push(*hash_algorithm);
            buf.push(*flags);
            buf.extend_from_slice(&iterations.to_be_bytes());
            buf.push(salt.len() as u8);
            buf.extend_from_slice(salt);
            buf.push(next_hashed_owner_name.len() as u8);
            buf.extend_from_slice(next_hashed_owner_name);
            
            let mut window_blocks: Vec<u8> = Vec::new();
            let mut current_window = 0;
            let mut window_data: Vec<u8> = Vec::new();
            
            for &rtype in type_bit_maps {
                let window = (rtype >> 8) as u8;
                if window != current_window {
                    if !window_data.is_empty() {
                        window_blocks.push(current_window);
                        window_blocks.push(window_data.len() as u8);
                        window_blocks.extend(&window_data);
                    }
                    current_window = window;
                    window_data = vec![0; 32];
                }
                
                let bit_position = (rtype & 0xFF) as usize;
                let byte_index = bit_position / 8;
                let bit_index = 7 - (bit_position % 8);
                if byte_index < window_data.len() {
                    window_data[byte_index] |= 1 << bit_index;
                }
            }
            
            if !window_data.is_empty() {
                window_blocks.push(current_window);
                window_blocks.push(window_data.len() as u8);
                window_blocks.extend(&window_data);
            }
            
            buf.extend_from_slice(&window_blocks);
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
        RecordKind::DNAME(_) => 39,
        RecordKind::SSHFP { .. } => 44,
        RecordKind::SRV { .. } => 33,
        RecordKind::NAPTR { .. } => 35,
        RecordKind::TLSA { .. } => 52,
        RecordKind::CAA { .. } => 257,
        RecordKind::DNSKEY { .. } => 48,
        RecordKind::RRSIG { .. } => 46,
        RecordKind::DS { .. } => 43,
        RecordKind::NSEC { .. } => 47,
        RecordKind::NSEC3 { .. } => 50,
    }
}

pub fn parse_question(data: &[u8]) -> Result<Question, Box<dyn Error>> {
    let mut pos: usize = 12;
    let mut domain_labels: Vec<String> = Vec::new();
    let mut visited_offsets: HashSet<usize> = HashSet::new();
    let mut jumped = false;
    let mut original_pos = pos;

    loop {
        if pos >= data.len() {
            return Err("Ungültige DNS-Anfrage: außerhalb des Puffers beim Lesen der Labels.".into());
        }
        let len = data[pos];

        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return Err("Ungültiger Pointer in DNS-Anfrage.".into());
            }
            let pointer = (((len & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            if visited_offsets.contains(&pointer) {
                return Err("Pointerloop entdeckt.".into());
            }
            visited_offsets.insert(pointer);

            if !jumped {
                original_pos = pos + 2;
                jumped = true;
            }

            pos = pointer;
            continue;
        }

        if len == 0 {
            if !jumped {
                original_pos = pos + 1;
            }
            break;
        }

        let len_usize = len as usize;
        if pos + 1 + len_usize > data.len() {
            return Err("Label geht über Pufferende.".into());
        }
        let slice = &data[pos + 1 .. pos + 1 + len_usize];
        let label = str::from_utf8(slice)?.to_string();
        domain_labels.push(label);
        pos += 1 + len_usize;
    }

    if original_pos + 4 > data.len() {
        return Err("Ungültige DNS-Anfrage: Fragefeld zu kurz für Type/Class.".into());
    }

    let qtype = u16::from_be_bytes([data[original_pos], data[original_pos + 1]]);
    let qclass = u16::from_be_bytes([data[original_pos + 2], data[original_pos + 3]]);

    let qname = domain_labels.join(".");

    let qlength = (original_pos + 4) - 12;

    Ok(Question {
        qname,
        qtype,
        qclass,
        qlength,
    })
}

pub fn build_response_local(
    request: &[u8], 
    q: &Question, 
    domain_norm: &str, 
    dns_records: &std::collections::HashMap<String, Vec<DnsRecord>>,
    dnssec_enabled: bool,
    dnssec_key: &Option<DnssecKey>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out: Vec<u8> = Vec::new();

    out.push(request[0]); out.push(request[1]);

    let mut flags1 = request[2];
    flags1 |= 0x80;
    flags1 |= 0x04;
    
    let do_bit_set = request.len() > 12 && (request[3] & 0x80) != 0;
    
    if dnssec_enabled && do_bit_set {
        flags1 |= 0x02;
    }
    
    out.push(flags1);

    let mut flags2 = request[3];
    flags2 &= !(0x80);
    flags2 &= 0x0F;
    out.push(flags2);

    out.push(request[4]); out.push(request[5]);

    let records_opt = dns_records.get(domain_norm);

    let mut answers: Vec<(DnsRecord, u16, u16, u32, Vec<u8>)> = Vec::new();

    if let Some(records) = records_opt {
        if q.qtype == 255 {
            for rec in records {
                let rtype = record_type_number(&rec.kind);

                let rdata = encode_rdata_for_record(rec)?;
                answers.push((rec.clone(), rtype, rec.class, rec.ttl, rdata));
            }
        } else {
            for rec in records {
                let rtype = record_type_number(&rec.kind);

                if rtype == q.qtype {
                    let rdata = encode_rdata_for_record(rec)?;
                    answers.push((rec.clone(), rtype, rec.class, rec.ttl, rdata));
                }
            }
        }
    }

    let mut authority: Vec<(u16, u16, u32, Vec<u8>)> = Vec::new();
    let mut additional: Vec<(Vec<u8>, u16, u16, u32, Vec<u8>)> = Vec::new();

    if answers.is_empty() {
        if let Some(records) = records_opt {
            for rec in records {
                if let RecordKind::SOA { .. } = &rec.kind {
                    let rtype = 6u16;
                    let rdata = encode_rdata_for_record(rec)?;
                    authority.push((rtype, rec.class, rec.ttl, rdata));
                    break;
                }
            }
        }
    }

    if dnssec_enabled && do_bit_set {
        if let Some(key) = dnssec_key {
            let dnskey_rec = DnsRecord {
                kind: RecordKind::DNSKEY {
                    flags: key.flags,
                    protocol: key.protocol,
                    algorithm: key.algorithm,
                    public_key: key.public_key.clone(),
                },
                ttl: 3600,
                class: 1,
            };
            let rdata = encode_rdata_for_record(&dnskey_rec)?;
            additional.push((encode_name(domain_norm), 48, 1, 3600, rdata));

            for (rec, rtype, rclass, ttl, rdata) in &answers {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
                let signature = sign_rdata(&key.private_key, &rdata, *rtype, *rclass, *ttl, domain_norm, now)?;
                
                let rrsig_rec = DnsRecord {
                    kind: RecordKind::RRSIG {
                        type_covered: *rtype,
                        algorithm: key.algorithm,
                        labels: domain_norm.split('.').count() as u8,
                        original_ttl: *ttl,
                        signature_expiration: now + 3600,
                        signature_inception: now,
                        key_tag: key.key_tag,
                        signer_name: domain_norm.to_string(),
                        signature,
                    },
                    ttl: *ttl,
                    class: *rclass,
                };
                
                let rrsig_rdata = encode_rdata_for_record(&rrsig_rec)?;
                additional.push((encode_name(domain_norm), 46, *rclass, *ttl, rrsig_rdata));
            }
        }
    }

    let ancount = answers.len() as u16;
    let nscount = authority.len() as u16;
    let arcount = additional.len() as u16;

    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&nscount.to_be_bytes());
    out.extend_from_slice(&arcount.to_be_bytes());

    let question_length = q.qlength;
    let qstart = 12;
    let qend = qstart + question_length;
    if qend > request.len() {
        return Err("Ungültige Anfrage: Frage-Länge überschreitet Request-Länge.".into());
    }
    out.extend_from_slice(&request[qstart .. qend]);

    for (_rec, rtype, rclass, ttl, rdata) in &answers {
        out.push(0xC0); out.push(0x0C);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&rclass.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        let rdlen = (rdata.len() as u16).to_be_bytes();
        out.extend_from_slice(&rdlen);
        out.extend_from_slice(&rdata);
    }

    for (rtype, rclass, ttl, rdata) in &authority {
        out.push(0xC0); out.push(0x0C);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&rclass.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        let rdlen = (rdata.len() as u16).to_be_bytes();
        out.extend_from_slice(&rdlen);
        out.extend_from_slice(&rdata);
    }

    for (owner_bytes, atype, aclass, attl, ardata) in &additional {
        out.extend_from_slice(owner_bytes);
        out.extend_from_slice(&atype.to_be_bytes());
        out.extend_from_slice(&aclass.to_be_bytes());
        out.extend_from_slice(&attl.to_be_bytes());
        let rdlen = (ardata.len() as u16).to_be_bytes();
        out.extend_from_slice(&rdlen);
        out.extend_from_slice(&ardata);
    }

    if ancount == 0 && nscount == 0 && arcount == 0 {
        let rcode: u8;
        if records_opt.is_none() {
            rcode = 3;
        } else {
            rcode = 0;
        }
        if out.len() > 3 {
            out[3] = (out[3] & 0xF0) | (rcode & 0x0F);
        }
    }

    Ok(out)
}

pub fn try_forward_to_upstreams(forwarders: &[ForwarderEntry], orig_request: &[u8], q: &Question, original_qname: &str, global_punny_flag: bool, timeout: std::time::Duration) -> Result<(Vec<u8>, String, bool), Box<dyn Error>> {
    use std::net::SocketAddr;

    for f in forwarders {
        let addr_str = match f {
            ForwarderEntry::Simple(s) => s.clone(),
            ForwarderEntry::WithFlag { address, .. } => address.clone(),
        };

        let effective_punny = match f {
            ForwarderEntry::Simple(_) => global_punny_flag,
            ForwarderEntry::WithFlag { punny_weitergabe, .. } => punny_weitergabe.unwrap_or(global_punny_flag),
        };

        let mut forward_qname = original_qname.to_string();
        if effective_punny {
            if crate::punycode_handling::domain_contains_non_ascii(original_qname) {
                match crate::punycode_handling::to_ascii_if_needed(original_qname) {
                    Ok(a) => forward_qname = a,
                    Err(e) => {
                        eprintln!("Warnung: konnte qname zu ASCII konvertieren (forwarder {}): {}", addr_str, e);
                    }
                }
            }
        } else {
            let mut has_puny = false;
            for lbl in original_qname.split('.') {
                if crate::punycode_handling::is_puny_label(lbl) { has_puny = true; break; }
            }
            if has_puny {
                let (u, _info) = idna::domain_to_unicode(original_qname);
                forward_qname = u;
            }
        }

        let forward_req = match build_forward_request(orig_request, q, &forward_qname) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Fehler beim Bauen der Forward-Request für {}: {}", addr_str, e);
                continue;
            }
        };

        let addr: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Forwarder-Adresse '{}' ungültig: {}", addr_str, e);
                continue;
            }
        };

        let bind_addr = match addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        match std::net::UdpSocket::bind(bind_addr) {
            Ok(sock) => {
                if let Err(e) = sock.set_read_timeout(Some(timeout)) {
                    eprintln!("Warnung: set_read_timeout failed: {}", e);
                }

                if let Err(e) = sock.send_to(&forward_req, addr) {
                    eprintln!("Fehler: Senden an Forwarder {} fehlgeschlagen: {}", addr, e);
                    continue;
                }

                let mut buf = [0u8; 4096];
                match sock.recv_from(&mut buf) {
                    Ok((amt, _src)) => {
                        let resp = buf[..amt].to_vec();
                        let converted_to_ascii = forward_qname != original_qname
                            && effective_punny
                            && crate::punycode_handling::domain_contains_non_ascii(original_qname);
                        return Ok((resp, forward_qname, converted_to_ascii));
                    }
                    Err(e) => {
                        eprintln!("Forwarder {} hat nicht geantwortet (timeout/err): {}", addr, e);
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Kann temporären UDP-Socket nicht binden: {}", e);
                continue;
            }
        }
    }

    Err("Alle Forwarder haben fehlgeschlagen".into())
}

fn build_forward_request(orig_request: &[u8], q: &Question, new_qname: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out: Vec<u8> = Vec::new();

    out.push(orig_request[0]);
    out.push(orig_request[1]);

    let rd = orig_request[2] & 0x01;
    let flags1 = rd;
    out.push(flags1);
    out.push(0x00);

    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00,0x00, 0x00,0x00, 0x00,0x00]);

    let name_bytes = encode_name(new_qname);
    out.extend_from_slice(&name_bytes);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());

    Ok(out)
}

pub fn compute_key_tag_rfc4034(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, byte) in rdata.iter().enumerate() {
        ac += if i & 1 == 0 {
            (*byte as u32) << 8
        } else {
            *byte as u32
        };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

pub fn load_dnssec_key(key_path: &str) -> Result<DnssecKey, Box<dyn std::error::Error>> {
    let key_data = fs::read(key_path)?;
    let priv_key = RsaPrivateKey::from_pkcs8_der(&key_data)?;
    let pub_key = RsaPublicKey::from(&priv_key);

    let modulus = pub_key.n().to_bytes_be();
    let exponent = pub_key.e().to_bytes_be();

    let e_len = exponent.len();
    if e_len > 255 {
        return Err("Exponent zu lang".into());
    }

    let mut public_key_bytes = Vec::new();
    public_key_bytes.push(e_len as u8);
    public_key_bytes.extend_from_slice(&exponent);
    public_key_bytes.extend_from_slice(&modulus);

    let mut dnskey_rdata = Vec::new();
    dnskey_rdata.extend_from_slice(&256u16.to_be_bytes());
    dnskey_rdata.push(3);
    dnskey_rdata.push(8);
    dnskey_rdata.extend_from_slice(&public_key_bytes);

    let key_tag = compute_key_tag_rfc4034(&dnskey_rdata);

    Ok(DnssecKey {
        flags: 256,
        protocol: 3,
        algorithm: 8,
        public_key: public_key_bytes,
        private_key: priv_key,
        key_tag,
    })
}

fn sign_rdata(
    private_key: &RsaPrivateKey,
    rdata: &[u8],
    rtype: u16,
    rclass: u16,
    ttl: u32,
    domain: &str,
    now: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(&rtype.to_be_bytes());
    data_to_sign.extend_from_slice(&rclass.to_be_bytes());
    data_to_sign.extend_from_slice(&ttl.to_be_bytes());
    data_to_sign.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    data_to_sign.extend_from_slice(rdata);
    data_to_sign.extend_from_slice(&encode_name(domain));
    
    let mut hasher = Sha256::new();
    hasher.update(&data_to_sign);
    let hash = hasher.finalize();
    
    // Verwenden Sie OsRng statt thread_rng
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key.clone());
    let mut rng = rand::rngs::OsRng;
    let signature = signing_key.sign_with_rng(&mut rng, &hash);
    Ok(signature.to_bytes().to_vec())
}

pub fn validate_dnssec_response(response: &[u8]) -> Result<bool, Box<dyn Error>> {
    Ok(true)
}