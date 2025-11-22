// src/main.rs

mod config;
mod dns;
mod record_handling;
mod punycode_handling;
mod dnssec;

use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use dns::{parse_question, build_response_local};
use record_handling::{load_zones_config, load_ptrs_config, build_dns_records_from_zones, add_ptr_record};
use chrono::Utc;

fn main() -> Result<(), Box<dyn Error>> {
    let zones_list_path = "zones.json";
    let start_time = Utc::now();
    let (zones_file, loaded_zones) = match load_zones_config(zones_list_path, start_time) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Fehler beim Laden von {}: {}", zones_list_path, e);
            return Err(e);
        }
    };

    let forwarders = zones_file.forwarders.unwrap_or_default();
    let punny_flag = zones_file.punny_weitergabe.unwrap_or(true);
    let global_dnssec_enabled = zones_file.dnssec_enabled.unwrap_or(false);
    let global_zsk_file = zones_file.dnssec_zsk_file;
    let global_ksk_file = zones_file.dnssec_ksk_file;

    let mut dns_records = match build_dns_records_from_zones(loaded_zones) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Fehler beim Erzeugen der DNS-Records: {}", e);
            return Err(e);
        }
    };

    match load_ptrs_config("ptrs.json") {
        Ok(ptrs) => {
            for p in ptrs {
                let ttl = p.ttl.unwrap_or(3600);
                let class = p.class.unwrap_or(1);
                match add_ptr_record(&mut dns_records, &p.ip, &p.ptr, ttl, class) {
                    Ok(_) => println!("PTR registriert: {} -> {} (ttl={})", p.ip, p.ptr, ttl),
                    Err(e) => eprintln!("Fehler beim Registrieren PTR {} -> {}: {}", p.ip, p.ptr, e),
                }
            }
        }
        Err(e) => eprintln!("Fehler beim Laden von ptrs.json: {}", e),
    }

    // Load per-zone KSK/ZSK. Store a tuple (ksk_opt, zsk_opt) for each zone.
    let mut dnssec_keys: HashMap<String, (Option<dns::DnssecKey>, Option<dns::DnssecKey>)> = HashMap::new();
    for zone_entry in zones_file.zones.iter() {
        let domain = zone_entry.domain.to_lowercase();
        let zone_dnssec_enabled = zone_entry.dnssec_enabled.unwrap_or(global_dnssec_enabled);
        if zone_dnssec_enabled {
            // Determine ZSK and KSK file paths: per-zone override or global, otherwise look into keys/<domain>/{zsk,ksk}.key
            // Prefer explicit private key paths if provided (new JSON fields), then legacy zsk_file, then keys/<zone>/zsk.key
            let mut zsk_file = zone_entry.zsk_private.clone()
                .or(zone_entry.dnssec_zsk_file.clone())
                .or(global_zsk_file.clone())
                .or_else(|| {
                    let p = format!("keys/{}/zsk.key", zone_entry.domain);
                    if Path::new(&p).exists() { Some(p) } else { None }
                });
            // Prefer explicit private KSK path if provided, then legacy ksk_file, then keys/<zone>/ksk.key
            let ksk_file = zone_entry.ksk_private.clone()
                .or(zone_entry.dnssec_ksk_file.clone())
                .or(global_ksk_file.clone())
                .or_else(|| {
                    let p = format!("keys/{}/ksk.key", zone_entry.domain);
                    if Path::new(&p).exists() { Some(p) } else { None }
                });

            // Backwards compatibility: if no ZSK/KSK provided but a legacy `dnssec_key_file` exists in config,
            // try to resolve a private key candidate from the .key (public) filename.
            let resolve_private = |maybe: Option<String>| -> Option<String> {
                let p = match maybe { Some(s) => s, None => return None };
                if !Path::new(&p).exists() {
                    return None;
                }
                // If file already looks like a private key, use it
                if let Ok(s) = fs::read_to_string(&p) {
                    if s.contains("PRIVATE KEY") {
                        return Some(p);
                    }
                }
                // Try common sibling names: .private, .pem, or append .private
                if p.ends_with(".key") {
                    let cand = p.trim_end_matches(".key").to_string() + ".private";
                    if Path::new(&cand).exists() { return Some(cand); }
                    let cand2 = p.trim_end_matches(".key").to_string() + ".pem";
                    if Path::new(&cand2).exists() { return Some(cand2); }
                }
                let cand3 = p.clone() + ".private";
                if Path::new(&cand3).exists() { return Some(cand3); }
                None
            };

            // If no explicit zsk/ksk set, check legacy `dnssec_key_file` at zone or global level
            // If we still don't have a private ZSK, but a public ZSK was provided, try to resolve its private sibling
            if zsk_file.is_none() {
                let legacy = zone_entry.dnssec_key_file.clone().or(zones_file.dnssec_key_file.clone());
                let public_candidate = zone_entry.zsk_public.clone().or(legacy);
                if let Some(pubp) = public_candidate {
                    if let Some(pk) = resolve_private(Some(pubp.clone())) {
                        zsk_file = Some(pk);
                        println!("Using resolved private for zone {} -> {}", domain, zsk_file.as_ref().unwrap());
                    } else {
                        println!("Public-only ZSK configured ({}) for zone {} but no private key candidate discovered.", pubp, domain);
                    }
                }
            }

            let mut ksk_opt = None;
            let mut zsk_opt = None;

            if let Some(kf) = ksk_file {
                match dns::load_dnssec_key(&kf, true) {
                    Ok(k) => ksk_opt = Some(k),
                    Err(e) => eprintln!("Fehler beim Laden KSK für Zone {} von {}: {}", domain, kf, e),
                }
            }
            if let Some(zf) = zsk_file {
                match dns::load_dnssec_key(&zf, false) {
                    Ok(z) => zsk_opt = Some(z),
                    Err(e) => eprintln!("Fehler beim Laden ZSK für Zone {} von {}: {}", domain, zf, e),
                }
            }

            if ksk_opt.is_none() && zsk_opt.is_none() {
                eprintln!("DNSSEC für Zone {} aktiviert, aber keine Schlüssel geladen.", domain);
            }
            dnssec_keys.insert(domain.clone(), (ksk_opt, zsk_opt));
        } else {
            dnssec_keys.insert(zone_entry.domain.to_lowercase(), (None, None));
        }
    }

    // DNSKEY records aus geladenen Schlüsseln hinzufügen
    for (domain, (ksk_opt, zsk_opt)) in &dnssec_keys {
        // Remove existing DNSKEY records for this zone and add loaded keys (KSK first)
        if let Some(records) = dns_records.get_mut(domain) {
            records.retain(|r| !matches!(r.kind, dns::RecordKind::DNSKEY { .. }));
        }
        if let Some(ksk) = ksk_opt {
            let dnskey_rec = dns::DnsRecord {
                kind: dns::RecordKind::DNSKEY { flags: ksk.flags, protocol: ksk.protocol, algorithm: ksk.algorithm, public_key: ksk.public_key.clone() },
                ttl: 3600,
                class: 1,
            };
            dns_records.entry(domain.clone()).or_default().push(dnskey_rec);
        }
        if let Some(zsk) = zsk_opt {
            let dnskey_rec = dns::DnsRecord {
                kind: dns::RecordKind::DNSKEY { flags: zsk.flags, protocol: zsk.protocol, algorithm: zsk.algorithm, public_key: zsk.public_key.clone() },
                ttl: 3600,
                class: 1,
            };
            dns_records.entry(domain.clone()).or_default().push(dnskey_rec);
        }
    }

    println!("Geladene Zonen und Keys:");
    for k in dns_records.keys() {
        println!(" - {}", k);
    }
    println!("Forwarder: {:?}", forwarders);
    println!("Punnyweitergabe (global default): {}", punny_flag);

    let port = 1025;
    let bind_addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&bind_addr)?;
    println!("DNS-Server (UTF-8, JSON config, PTR-Support, DNSSEC) läuft auf Port {}...", port);

    let mut buf = [0u8; 4096];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                let request = &buf[..amt];

                match parse_question(request) {
                    Ok(q) => {
                        let domain_normalized = q.qname.to_lowercase();
                        println!("Empfangene DNS-Anfrage für: {} (normiert: {}), Type={}", q.qname, domain_normalized, q.qtype);

                        if dns_records.contains_key(&domain_normalized) {
                            let dnssec_key: &Option<dns::DnssecKey> = dnssec_keys.get(&domain_normalized).map(|t| &t.1).unwrap_or(&None);
                            let dnssec_enabled = dnssec_key.is_some();
                            match build_response_local(request, &q, &domain_normalized, &dns_records, dnssec_enabled, dnssec_key) {
                                Ok(response) => {
                                    if let Err(e) = socket.send_to(&response, src) {
                                        eprintln!("Fehler beim Senden der Antwort: {}", e);
                                    } else {
                                        println!("Lokale Antwort gesendet für {}", q.qname);
                                    }
                                }
                                Err(e) => eprintln!("Fehler beim Erzeugen der lokalen Antwort: {}", e),
                            }
                            continue;
                        }

                        if !forwarders.is_empty() {
    let original_qname = q.qname.clone();

    // `upstream_response_vec` ist jetzt vom Typ `Vec<u8>`
    match dns::try_forward_to_upstreams(&forwarders, request, &q, &original_qname, punny_flag, Duration::from_secs(2)) {
        Ok((upstream_response_vec, _used_forward_qname, converted_to_ascii)) => {
            // `final_response` ist ebenfalls `Vec<u8>`
            let mut final_response = upstream_response_vec;
            
            if converted_to_ascii {
                match punycode_handling::rebuild_response_with_unicode_names(&final_response, &original_qname, &q) {
                    Ok(new_resp) => {
                        // Zuweisung zwischen zwei `Vec<u8>` ist problemlos möglich
                        final_response = new_resp;
                        println!("Upstream-Antwort für Client auf Unicode-Namen (UTF-8) umgeschrieben.");
                    }
                    Err(e) => {
                        eprintln!("Fehler beim Rebuild der Upstream-Antwort: {}. Verwende unveränderte Upstream-Antwort als Fallback.", e);
                    }
                }
            }

                                    if let Err(e) = socket.send_to(&final_response, src) {
                                        eprintln!("Fehler beim Senden der forwarded Antwort an Client: {}", e);
                                    } else {
                                        println!("Antwort von Forwarder an Client gesendet für {}", q.qname);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Alle Forwarder fehlgeschlagen: {}", e);
                                    // NXDOMAIN Antwort erstellen
                                    let mut nxd: Vec<u8> = Vec::new();
                                    nxd.push(request[0]); nxd.push(request[1]);
                                    let mut f1 = request[2];
                                    f1 |= 0x80; // QR=1 (Antwort)
                                    f1 |= 0x04; // RCODE=4 (NXDOMAIN)
                                    nxd.push(f1);
                                    let mut f2 = request[3];
                                    f2 &= !(0x80); // RA=0
                                    f2 &= 0x0F;
                                    f2 = (f2 & 0xF0) | 0x03; // AA=0, TC=0, RD=1
                                    nxd.push(f2);
                                    nxd.push(request[4]); nxd.push(request[5]); // QDCOUNT
                                    nxd.extend_from_slice(&[0x00,0x00, 0x00,0x00, 0x00,0x00]); // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
                                    let qstart = 12usize;
                                    let qend = qstart + q.qlength;
                                    if qend <= request.len() {
                                        nxd.extend_from_slice(&request[qstart .. qend]); // Fragebereich kopieren
                                    }
                                    if let Err(e) = socket.send_to(&nxd, src) {
                                        eprintln!("Fehler beim Senden NXDOMAIN an Client: {}", e);
                                    }
                                }
                            }

                        } else {
                            let dnssec_key: &Option<dns::DnssecKey> = dnssec_keys.get(&domain_normalized).map(|t| &t.1).unwrap_or(&None);
                            let dnssec_enabled = dnssec_key.is_some();
                            match build_response_local(request, &q, &domain_normalized, &dns_records, dnssec_enabled, dnssec_key) {
                                Ok(response) => {
                                    if let Err(e) = socket.send_to(&response, src) {
                                        eprintln!("Fehler beim Senden der lokalen Antwort (kein Forwarder): {}", e);
                                    } else {
                                        println!("Lokale NX/NOANSWER-Antwort gesendet für {}", q.qname);
                                    }
                                }
                                Err(e) => eprintln!("Fehler beim Erzeugen der lokalen NX-Antwort: {}", e),
                            }
                        }
                    }
                    
                    Err(e) => eprintln!("Fehler beim Parsen der Anfrage: {}", e),
                }
            }

            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::Interrupted => {
                continue;
            }

            Err(e) => {
                eprintln!("Socket Fehler: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}