mod config;
mod dns;
mod record_handling;
mod punycode_handling;
mod dnssec;

use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;
use std::collections::HashMap;

use dns::{parse_question, build_response_local, try_forward_to_upstreams};
use record_handling::{load_zones_config, load_ptrs_config, build_dns_records_from_zones, add_ptr_record};

fn main() -> Result<(), Box<dyn Error>> {
    let zones_list_path = "zones.json";
    let (zones_file, loaded_zones) = match load_zones_config(zones_list_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Fehler beim Laden von {}: {}", zones_list_path, e);
            return Err(e);
        }
    };

    let forwarders = zones_file.forwarders.unwrap_or_default();
    let punny_flag = zones_file.punny_weitergabe.unwrap_or(true);
    let global_dnssec_enabled = zones_file.dnssec_enabled.unwrap_or(false);
    let global_dnssec_key_file = zones_file.dnssec_key_file;

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

    let mut dnssec_keys: HashMap<String, Option<dns::DnssecKey>> = HashMap::new();
    for zone_entry in zones_file.zones {
        let domain = zone_entry.domain.to_lowercase();
        let zone_dnssec_enabled = zone_entry.dnssec_enabled.unwrap_or(global_dnssec_enabled);
        if zone_dnssec_enabled {
            let key_file = zone_entry.dnssec_key_file.or(global_dnssec_key_file.clone());
            if let Some(key_path) = key_file {
                match dns::load_dnssec_key(&key_path) {
                    Ok(key) => {
                        dnssec_keys.insert(domain.clone(), Some(key));
                    }
                    Err(e) => {
                        eprintln!("Fehler beim Laden des DNSSEC-Schlüssels für Zone {} von Datei {}: {}", domain, key_path, e);
                        dnssec_keys.insert(domain, None);
                    }
                }
            } else {
                eprintln!("DNSSEC für Zone {} aktiviert, aber keine Schlüsseldatei angegeben.", domain);
                dnssec_keys.insert(domain, None);
            }
        } else {
            dnssec_keys.insert(domain, None);
        }
    }

    // Add DNSKEY records from loaded keys
    for (domain, key_opt) in &dnssec_keys {
        if let Some(key) = key_opt {
            // Remove any existing DNSKEY records
            if let Some(records) = dns_records.get_mut(domain) {
                records.retain(|r| !matches!(r.kind, dns::RecordKind::DNSKEY { .. }));
            }
            
            // Add DNSKEY record from loaded key
            let dnskey_rec = dns::DnsRecord {
                kind: dns::RecordKind::DNSKEY {
                    flags: key.flags,
                    protocol: key.protocol,
                    algorithm: key.algorithm,
                    public_key: key.public_key.clone(),
                },
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
                            let dnssec_key = dnssec_keys.get(&domain_normalized).unwrap_or(&None);
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

                            match try_forward_to_upstreams(&forwarders, request, &q, &original_qname, punny_flag, Duration::from_secs(2)) {
                                Ok((mut upstream_response, _used_forward_qname, converted_to_ascii)) => {
                                    if converted_to_ascii {
                                        match punycode_handling::rebuild_response_with_unicode_names(&upstream_response, &original_qname, &q) {
                                            Ok(new_resp) => {
                                                upstream_response = new_resp;
                                                println!("Upstream-Antwort für Client auf Unicode-Namen (UTF-8) umgeschrieben.");
                                            }
                                            Err(e) => {
                                                eprintln!("Fehler beim Rebuild der Upstream-Antwort: {}. Verwende unveränderte Upstream-Antwort als Fallback.", e);
                                            }
                                        }
                                    }

                                    if let Err(e) = socket.send_to(&upstream_response, src) {
                                        eprintln!("Fehler beim Senden der forwarded Antwort an Client: {}", e);
                                    } else {
                                        println!("Antwort von Forwarder an Client gesendet für {}", q.qname);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Alle Forwarder fehlgeschlagen: {}", e);
                                    let mut nxd: Vec<u8> = Vec::new();
                                    nxd.push(request[0]); nxd.push(request[1]);
                                    let mut f1 = request[2];
                                    f1 |= 0x80;
                                    f1 |= 0x04;
                                    nxd.push(f1);
                                    let mut f2 = request[3];
                                    f2 &= !(0x80);
                                    f2 &= 0x0F;
                                    f2 = (f2 & 0xF0) | 0x03;
                                    nxd.push(f2);
                                    nxd.push(request[4]); nxd.push(request[5]);
                                    nxd.extend_from_slice(&[0x00,0x00, 0x00,0x00, 0x00,0x00]);
                                    let qstart = 12usize;
                                    let qend = qstart + q.qlength;
                                    if qend <= request.len() {
                                        nxd.extend_from_slice(&request[qstart .. qend]);
                                    }
                                    if let Err(e) = socket.send_to(&nxd, src) {
                                        eprintln!("Fehler beim Senden NXDOMAIN an Client: {}", e);
                                    }
                                }
                            }

                        } else {
                            let dnssec_key = dnssec_keys.get(&domain_normalized).unwrap_or(&None);
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