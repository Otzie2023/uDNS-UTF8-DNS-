use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};

use crate::config::{ZonesFile, ZoneJson, PtrConfig, PtrEntry};
use crate::dns::{DnsRecord, RecordKind};

pub fn load_zones_config(path: &str) -> Result<(ZonesFile, Vec<ZoneJson>), Box<dyn Error>> {
    let s = fs::read_to_string(path)?;
    let zones_file: ZonesFile = serde_json::from_str(&s)?;
    let mut loaded_zones = Vec::new();

    for entry in &zones_file.zones {
        if !entry.enabled {
            continue;
        }
        let zone_path = Path::new(&entry.zone_file);
        if !zone_path.exists() {
            eprintln!("Warnung: zone_file '{}' für Domain '{}' nicht gefunden. Überspringe.", entry.zone_file, entry.domain);
            continue;
        }
        let zone_str = fs::read_to_string(zone_path)?;
        let zone_json: ZoneJson = serde_json::from_str(&zone_str)?;

        if let Some(soa) = &zone_json.soa {
            if let Some(last_updated_str) = &entry.last_updated {
                match DateTime::parse_from_rfc3339(last_updated_str) {
                    Ok(dt_fixed) => {
                        let last_dt_utc: DateTime<Utc> = dt_fixed.with_timezone(&Utc);
                        let now = Utc::now();
                        let age_seconds = (now - last_dt_utc).num_seconds();
                        if !soa.expire.is_infinite() {
                            let expire_seconds = soa.expire.as_seconds_or_max() as i64;
                            if age_seconds > expire_seconds {
                                println!(
                                    "Zone '{}' übersprungen: verfallen (age {}s > expire {}s).",
                                    entry.domain, age_seconds, expire_seconds
                                );
                                continue;
                            } else {
                                println!(
                                    "Zone '{}' ist noch gültig (age {}s <= expire {}s).",
                                    entry.domain, age_seconds, expire_seconds
                                );
                            }
                        } else {
                            println!("Zone '{}' hat expire=∞; niemals verfallen.", entry.domain);
                        }
                    }
                    Err(e) => {
                        eprintln!("Warnung: Kann last_updated '{}' nicht parsen für Domain '{}': {}. Behandle als nicht verfallen.", last_updated_str, entry.domain, e);
                    }
                }
            } else {
                println!("Zone '{}' hat kein last_updated; lade ohne Expire-Check.", entry.domain);
            }
        } else {
            println!("Zone '{}' hat keine SOA-Angabe; lade ohne Expire-Check.", entry.domain);
        }

        loaded_zones.push(zone_json);
    }

    Ok((zones_file, loaded_zones))
}

pub fn load_ptrs_config(path: &str) -> Result<Vec<PtrEntry>, Box<dyn Error>> {
    let p = Path::new(path);
    if !p.exists() {
        return Ok(Vec::new());
    }
    let s = fs::read_to_string(path)?;
    let cfg: PtrConfig = serde_json::from_str(&s)?;
    Ok(cfg.ptrs)
}

pub fn build_dns_records_from_zones(zones: Vec<ZoneJson>) -> Result<HashMap<String, Vec<DnsRecord>>, Box<dyn Error>> {
    let mut dns_records: HashMap<String, Vec<DnsRecord>> = HashMap::new();

    for zone in zones {
        let apex = zone.domain.to_lowercase();
        let zone_ttl = zone.ttl.unwrap_or(3600);

        if let Some(soa) = &zone.soa {
            let mname = trim_trailing_dot(&soa.primary_ns);
            let rname = trim_trailing_dot(&soa.admin_email);
            let soa_rec = DnsRecord {
                kind: RecordKind::SOA {
                    mname,
                    rname,
                    serial: soa.serial,
                    refresh: soa.refresh,
                    retry: soa.retry,
                    expire: soa.expire.clone(),
                    minimum: soa.minimum,
                },
                ttl: zone_ttl,
                class: 1,
            };
            dns_records.entry(apex.clone()).or_default().push(soa_rec);
        }

        for r in zone.records {
            let rtype = r.r#type.to_uppercase();
            let fullname = if r.name == "@" {
                apex.clone()
            } else {
                let name_part = trim_trailing_dot(&r.name);
                format!("{}.{}", name_part, apex)
            }.to_lowercase();

            match rtype.as_str() {
                "A" => {
                    if let Some(val) = r.value {
                        let v = trim_trailing_dot(&val);
                        let rec = DnsRecord { kind: RecordKind::A(v), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "PTR" => {
                    if let Some(val) = r.value {
                        let target = trim_trailing_dot(&val);
                        let rec = DnsRecord { kind: RecordKind::PTR(target), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "SRV" => {
                    if let Some(val) = r.value {
                        let parts: Vec<&str> = val.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let pr = parts[0].parse::<u16>().unwrap_or(0);
                            let wt = parts[1].parse::<u16>().unwrap_or(0);
                            let port = parts[2].parse::<u16>().unwrap_or(0);
                            let tgt = trim_trailing_dot(parts[3]);
                            let rec = DnsRecord { kind: RecordKind::SRV { priority: pr, weight: wt, port, target: tgt }, ttl: zone_ttl, class: 1 };
                            dns_records.entry(fullname).or_default().push(rec);
                        } else {
                            eprintln!("Ungültiges SRV value für {}: '{}'", fullname, val);
                        }
                    }
                }
                "NAPTR" => {
                    if let Some(val) = r.value {
                        let parts: Vec<&str> = val.split_whitespace().collect();
                        if parts.len() >= 6 {
                            let order = parts[0].parse::<u16>().unwrap_or(0);
                            let preference = parts[1].parse::<u16>().unwrap_or(0);
                            let flags = parts[2].to_string();
                            let services = parts[3].to_string();
                            let regexp = parts[4].to_string();
                            let replacement = trim_trailing_dot(parts[5]);
                            let rec = DnsRecord { kind: RecordKind::NAPTR { order, preference, flags, services, regexp, replacement }, ttl: zone_ttl, class: 1 };
                            dns_records.entry(fullname).or_default().push(rec);
                        } else {
                            eprintln!("Ungültiges NAPTR value für {}: '{}'", fullname, val);
                        }
                    }
                }
                "CAA" => {
                    if let Some(val) = r.value {
                            let parts: Vec<&str> = val.splitn(3, ' ').collect();
                        if parts.len() >= 3 {
                            let flags = parts[0].parse::<u8>().unwrap_or(0);
                            let tag = parts[1].trim_matches('"').to_string();
                            let value = parts[2].trim_matches('"').to_string();
                            let rec = DnsRecord { kind: RecordKind::CAA { flags, tag, value }, ttl: zone_ttl, class: 1 };
                            dns_records.entry(fullname).or_default().push(rec);
                        }
                    }
                }
                "TLSA" => {
                    if let Some(val) = r.value {
                        let parts: Vec<&str> = val.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let usage = parts[0].parse::<u8>().unwrap_or(0);
                            let selector = parts[1].parse::<u8>().unwrap_or(0);
                            let mtype = parts[2].parse::<u8>().unwrap_or(0);
                            let hex = parts[3].trim();
                            let cert = hex::decode(hex).unwrap_or_default();
                            let rec = DnsRecord { kind: RecordKind::TLSA { usage, selector, matching_type: mtype, cert_assoc_data: cert }, ttl: zone_ttl, class: 1 };
                            dns_records.entry(fullname).or_default().push(rec);
                        }
                    }
                }
                "SSHFP" => {
                    if let Some(val) = r.value {
                        let parts: Vec<&str> = val.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let alg = parts[0].parse::<u8>().unwrap_or(0);
                            let fptype = parts[1].parse::<u8>().unwrap_or(0);
                            let fp = hex::decode(parts[2].trim()).unwrap_or_default();
                            let rec = DnsRecord { kind: RecordKind::SSHFP { algorithm: alg, fptype, fingerprint: fp }, ttl: zone_ttl, class: 1 };
                            dns_records.entry(fullname).or_default().push(rec);
                        }
                    }
                }
                "DNAME" => {
                    if let Some(val) = r.value {
                        let target = trim_trailing_dot(&val);
                        let rec = DnsRecord { kind: RecordKind::DNAME(target), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "HINFO" => {
                    if let Some(val) = r.value {
                        let s = trim_quotes(&val);
                        let parts: Vec<&str> = s.splitn(2, ' ').collect();
                        let cpu = parts.get(0).map(|s| s.to_string()).unwrap_or_default();
                        let os = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
                        let rec = DnsRecord { kind: RecordKind::HINFO { cpu, os }, ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "RP" => {
                    if let Some(val) = r.value {
                        let parts: Vec<&str> = val.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let mbox = trim_trailing_dot(parts[0]);
                            let txt = trim_trailing_dot(parts[1]);
                            let rec = DnsRecord { kind: RecordKind::RP { mbox, txt }, ttl: zone_ttl, class: 1 };
                            dns_records.entry(fullname).or_default().push(rec);
                        }
                    }
                }
                "SPF" => {
                    if let Some(val) = r.value {
                        let txt = trim_quotes(&val);
                        let rec = DnsRecord { kind: RecordKind::TXT(txt), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "AAAA" => {
                    if let Some(val) = r.value {
                        let v = trim_trailing_dot(&val);
                        let rec = DnsRecord { kind: RecordKind::AAAA(v), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "CNAME" => {
                    if let Some(val) = r.value {
                        let target = trim_trailing_dot(&val);
                        let rec = DnsRecord { kind: RecordKind::CNAME(target), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "MX" => {
                    if let Some(val) = r.value {
                        let pref = r.priority.unwrap_or(10);
                        let exchange = trim_trailing_dot(&val);
                        let rec = DnsRecord { kind: RecordKind::MX { pref, exchange }, ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "TXT" => {
                    if let Some(val) = r.value {
                        let txt = trim_quotes(&val);
                        let rec = DnsRecord { kind: RecordKind::TXT(txt), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "NS" => {
                    if let Some(val) = r.value {
                        let target = trim_trailing_dot(&val);
                        let rec = DnsRecord { kind: RecordKind::NS(target), ttl: zone_ttl, class: 1 };
                        dns_records.entry(fullname).or_default().push(rec);
                    }
                }
                "DNSKEY" => {
                    if let Some(val) = r.value {
                        let parts: Vec<&str> = val.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let flags = parts[0].parse::<u16>().unwrap_or(0);
                            let protocol = parts[1].parse::<u8>().unwrap_or(0);
                            let algorithm = parts[2].parse::<u8>().unwrap_or(0);
                            let key_data = hex::decode(parts[3].trim()).unwrap_or_default();
                            let rec = DnsRecord { kind: RecordKind::DNSKEY { flags, protocol, algorithm, public_key: key_data }, ttl: zone_ttl, class: 1 };
                            dns_records.entry(fullname).or_default().push(rec);
                        }
                    }
                }
                other => {
                    eprintln!("Warnung: Record-Typ '{}' nicht unterstützt -> übersprungen", other);
                }
            }
        }
    }

    Ok(dns_records)
}

pub fn add_ptr_record(dns_records: &mut HashMap<String, Vec<DnsRecord>>, ip_str: &str, ptr_target: &str, ttl: u32, class: u16) -> Result<(), Box<dyn Error>> {
    if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
        let octs = v4.octets();
        let rev = format!("{}.{}.{}.{}.in-addr.arpa", octs[3], octs[2], octs[1], octs[0]);
        let owner = rev.to_lowercase();
        let target = trim_trailing_dot(ptr_target);
        let rec = DnsRecord { kind: RecordKind::PTR(target), ttl, class };
        dns_records.entry(owner).or_default().push(rec);
        return Ok(());
    }

    if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
        let octets = v6.octets();
        let mut hex = String::new();
        for b in &octets {
            hex.push_str(&format!("{:02x}", b));
        }
        let mut labels: Vec<String> = Vec::with_capacity(32);
        for ch in hex.chars().rev() {
            labels.push(ch.to_string());
        }
        let owner = format!("{}.ip6.arpa", labels.join("."));
        let owner_lc = owner.to_lowercase();
        let target = trim_trailing_dot(ptr_target);
        let rec = DnsRecord { kind: RecordKind::PTR(target), ttl, class };
        dns_records.entry(owner_lc).or_default().push(rec);
        return Ok(());
    }

    Err(format!("Ungültige IP-Adresse für PTR-Registrierung: {}", ip_str).into())
}

pub fn trim_trailing_dot(s: &str) -> String {
    if s.ends_with('.') {
        s[..s.len()-1].to_string()
    } else {
        s.to_string()
    }
}

pub fn trim_quotes(s: &str) -> String {
    let mut res = s.to_string();
    if res.starts_with('"') && res.ends_with('"') && res.len() >= 2 {
        res = res[1..res.len()-1].to_string();
    }
    res
}