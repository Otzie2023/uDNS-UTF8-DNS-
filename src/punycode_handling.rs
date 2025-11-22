use std::error::Error;
use idna;

use crate::dns::{decode_name, encode_name, Question};

pub fn is_puny_label(label: &str) -> bool {
    label.to_lowercase().starts_with("xn--")
}

pub fn domain_contains_non_ascii(domain: &str) -> bool {
    domain.bytes().any(|b| b >= 0x80)
}

pub fn to_ascii_if_needed(domain: &str) -> Result<String, Box<dyn Error>> {
    match idna::domain_to_ascii(domain) {
        Ok(s) => Ok(s),
        Err(e) => Err(format!("idna to_ascii error: {:?}", e).into()),
    }
}

pub fn to_unicode_if_needed(domain: &str) -> Result<String, Box<dyn Error>> {
    let (unicode, _info) = idna::domain_to_unicode(domain);
    Ok(unicode)
}

pub fn rebuild_response_with_unicode_names(upstream: &[u8], original_qname: &str, q: &Question) -> Result<Vec<u8>, Box<dyn Error>> {
    if upstream.len() < 12 { return Err("upstream response zu kurz".into()); }

    let id0 = upstream[0];
    let id1 = upstream[1];
    let flags2 = upstream[2];
    let flags3 = upstream[3];

    let qdcount = u16::from_be_bytes([upstream[4], upstream[5]]) as usize;
    let ancount = u16::from_be_bytes([upstream[6], upstream[7]]) as usize;
    let nscount = u16::from_be_bytes([upstream[8], upstream[9]]) as usize;
    let arcount = u16::from_be_bytes([upstream[10], upstream[11]]) as usize;

    let mut pos = 12usize;

    for _ in 0..qdcount {
        let (_qname, next) = decode_name(upstream, pos)?;
        pos = next;
        if pos + 4 > upstream.len() { return Err("upstream question truncated".into()); }
        pos += 4;
    }

    struct RR { owner: String, rtype: u16, rclass: u16, ttl: u32, rdata: Vec<u8> }

    let mut answers: Vec<RR> = Vec::new();
    let mut authority: Vec<RR> = Vec::new();
    let mut additional: Vec<RR> = Vec::new();

    let mut parse_records = |count: usize, out: &mut Vec<RR>| -> Result<(), Box<dyn Error>> {
        for _ in 0..count {
            let (owner_raw, next_after_name) = decode_name(upstream, pos)?;
            pos = next_after_name;
            if pos + 10 > upstream.len() { return Err("RR header truncated".into()); }
            let rtype = u16::from_be_bytes([upstream[pos], upstream[pos+1]]);
            let rclass = u16::from_be_bytes([upstream[pos+2], upstream[pos+3]]);
            let ttl = u32::from_be_bytes([upstream[pos+4], upstream[pos+5], upstream[pos+6], upstream[pos+7]]);
            let rdlen = u16::from_be_bytes([upstream[pos+8], upstream[pos+9]]) as usize;
            pos += 10;
            if pos + rdlen > upstream.len() { return Err("RR rdata truncated".into()); }
            let rdata = upstream[pos .. pos + rdlen].to_vec();
            pos += rdlen;

            let (owner_unicode, _info) = idna::domain_to_unicode(&owner_raw);

            out.push(RR { owner: owner_unicode, rtype, rclass, ttl, rdata });
        }
        Ok(())
    };

    parse_records(ancount, &mut answers)?;
    parse_records(nscount, &mut authority)?;
    parse_records(arcount, &mut additional)?;

    let mut out: Vec<u8> = Vec::new();
    out.push(id0); out.push(id1);
    out.push(flags2); out.push(flags3);

    out.extend_from_slice(&((qdcount as u16).to_be_bytes()));
    out.extend_from_slice(&((answers.len() as u16).to_be_bytes()));
    out.extend_from_slice(&((authority.len() as u16).to_be_bytes()));
    out.extend_from_slice(&((additional.len() as u16).to_be_bytes()));

    let qname_bytes = encode_name(original_qname);
    out.extend_from_slice(&qname_bytes);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());

    let write_rrs = |rrs: &Vec<RR>, buf: &mut Vec<u8>| {
        for rr in rrs {
            let owner_enc = encode_name(&rr.owner);
            buf.extend_from_slice(&owner_enc);
            buf.extend_from_slice(&rr.rtype.to_be_bytes());
            buf.extend_from_slice(&rr.rclass.to_be_bytes());
            buf.extend_from_slice(&rr.ttl.to_be_bytes());
            let rdlen = (rr.rdata.len() as u16).to_be_bytes();
            buf.extend_from_slice(&rdlen);
            buf.extend_from_slice(&rr.rdata);
        }
    };

    write_rrs(&answers, &mut out);
    write_rrs(&authority, &mut out);
    write_rrs(&additional, &mut out);

    Ok(out)
}