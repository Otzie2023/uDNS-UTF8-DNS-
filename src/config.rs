use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum ForwarderEntry {
    Simple(String),
    WithFlag { address: String, punny_weitergabe: Option<bool> },
}

#[derive(Deserialize)]
pub struct ZonesFile {
    pub zones: Vec<ZoneEntry>,
    pub forwarders: Option<Vec<ForwarderEntry>>,
    pub punny_weitergabe: Option<bool>,
    pub dnssec_enabled: Option<bool>,
    pub dnssec_key_file: Option<String>,
}

#[derive(Deserialize)]
pub struct ZoneEntry {
    pub domain: String,
    pub zone_file: String,
    pub enabled: bool,
    pub last_updated: Option<String>,
    pub dnssec_enabled: Option<bool>,
    pub dnssec_key_file: Option<String>,
}

#[derive(Deserialize)]
pub struct ZoneJson {
    pub domain: String,
    pub ttl: Option<u32>,
    pub soa: Option<SoaJson>,
    pub records: Vec<RecordJson>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SoaJson {
    pub primary_ns: String,
    pub admin_email: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: Expire,
    pub minimum: u32,
}

#[derive(Deserialize)]
pub struct RecordJson {
    #[serde(rename = "type")]
    pub r#type: String,
    pub name: String,
    pub value: Option<String>,
    pub priority: Option<u16>,
}

#[derive(Deserialize)]
pub struct PtrConfig {
    pub ptrs: Vec<PtrEntry>,
}

#[derive(Deserialize)]
pub struct PtrEntry {
    pub ip: String,
    pub ptr: String,
    pub ttl: Option<u32>,
    pub class: Option<u16>,
}

#[derive(Debug, Clone)]
pub enum Expire {
    Seconds(u32),
    Infinite,
}

impl Expire {
    pub fn is_infinite(&self) -> bool {
        matches!(self, Expire::Infinite)
    }
    pub fn as_seconds_or_max(&self) -> u32 {
        match self {
            Expire::Seconds(s) => *s,
            Expire::Infinite => u32::MAX,
        }
    }
}

impl<'de> serde::Deserialize<'de> for Expire {
    fn deserialize<D>(deserializer: D) -> Result<Expire, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ExpireVisitor;
        impl<'de> serde::de::Visitor<'de> for ExpireVisitor {
            type Value = Expire;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer (seconds) or the string \"∞\"")
            }
            fn visit_u64<E>(self, v: u64) -> Result<Expire, E>
            where E: serde::de::Error {
                if v > (u32::MAX as u64) { return Err(E::custom("expire value too large for u32")); }
                Ok(Expire::Seconds(v as u32))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Expire, E>
            where E: serde::de::Error {
                if v < 0 { return Err(E::custom("negative expire not allowed")); }
                self.visit_u64(v as u64)
            }
            fn visit_str<E>(self, v: &str) -> Result<Expire, E>
            where E: serde::de::Error {
                let trimmed = v.trim();
                if trimmed == "∞" { return Ok(Expire::Infinite); }
                if let Ok(n) = trimmed.parse::<u64>() {
                    if n > (u32::MAX as u64) { return Err(E::custom("expire value too large for u32")); }
                    return Ok(Expire::Seconds(n as u32));
                }
                Err(E::custom("invalid expire value: expected integer or \"∞\""))
            }
            fn visit_string<E>(self, v: String) -> Result<Expire, E>
            where E: serde::de::Error {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_any(ExpireVisitor)
    }
}