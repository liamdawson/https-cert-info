use std::convert::TryFrom;

use chrono::prelude::*;
use x509_parser::extensions::GeneralName;

#[derive(Debug)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    // TODO:
    // pub fingerprint: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub sans: Vec<(&'static str, String)>,
}

impl TryFrom<&rustls::Certificate> for CertSummary {
    type Error = anyhow::Error;

    fn try_from(value: &rustls::Certificate) -> Result<Self, Self::Error> {
        let (_, parsed) = x509_parser::parse_x509_der(value.0.as_slice())?;

        let sans = match parsed.tbs_certificate.subject_alternative_name() {
            Some((_, sans)) => sans
                .general_names
                .iter()
                .map(|name| match &name {
                    GeneralName::DNSName(name) => ("DNS", name.to_string()),
                    GeneralName::IPAddress(bytes) => ("IP", format_ip(bytes)),
                    _ => ("Unknown", format!("{:?}", &name)),
                })
                .collect(),
            _ => Vec::default(),
        };

        Ok(Self {
            sans,
            subject: parsed.subject().to_string(),
            issuer: parsed.issuer().to_string(),
            not_before: Utc.timestamp(parsed.validity().not_before.timestamp(), 0),
            not_after: Utc.timestamp(parsed.validity().not_after.timestamp(), 0),
        })
    }
}

// very primative IP formatting
fn format_ip(bytes: &[u8]) -> String {
    if bytes.len() > 4 {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        bytes
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<_>>()
            .join(".")
    }
}
