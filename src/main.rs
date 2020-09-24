#![warn(clippy::all)]

mod cert;
mod cli;

use std::convert::TryFrom;
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;

use cert::CertSummary;
use chrono::prelude::*;
use console::style;
use once_cell::sync::Lazy;
use regex::Regex;
use rustls::{Certificate, ClientConfig, Session};
use structopt::StructOpt;
use webpki::DNSNameRef;

static CN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new("CN=(.+)(?:,|$)").expect("Unable to compile CN regex"));

fn main() -> anyhow::Result<()> {
    let result = inner_main();

    if result.is_err() {
        println!();
    }

    result
}

fn inner_main() -> anyhow::Result<()> {
    let args = cli::Command::from_args();

    let start_time = Local::now();

    eprint!(
        "Connecting to {} ",
        style(format!("{}:{}", &args.host, args.port)).cyan()
    );

    let mut sock = connect(&args.host, args.port)?;

    let connected_at = Local::now();

    eprintln!(
        "{}",
        style(format!(
            "(took {}ms)",
            connected_at
                .signed_duration_since(start_time)
                .num_milliseconds()
        ))
        .dim()
    );
    eprint!("Performing handshake for {} ", style(args.domain()).cyan());

    let certs = get_certificates(&mut sock, args.domain())?;
    let shutdown_result = sock.shutdown(Shutdown::Both);

    eprintln!(
        "{}",
        style(format!(
            "(took {}ms)",
            Local::now()
                .signed_duration_since(connected_at)
                .num_milliseconds()
        ))
        .dim()
    );

    if let Err(err) = shutdown_result {
        eprintln!("Warning: could not cleanly shutdown the socket: {}", err);
    };

    eprintln!();

    if certs.is_empty() {
        println!("Error: no certificates were returned");
        std::process::exit(2);
    }

    if args.all {
        for cert in certs {
            print_cert_details(&cert, args.print_all_sans)?;
            println!("\n---\n");
        }
    } else if let Some(cert) = certs.first() {
        print_cert_details(cert, args.print_all_sans)?;
    }

    Ok(())
}

fn client_config() -> std::io::Result<ClientConfig> {
    let mut config = ClientConfig::new();

    config.root_store = match rustls_native_certs::load_native_certs() {
        Ok(root_store) => root_store,
        Err((res, err)) => {
            if let Some(root_store) = res {
                eprintln!("Could not fully load root certificates: {}", err);
                root_store
            } else {
                return Err(err);
            }
        }
    };

    config.enable_sni = true;

    Ok(config)
}

fn connect(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    Ok(TcpStream::connect((host, port))?)
}

fn get_certificates(sock: &mut TcpStream, server_name: &str) -> anyhow::Result<Vec<Certificate>> {
    let domain = DNSNameRef::try_from_ascii_str(server_name)?;
    let config = client_config()?;
    let mut sess = rustls::ClientSession::new(&Arc::from(config), domain);

    sess.complete_io(sock)?;
    sess.process_new_packets()?;

    let raw_certs = sess.get_peer_certificates().unwrap_or_default();

    Ok(raw_certs)
}

fn print_cert_details(raw_certificate: &Certificate, print_all_sans: bool) -> anyhow::Result<()> {
    let summary = CertSummary::try_from(raw_certificate)?;
    let now = Utc::now();

    let expires_in = summary.not_after.signed_duration_since(now);
    let started_ago = now.signed_duration_since(summary.not_before);

    println!("Subject     {}", style_subject(&summary.subject));
    println!("Issued by   {}", style_subject(&summary.issuer));
    println!(
        "Valid from  {} days ago {}\nExpires in  {} days {}",
        style(started_ago.num_days()).cyan(),
        style(format!(
            "({})",
            summary
                .not_before
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        ))
        .dim(),
        style(expires_in.num_days()).cyan(),
        style(format!(
            "({})",
            summary.not_after.to_rfc3339_opts(SecondsFormat::Secs, true)
        ))
        .dim(),
    );

    if !summary.sans.is_empty() {
        let printed_sans = if print_all_sans {
            summary.sans.len()
        } else {
            summary.sans.len().min(10)
        };

        let skipped_sans = summary.sans.len() - printed_sans;

        let printed: Vec<_> = summary
            .sans
            .iter()
            .take(printed_sans)
            .map(|name| name.1.clone())
            .collect();

        println!();
        println!("{}", style("Subject Alternative Names:").dim());
        for name in printed {
            println!("  {}", name);
        }

        if skipped_sans > 0 {
            println!("    and {} more.", skipped_sans);
        }
    }

    Ok(())
}

fn style_subject(subject: &str) -> String {
    if let Some(captures) = CN_REGEX.captures(subject) {
        if let Some(cn) = captures.get(1) {
            let full = style(format!("({})", subject)).dim();
            return format!("{} {}", style(cn.as_str()).green(), full);
        }
    }

    subject.to_string()
}
