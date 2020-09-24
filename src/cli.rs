use structopt::StructOpt;

/// View a summary of the HTTPS certificate for a server
#[derive(StructOpt)]
pub struct Command {
    /// Server hostname or IP address
    #[structopt(index = 1, name = "HOST")]
    pub host: String,
    /// Destination port
    #[structopt(index = 2, name = "PORT", default_value = "443")]
    pub port: u16,
    /// Domain name expected in the certificate (default: value of HOST)
    #[structopt(short, long)]
    pub domain: Option<String>,
    /// List all certificates in the chain returned by the server
    #[structopt(short, long)]
    pub all: bool,
    /// Print all Subject Alternative Names (only prints 10 by default)
    #[structopt(short, long)]
    pub print_all_sans: bool,
}

impl Command {
    pub fn domain(&self) -> &String {
        self.domain.as_ref().unwrap_or(&self.host)
    }
}
