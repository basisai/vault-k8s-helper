mod error;
pub use error::Error;

use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::Read as _;

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use clap::{crate_authors, crate_name, crate_version, App, AppSettings, Arg};
use log::debug;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use vault::{self, Client, Vault};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct GcpAccessToken {
    #[serde(deserialize_with = "timestamp_to_iso")]
    pub expires_at_seconds: String,
    pub token: String,
    #[serde(skip_serializing)]
    pub token_ttl: u64,
}

struct TimestampVisitor;

impl<'de> Visitor<'de> for TimestampVisitor {
    type Value = i64;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an integer")
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(value)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        use std::i64;
        use std::u64;
        if value <= i64::MAX as u64 {
            Ok(value as i64)
        } else {
            Err(E::custom(format!("i64 out of range: {}", value)))
        }
    }
}

fn timestamp_to_iso<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let timestamp = deserializer.deserialize_i64(TimestampVisitor)?;
    let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc);
    Ok(dt.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn read_file<P: AsRef<std::path::Path>>(path: P) -> Result<Vec<u8>, Error> {
    let metadata = std::fs::metadata(&path)?;
    let size = metadata.len();
    let mut file = File::open(&path)?;
    let mut buffer = Vec::with_capacity(size as usize);
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn read_gcp_access_token<S: AsRef<str>>(
    client: &Client,
    path: S,
) -> Result<GcpAccessToken, Error> {
    let response = client.get(path.as_ref())?;
    let data = response.data()?;
    Ok(data)
}

fn make_parser<'a, 'b>() -> App<'a, 'b> {
    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .global_setting(AppSettings::NextLineHelp)
        .about("Read Google Cloud Platform access token from Vault")
        .arg(
            Arg::with_name("vault_address")
                .help("Vault Address")
                .long("--vault-address")
                .long_help(
                    "Specifies the Vault Address to connect to. \
                     Include the scheme and port. \
                     Can be provided by the `VAULT_ADDR` environment variable as well",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("vault_token")
                .help("Vault Token")
                .long("--vault-token")
                .long_help(
                    "Specifies the Vault token to use with Vault. \
                     Can be provided by the `VAULT_TOKEN` environment variable as well",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("vault_token_file")
                .help("Vault Token File")
                .long("--vault-token-file")
                .long_help("Specifies a path to Vault token to read from and use with Vault.")
                .takes_value(true)
                .conflicts_with("vault_token"),
        )
        .arg(
            Arg::with_name("vault_ca_cert")
                .help("Vault CA Certificate")
                .long("--vault-ca-cert")
                .long_help(
                    "Specifies a path to the PEM encoded CA Certificate for Vault. \
                     Can be provided by the `VAULT_CACERT` environment variable as well",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("path")
                .help("Path to read from Vault")
                .takes_value(true)
                .required(true),
        )
}

fn main() -> Result<(), Error> {
    env_logger::init();
    let parser = make_parser();
    let args = parser.get_matches();

    let token = if let Some(path) = args.value_of("vault_token_file") {
        let file = read_file(path)?;
        let token = String::from_utf8(file)?;
        Some(Cow::Owned(token))
    } else {
        args.value_of("vault_token").map(|s| Cow::Borrowed(s))
    };
    let address = args.value_of("vault_address");
    let ca_cert = args.value_of("vault_ca_cert");

    let client = Client::new(address, token, ca_cert, false)?;
    debug!("Vault Client: {:#?}", client);

    let gcp_access_token = read_gcp_access_token(
        &client,
        args.value_of("path").expect("to be handled by clap"),
    )?;

    println!("{}", serde_json::to_string_pretty(&gcp_access_token)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    pub(crate) fn vault_client() -> Client {
        Client::from_environment::<&str, &str, &str>(None, None, None).unwrap()
    }

    #[test]
    fn can_read_self_capabilities() {
        let client = vault_client();
        client.get("/auth/token/lookup-self").unwrap();
    }

    fn path() -> String {
        env::var("GCP_PATH").expect("Provide Path to GCP role in GCP_PATH variable")
    }

    #[test]
    fn can_read_gcp_secrets() {
        let client = vault_client();
        read_gcp_access_token(&client, path()).unwrap();
    }
}
