mod error;
pub use error::Error;
mod aws;
mod gcp;

use std::borrow::Cow;
use std::fs::File;
use std::io::Read as _;
use std::io::Write;
use std::str::FromStr;

use clap::{crate_authors, crate_name, crate_version, App, AppSettings, Arg, ArgMatches};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use vault::{self, Client};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
enum CredentialType {
    Gke,
    Eks,
}

static CRED_VARIANTS: &[&str] = &["gke", "eks"];

impl FromStr for CredentialType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gke" => Ok(CredentialType::Gke),
            "eks" => Ok(CredentialType::Eks),
            _ => Err(Error::InvalidCredentialType),
        }
    }
}

fn read_file<P: AsRef<std::path::Path>>(path: P) -> Result<Vec<u8>, Error> {
    let metadata = std::fs::metadata(&path)?;
    let size = metadata.len();
    let mut file = File::open(&path)?;
    let mut buffer = Vec::with_capacity(size as usize);
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn make_parser<'a, 'b>() -> App<'a, 'b> {
    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .global_setting(AppSettings::NextLineHelp)
        .about("Read access tokens from Vault to authenticate with Kubernetes")
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
            Arg::with_name("output")
                .long("--output")
                .help("Output Path")
                .long_help(
                    "Change to path to output the credentials to. Defaults to `-` which is stdout",
                )
                .takes_value(true)
                .default_value("-"),
        )
        .arg(
            Arg::with_name("eks_role_arn")
                .long("--eks-role-arn")
                .help("AWS IAM Role ARN")
                .long_help(
                    "The ARN of the role to assume if the AWS Secrets Engine role is configured \
                     with multiple roles",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("eks_ttl")
                .long("--eks-ttl")
                .help("STS Token TTL")
                .long_help("Specifies the TTL for the use of the STS token.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("eks_expiry")
                .long("--eks-expiry")
                .help("EKS Token Expiry")
                .long_help(
                    "Specifies the Expiry duration in number of seconds for the Kubernetes Token.",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("eks_cluster")
                .long("--eks-cluster")
                .help("EKS Cluster Name")
                .long_help("Name of the EKS cluster. Required if type is `eks`")
                .takes_value(true)
                .required_if("type", "eks"),
        )
        .arg(
            Arg::with_name("eks_region")
                .long("--eks-region")
                .help("AWS Region")
                .long_help("Region of AWS to use. Defaults to the Global Endpoint")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("type")
                .help("Credentials Type")
                .long_help("Type of credentials to read")
                .takes_value(true)
                .possible_values(CRED_VARIANTS)
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("path")
                .help("Vault Path")
                .long_help("Path to read from Vault")
                .takes_value(true)
                .index(2)
                .required(true),
        )
}

fn required_arg_value<'a>(args: &'a ArgMatches<'a>, param: &str) -> &'a str {
    args.value_of(param)
        .expect("required args to be handled by clap")
}

fn get_writer(path: &str) -> Result<Box<dyn Write>, Error> {
    Ok(match path {
        "-" => Box::new(std::io::stdout()),
        others => Box::new(File::create(others)?),
    })
}

fn write<W: Write>(mut writer: W, output: &str) -> Result<(), Error> {
    write!(writer, "{}", output)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let parser = make_parser();
    let args = parser.get_matches();

    let credential_type: CredentialType =
        CredentialType::from_str(required_arg_value(&args, "type"))
            .expect("invalid values to be validated by clap");
    let token = if let Some(path) = args.value_of("vault_token_file") {
        let file = read_file(path)?;
        let token = String::from_utf8(file)?;
        Some(Cow::Owned(token))
    } else {
        args.value_of("vault_token").map(|s| Cow::Borrowed(s))
    };
    let address = args.value_of("vault_address");
    let ca_cert = args.value_of("vault_ca_cert");
    let path = required_arg_value(&args, "path");
    let output = required_arg_value(&args, "output");

    let client = Client::new(address, token, ca_cert, false)?;
    debug!("Vault Client: {:#?}", client);

    let creds = match credential_type {
        CredentialType::Gke => {
            info!("Requesting GKE Access token from {}", path);
            let gcp_access_token = gcp::read_gcp_access_token(&client, path).await?;
            serde_json::to_string_pretty(&gcp_access_token)?
        }
        CredentialType::Eks => {
            info!("Requesting AWS Credentials from {}", path);
            let request = vault::secrets::aws::CredentialsRequest {
                role_arn: args.value_of("eks_role_arn").map(|s| s.to_string()),
                ttl: args.value_of("eks_ttl").map(|s| s.to_string()),
            };
            let aws_credentials = aws::read_aws_credentials(&client, path, &request).await?;
            debug!("AWS Credentials: {:#?}", aws_credentials);
            let token = aws::get_eks_token(
                &aws_credentials,
                required_arg_value(&args, "eks_cluster"),
                args.value_of("eks_region"),
                args.value_of("eks_expiry"),
            )?;
            serde_json::to_string_pretty(&token)?
        }
    };

    let output = get_writer(output)?;
    write(output, &creds)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use vault::Vault;

    pub(crate) fn vault_client() -> Client {
        Client::from_environment::<&str, &str, &str>(None, None, None).unwrap()
    }

    #[tokio::test(threaded_scheduler)]
    async fn can_read_self_capabilities() {
        let client = vault_client();
        client.get("/auth/token/lookup-self").await.unwrap();
    }
}
