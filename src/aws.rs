use std::collections::HashMap;

use rusoto_core::credential::AwsCredentials;
use serde::{Deserialize, Serialize};
use vault::secrets::Aws;
use vault::{self, Client};

use crate::Error;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct EksCredential {
    pub kind: &'static str,
    #[serde(rename = "apiVersion")]
    pub api_version: &'static str,
    pub spec: HashMap<(), ()>,
    pub status: EksCredentialStatus,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct EksCredentialStatus {
    pub token: String,
}

pub fn read_aws_credentials<S: AsRef<str>>(
    client: &Client,
    path: S,
    request: &vault::secrets::aws::CredentialsRequest,
) -> Result<AwsCredentials, Error> {
    let path_parts: Vec<_> = path.as_ref().split('/').collect();
    if path_parts.len() != 3 {
        Err(Error::InvalidVaultPath)?;
    }
    if path_parts[1] != "creds" {
        Err(Error::InvalidVaultPath)?;
    }

    let mount_point = path_parts[0];
    let role = path_parts[2];

    let creds = Aws::generate_credentials(&client, mount_point, role, request)?;
    Ok(AwsCredentials::new(
        creds.access_key,
        creds.secret_key,
        creds.security_token,
        None,
    ))
}

pub fn get_eks_token(
    credentials: &AwsCredentials,
    cluster: &str,
    region: Option<&str>,
    expires_in: Option<&str>,
) -> Result<EksCredential, Error> {
    let region: Option<rusoto_core::region::Region> = match region {
        Some(r) => Some(r.parse()?),
        None => None,
    };
    let expiry = match expires_in {
        Some(expiry) => Some(std::time::Duration::from_secs(expiry.parse()?)),
        None => None,
    };
    let headers = [("x-k8s-aws-id", cluster)].iter().cloned().collect();

    let mut token = "k8s-aws-v1.".to_string();

    let url = aws_auth::client::presigned_url(credentials, region, headers, expiry.as_ref());
    base64::encode_config_buf(&url, base64::URL_SAFE_NO_PAD, &mut token);

    Ok(EksCredential {
        kind: "ExecCredential",
        api_version: "client.authentication.k8s.io/v1alpha1",
        spec: Default::default(),
        status: EksCredentialStatus { token },
    })
}
