use std::collections::HashMap;

use log::{debug, warn};
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
        return Err(Error::InvalidVaultPath);
    }
    if path_parts[1] != "creds" {
        return Err(Error::InvalidVaultPath);
    }

    let mount_point = path_parts[0];
    let role = path_parts[2];

    let creds = Aws::generate_credentials(&client, mount_point, role, request)?;
    debug!(
        "AWS Credentials from Vault: {}",
        serde_json::to_string_pretty(&creds)?
    );

    let expiry = if creds.data.security_token.is_some() {
        Some(chrono::Utc::now() + chrono::Duration::seconds(creds.lease_duration as i64))
    } else {
        None
    };

    Ok(AwsCredentials::new(
        creds.data.access_key,
        creds.data.secret_key,
        creds.data.security_token,
        expiry,
    ))
}

pub fn generate_presigned_url(
    credentials: &AwsCredentials,
    cluster: &str,
    region: Option<&str>,
    expires_in: Option<&str>,
) -> Result<String, Error> {
    let region: Option<rusoto_core::region::Region> = match region {
        Some(r) => Some(r.parse()?),
        None => None,
    };
    let expiry = match expires_in {
        Some(expiry) => Some(std::time::Duration::from_secs(expiry.parse()?)),
        None => None,
    };

    if let Some(duration) = expiry {
        warn!(
            "The sts `GetCallerIdentity` request is valid for 15 minutes regardless of this \
             parameters value after it has been signed."
        );
        if duration.as_secs() < 60 {
            warn!(
                "Setting the expiry to less than 60 seconds might cause versions of \
                 `aws-iam-authenticator` earlier than 0.3.0 to error"
            );
        }
    }

    let headers = [("x-k8s-aws-id", cluster)].iter().cloned().collect();
    Ok(aws_auth_payload::client::presigned_url(
        credentials,
        region,
        headers,
        expiry.as_ref(),
    ))
}

pub fn get_eks_token(
    credentials: &AwsCredentials,
    cluster: &str,
    region: Option<&str>,
    expires_in: Option<&str>,
) -> Result<EksCredential, Error> {
    let url = generate_presigned_url(credentials, cluster, region, expires_in)?;
    debug!("Generated AWS Pre-signed URL: {}", url);

    let mut token = "k8s-aws-v1.".to_string();
    base64::encode_config_buf(&url, base64::URL_SAFE_NO_PAD, &mut token);

    Ok(EksCredential {
        kind: "ExecCredential",
        api_version: "client.authentication.k8s.io/v1alpha1",
        spec: Default::default(),
        status: EksCredentialStatus { token },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    fn aws_path() -> String {
        env::var("AWS_PATH").expect("Provide Path to AWS role in AWS_PATH variable")
    }

    fn aws_credentials() -> rusoto_core::credential::AwsCredentials {
        let client = crate::tests::vault_client();
        read_aws_credentials(&client, &aws_path(), &Default::default()).unwrap()
    }

    #[test]
    fn presigned_url_is_valid() {
        let aws_credentials = aws_credentials();
        let url = generate_presigned_url(&aws_credentials, "foobar", None, None).unwrap();

        // We try to make the call to the pre-signed URL and it should succeed with 200
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("x-k8s-aws-id", "foobar")
            .send()
            .unwrap();
        assert!(response.status().is_success());
    }

    #[test]
    fn can_create_aws_token() {
        let aws_credentials = aws_credentials();
        let _ = get_eks_token(&aws_credentials, "test", None, None).unwrap();
    }
}
