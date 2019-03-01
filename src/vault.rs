use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::ops::Deref;

use crate::Error;
use log::{debug, info, warn};
use reqwest::{Certificate, Client as HttpClient, ClientBuilder};
use serde::{Deserialize, Serialize};

/// A wrapper around a String with custom implementation of Display and Debug to not leak
/// secrets during logging.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Secret(pub String);

impl Deref for Secret {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***")
    }
}

impl AsRef<str> for Secret {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret(s)
    }
}

/// Vault API Client
#[derive(Clone, Debug)]
pub struct Client {
    token: Secret,
    address: String,
    client: HttpClient,
    revoke_self_on_drop: bool,
}

/// Generic Vault Response
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    /// An error response
    Error {
        /// List of errors returned from Vault
        errors: Vec<String>,
    },
    /// A successful response
    Response(ResponseData),
}

/// Vault General Response Data
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ResponseData {
    /// Request UUID
    pub request_id: String,
    /// Lease ID for secrets
    pub lease_id: String,
    /// Renewable for secrets
    pub renewable: bool,
    /// Lease duration for secrets
    pub lease_duration: u64,
    /// Warnings, if any
    #[serde(default)]
    pub warnings: Option<Vec<String>>,

    /// Auth data for authentication requests
    #[serde(default)]
    pub auth: Option<Authentication>,

    /// Data for secrets requests
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    // Missing and ignored fields:
    // - wrap_info
}

/// Authentication data from Vault
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Authentication {
    /// The actual token
    pub client_token: Secret,
    /// The accessor for the Token
    pub accessor: String,
    /// List of policies for token, including from Identity
    pub policies: Vec<String>,
    /// List of tokens directly assigned to token
    pub token_policies: Vec<String>,
    /// Arbitrary metadata
    pub metadata: HashMap<String, String>,
    /// Lease Duration for the token
    pub lease_duration: u64,
    /// Whether the token is renewable
    pub renewable: bool,
    /// UUID for the entity
    pub entity_id: String,
    /// Type of token
    pub token_type: TokenType,
}

/// Type of token from Vault
/// See [Vault Documentation](https://www.vaultproject.io/docs/concepts/tokens.html#token-types-in-detail)
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    /// Long lived service tokens
    Service,
    /// Short lived batch tokens
    Batch,
}

impl Client {
    fn internal_new<S1, S2>(
        vault_address: S1,
        vault_token: S2,
        revoke_self_on_drop: bool,
        client: Option<HttpClient>,
    ) -> Result<Self, Error>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        let client = match client {
            Some(client) => client,
            None => ClientBuilder::new().build()?,
        };

        Ok(Self {
            address: vault_address.as_ref().to_string(),
            token: Secret(vault_token.as_ref().to_string()),
            revoke_self_on_drop,
            client,
        })
    }

    /// Create a new API client from an existing Token
    ///
    /// You can optionally provide a `reqwest::Client` if you have specific needs like custom root
    /// CA certificate or require client authentication
    #[allow(clippy::new_ret_no_self)]
    pub fn new<S1, S2, S3>(
        vault_address: Option<S1>,
        vault_token: Option<S2>,
        root_ca: Option<S3>,
        revoke_self_on_drop: bool,
    ) -> Result<Self, Error>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
        S3: AsRef<str>,
    {
        let mut client = Self::from_environment(vault_address, vault_token, root_ca)?;
        client.revoke_self_on_drop = revoke_self_on_drop;
        Ok(client)
    }

    pub fn from_environment<S1, S2, S3>(
        address: Option<S1>,
        token: Option<S2>,
        ca_cert: Option<S3>,
    ) -> Result<Self, Error>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
        S3: AsRef<str>,
    {
        let address = Self::environment_variable_or_provided("VAULT_ADDR", address)
            .ok_or_else(|| Error::MissingAddress)?;
        let token = Self::environment_variable_or_provided("VAULT_TOKEN", token)
            .ok_or_else(|| Error::MissingToken)?;
        let root_ca = Self::environment_variable_or_provided("VAULT_CACERT", ca_cert);

        let client = if let Some(cert) = root_ca {
            let cert = Certificate::from_pem(&crate::read_file(cert)?)?;

            Some(ClientBuilder::new().add_root_certificate(cert).build()?)
        } else {
            None
        };

        // TODOs
        // VAULT_CLIENT_CERT
        // VAULT_CLIENT_KEY
        // VAULT_TLS_SERVER_NAME
        Self::internal_new(&address, &token, false, client)
    }

    fn environment_variable_or_provided<S>(
        env: &'static str,
        alternative: Option<S>,
    ) -> Option<String>
    where
        S: AsRef<str>,
    {
        alternative
            .map(|s| s.as_ref().to_string())
            .or_else(|| std::env::var(env).ok())
    }

    /// Returns the Vault Token
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the Vault address
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the HTTP Client
    pub fn http_client(&self) -> &HttpClient {
        &self.client
    }

    fn execute_request<T>(client: &HttpClient, request: reqwest::Request) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned + Debug,
    {
        debug!("Executing request: {:#?}", request);
        let mut response = client.execute(request)?;
        debug!("Response received: {:#?}", response);
        let body = response.text()?;
        debug!("Response body: {}", body);
        let result = serde_json::from_str(&body)?;
        debug!("Deserialized body: {:#?}", result);
        Ok(result)
    }

    fn execute_request_no_body(
        client: &HttpClient,
        request: reqwest::Request,
    ) -> Result<(), Error> {
        debug!("Executing request: {:#?}", request);
        let response = client.execute(request)?;
        debug!("Response received: {:#?}", response);
        Ok(())
    }

    /// Read a generic Path from Vault
    pub fn read(&self, path: &str) -> Result<Response, Error> {
        let vault_address = url::Url::parse(self.address())?;
        let vault_address = vault_address.join(&format!("/v1/{}", path))?;

        let request = self
            .client
            .get(vault_address)
            .header("X-Vault-Token", self.token.as_str())
            .build()?;

        Self::execute_request(&self.client, request)
    }

    /// Revoke the Vault token itself
    ///
    /// If successful, the Vault Token can no longer be used
    pub fn revoke_self(&self) -> Result<(), Error> {
        info!("Revoking self Vault Token");

        let request = self.build_revoke_self_request()?;
        // HTTP 204 is returned
        Self::execute_request_no_body(&self.client, request)?;
        Ok(())
    }

    fn build_revoke_self_request(&self) -> Result<reqwest::Request, Error> {
        let vault_address = url::Url::parse(self.address())?;
        let vault_address = vault_address.join("/v1/auth/token/revoke-self")?;

        Ok(self
            .client
            .post(vault_address)
            .header("X-Vault-Token", self.token.as_str())
            .build()?)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.revoke_self_on_drop {
            info!("Vault Client is being dropped. Revoking its own Token");
            match self.revoke_self() {
                Ok(()) => {}
                Err(e) => warn!("Error revoking self: {}", e),
            }
        }
    }
}

impl Response {
    pub fn ok(self) -> Result<ResponseData, Error> {
        match self {
            Response::Error { errors } => Err(Error::VaultError(errors.join("; "))),
            Response::Response(data) => Ok(data),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn vault_client() -> Client {
        Client::from_environment::<&str, &str, &str>(None, None, None).unwrap()
    }

    #[test]
    fn can_read_self_capabilities() {
        let client = vault_client();
        client.read("/auth/token/lookup-self").unwrap();
    }
}
