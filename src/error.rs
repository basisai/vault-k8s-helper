use failure::Fail;

/// Error type for this library
#[derive(Debug, Fail)]
pub enum Error {
    /// Errors related to API HTTP calls
    #[fail(display = "Error making HTTP Request: {}", _0)]
    ReqwestError(#[cause] reqwest::Error),
    /// Errors parsing headers
    #[fail(display = "Error parsing HTTP header: {}", _0)]
    HeadersErrors(#[cause] reqwest::header::ToStrError),
    /// Errors related to URL parsing
    #[fail(display = "Error Parsing URL: {}", _0)]
    UrlParseError(#[cause] url::ParseError),
    /// Errors parsing Numbers
    #[fail(display = "Error parsing integer: {}", _0)]
    ParseIntError(#[cause] std::num::ParseIntError),
    /// Errors deserializing JSON
    #[fail(display = "Error deserializing JSON: {}", _0)]
    JsonError(#[cause] serde_json::Error),
    #[fail(display = "Vault Address is missing")]
    MissingAddress,
    #[fail(display = "Vault Token is missing")]
    MissingToken,
    #[fail(display = "{}", _0)]
    IoError(#[cause] std::io::Error),
    #[fail(display = "Error converting bytes to UTF-8: {}", _0)]
    Utf8Error(#[cause] std::string::FromUtf8Error),
    #[fail(display = "Vault Error: {}", _0)]
    VaultError(#[cause] vault::Error),
    #[fail(display = "Invalid Credential Type")]
    InvalidCredentialType,
    #[fail(display = "Vault credentials path is invalid")]
    InvalidVaultPath,
    #[fail(display = "Invalid AWS Region: {}", _0)]
    InvalidAwsRegion(#[cause] rusoto_core::region::ParseRegionError),
    #[fail(display = "GCP Authentication error: {}", _0)]
    GCPAuthError(gcp_auth::Error),
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::ReqwestError(error)
    }
}

impl From<reqwest::header::ToStrError> for Error {
    fn from(error: reqwest::header::ToStrError) -> Self {
        Error::HeadersErrors(error)
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Error::UrlParseError(error)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(error: std::num::ParseIntError) -> Self {
        Error::ParseIntError(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::JsonError(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Error::Utf8Error(error)
    }
}

impl From<vault::Error> for Error {
    fn from(error: vault::Error) -> Self {
        Error::VaultError(error)
    }
}

impl From<rusoto_core::region::ParseRegionError> for Error {
    fn from(error: rusoto_core::region::ParseRegionError) -> Self {
        Error::InvalidAwsRegion(error)
    }
}

impl From<gcp_auth::Error> for Error {
    fn from(error: gcp_auth::Error) -> Self {
        Error::GCPAuthError(error)
    }
}
