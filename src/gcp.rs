use std::fmt;

use chrono::{DateTime, Duration, NaiveDateTime, SecondsFormat, Utc};
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use vault::{self, Client, Vault};

use crate::Error;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GcpAccessToken {
    #[serde(deserialize_with = "timestamp_to_iso")]
    #[serde(rename(serialize = "token_expiry", deserialize = "expires_at_seconds"))]
    pub expiry: String,
    pub token: String,
    #[serde(skip_serializing)]
    pub token_ttl: u64,
}

impl GcpAccessToken {
    pub(crate) fn from_gcp_auth(token: &gcp_auth::Token) -> Self {
        let expiry = token.expires_at().unwrap_or_else(|| {
            // No expiry, let's just add now + 50 mins
            Utc::now() + Duration::minutes(50)
        });
        Self {
            token: token.as_str().to_string(),
            expiry: expiry.to_rfc3339_opts(SecondsFormat::Secs, true),
            token_ttl: (expiry - Utc::now()).num_seconds().abs() as u64,
        }
    }
}

fn timestamp_to_iso<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
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

    let timestamp = deserializer.deserialize_i64(TimestampVisitor)?;
    let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc);
    Ok(dt.to_rfc3339_opts(SecondsFormat::Secs, true))
}

pub async fn read_gcp_access_token<S: AsRef<str>>(
    client: &Client,
    path: S,
) -> Result<GcpAccessToken, Error> {
    let response = client.get(path.as_ref()).await?;
    let data = response.data()?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    fn gcp_path() -> String {
        env::var("GCP_PATH").expect("Provide Path to GCP role in GCP_PATH variable")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn can_read_gcp_secrets() {
        let client = crate::tests::vault_client();
        read_gcp_access_token(&client, gcp_path()).await.unwrap();
    }
}
