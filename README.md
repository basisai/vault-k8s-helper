# GKE Helper

An authentication provider for GKE that reads access tokens from Vault.

## Usage

You have to configure Vault's
[Google Cloud Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html) first with
an appropriate
[access token roleset](https://www.vaultproject.io/docs/secrets/gcp/index.html#access-tokens).

```text
Read Google Cloud Platform access token from Vault

USAGE:
    vault-gke-helper [OPTIONS] <path>

FLAGS:
    -h, --help
            Prints help information

    -V, --version
            Prints version information


OPTIONS:
        --vault-address <vault_address>
            Specifies the Vault Address to connect to. Include the scheme and port. Can be provided by the `VAULT_ADDR`
            environment variable as well
        --vault-ca-cert <vault_ca_cert>
            Specifies a path to the PEM encoded CA Certificate for Vault. Can be provided by the `VAULT_CACERT`
            environment variable as well
        --vault-token <vault_token>
            Specifies the Vault token to use with Vault. Can be provided by the `VAULT_TOKEN` environment variable as
            well
        --vault-token-file <vault_token_file>
            Specifies a path to Vault token to read from and use with Vault.


ARGS:
    <path>
            Path to read from Vault

```

## Tests

You have to use a real Vault server with a configured
[Google Cloud Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html)
[access token roleset](https://www.vaultproject.io/docs/secrets/gcp/index.html#access-tokens).

Provide the usual environemnt variables plus:

- `GCP_PATH` for the path to read the secrets from
