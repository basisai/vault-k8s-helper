# Vault Kubernetes Helper

An authentication provider for Kubernetes that reads access tokens from Vault for
Google Kubernetes Engine (GKE) or Elastic Kubernetes Service (EKS).

## Install

Get prebuilt binary from release page

```bash
# Make it executable
chmod +x vault-k8s-helper
```

## Usage

```text
Read access tokens from Vault to authenticate with Kubernetes

USAGE:
    vault-k8s-helper [OPTIONS] <type> <path>

FLAGS:
    -h, --help
            Prints help information

    -V, --version
            Prints version information


OPTIONS:
        --eks-cluster <eks_cluster>
            Name of the EKS cluster. Required if type is `eks`

        --eks-expiry <eks_expiry>
            Specifies the Expiry duration in number of seconds for the Kubernetes Token.

        --eks-region <eks_region>
            Region of AWS to use. Defaults to the Global Endpoint

        --eks-role-arn <eks_role_arn>
            The ARN of the role to assume if the AWS Secrets Engine role is configured with multiple roles

        --eks-ttl <eks_ttl>
            Specifies the TTL for the use of the STS token.

        --output <output>
            Change to path to output the credentials to. Defaults to `-` which is stdout [default: -]

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
    <type>
            Type of credentials to read [possible values: gke, eks]

    <path>
            Path to read from Vault
```

### GKE

You have to configure Vault's
[Google Cloud Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html) first with
an appropriate
[access token roleset](https://www.vaultproject.io/docs/secrets/gcp/index.html#access-tokens).

```bash
VAULT_TOKEN="s.xxx" \
VAULT_ADDR="https://vault.service.consul:8200" \
VAULT_CACERT=/path/to/ca \
vault-k8s-helper gke gcp/token/roleset
```

### AWS

You have to configure Vault's
[AWS Secrets Engine](https://www.vaultproject.io/docs/secrets/aws/index.html)
with an appropriate role. Any role type should work.

```bash
VAULT_TOKEN="s.xxx" \
VAULT_ADDR="https://vault.service.consul:8200" \
VAULT_CACERT=/path/to/ca \
vault-k8s-helper eks --eks-cluster my_cluster aws/creds/role
```

### Example output

#### GKE

```json
{ "token_expiry": "2019-03-01T08:09:32Z", "token": "ya29.c.<REDACTED>" }
```

#### EKS

```json
{
  "kind": "ExecCredential",
  "apiVersion": "client.authentication.k8s.io/v1alpha1",
  "spec": {},
  "status": {
    "token": "k8s-aws-v1.<redacted>"
  }
```

## Tests

You have to use a real Vault server with a configured
[Google Cloud Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html)
[access token roleset](https://www.vaultproject.io/docs/secrets/gcp/index.html#access-tokens)
and AWS Secrets Engine Role.

Provide the usual environment variables plus:

- `GCP_PATH` for the path to a GCP Secrets Engine credential endpoint for a token Roleset
- `AWS_PATH` for the path to a AWS Secrets Engine credential endpoint for a role

## Kube Config

The following template for Kube Config would work well.

### GKE

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: <K8S-CA>
    server: <K8S-URL>
  name: deploy
contexts:
- context:
    cluster: deploy
    user: deploy
  name: deploy
current-context: deploy
kind: Config
preferences: {}
users:
- name: deploy
  user:
    auth-provider:
      config:
        cmd-args: >-
            --vault-token-file=/path/to/vault/token
            --vault-address=https://vault.service.consul:8200
            --vault-ca-cert=/path/to/cert
            gke gcp/token/roleset

        cmd-path: /bin/path/to/vault-k8s-helper
        expiry-key: '{.token_expiry}'
        token-key: '{.token}'
      name: gcp
```

### EKS

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: <K8S-CA>
    server: <K8S-URL>
  name: deploy
contexts:
- context:
    cluster: deploy
    user: deploy
  name: deploy
current-context: deploy
kind: Config
preferences: {}
users:
- name: deploy
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      args:
      - eks
      - --eks-cluster=bedrock
      - --vault-token-file=/path/to/vault/token
      - --vault-address=https://vault.service.consul:8200
      - --vault-ca-cert=/path/to/cert
      - aws/creds/role
      command: /bin/path/to/vault-k8s-helper
      env:
      - name: AWS_PROFILE
        value: default
```
