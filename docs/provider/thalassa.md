# Thalassa Secrets Manager

External Secrets Operator integrates with [Thalassa Cloud](https://thalassa.cloud/) [Secret Manager](https://docs.thalassa.cloud/docs/secrets-manager/).

## Creating a SecretStore

You need to set `region`, `organisationId`, and one authentication method.
Set `kmsKeyId` when using `PushSecret`.
When using a `ClusterSecretStore`, set `namespace` on every `secretRef` and `serviceAccountRef`.

### JWT and Workload Identity

The recommended way to authenticate is workload identity: the Kubernetes ServiceAccount JWT is used to impersonate a Thalassa ServiceAccount.

If you are on the Thalassa Kubernetes Service, you can bootstrap this with `tcloud`:

```bash
export ORGANISATION_ID="<org-id>"
export CLUSTER_ID="<kubernetes-cluster-id>"

tcloud iam workload-identity-federation bootstrap kubernetes \
  --cluster "$CLUSTER_ID" \
  --namespace external-secrets \
  --service-account external-secrets \
  --role secrets:FullAccess
```

This creates a Thalassa ServiceAccount for the cluster, binds the role, and configures Identity Federation. See the [OIDC documentation](https://docs.thalassa.cloud/docs/iam/oidc/kubernetes/) for details.

Example SecretStore:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: thalassa
spec:
  provider:
    thalassa:
      region: nl-01
      organisationId: o-abc1234
      auth:
        jwt:
          thalassaServiceAccountId: sa-abc1234
          serviceAccountRef:
            name: external-secrets
            namespace: external-secrets
```

### Access credentials

If workload identity is not an option, use [Access Credentials](https://docs.thalassa.cloud/docs/iam/service-accounts/#managing-access-credentials). Create credentials for your Thalassa ServiceAccount and store them in a Kubernetes Secret:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: thalassa
spec:
  provider:
    thalassa:
      region: nl-01
      organisationId: o-abc1234
      auth:
        accessCredentials:
          accessKey: <accessKey>
          accessSecretRef:
            name: thalassa-credentials
            key: accessSecret
```

## Referencing secrets

Secrets are referenced by path, for example `/app/demo/password`. The path must start with `/`.

`remoteRef.version` can be `latest`, `latest_enabled`, a version number, or left empty.

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: thalassa-secret
spec:
  refreshInterval: 1h0m0s
  secretStoreRef:
    kind: SecretStore
    name: thalassa
  target:
    name: thalassa-secret
    creationPolicy: Owner
  data:
    - secretKey: password
      remoteRef:
        key: /app/demo/password
        version: latest_enabled
```
