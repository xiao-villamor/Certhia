# Private registry connections

Catalog browsing, listing tags for a known repository, and retrieving a manifest for a tag or digest are separate operations. In **Registry connections → Browse**, enter the repository to look up its tags, or enter the complete image reference to test its manifest and start a scan. A manifest test confirms access to the manifest. A scan also needs access to the image’s config and layers.

## GitHub Container Registry

Select **GitHub Container Registry** and use `ghcr.io`. For private images, enter the GitHub username and a classic personal access token with `read:packages`. The user must have access to the package, and organizations that enforce SSO may require authorizing the token for the organization. Enter the GitHub organization or account as the namespace to browse its Packages API catalog. A catalog HTTP 403 means the Packages API rejected that request. Check OCI tag listing or an exact image separately. Public GHCR images can be tested anonymously. [GitHub Container registry authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) · [GitHub Packages REST API](https://docs.github.com/en/rest/packages/packages)

## Forgejo

Select **Forgejo** and enter the instance's registry host. Use your Forgejo username with a personal access token that has `read:package` and can read the package owner’s private packages. Set the namespace to the owning user or organization. Catalog requests authenticate with `Authorization: token …` at `/api/v1/packages/{owner}?type=container`. OCI requests use the registry’s bearer challenge with the username and token. A nested package such as `owner/team/image` retains its full repository path. [Forgejo container registry](https://forgejo.org/docs/v15.0/user/packages/container/) · [Forgejo API authentication and scopes](https://forgejo.org/docs/latest/user/api/usage/)

## Amazon ECR

Select **Amazon ECR** and enter the private login host, such as `123456789012.dkr.ecr.us-east-1.amazonaws.com`. Select **Use server workload identity** and save the connection. Configure the Certhia backend with an ECS task role or EKS Pod Identity. ECS supplies its relative credential endpoint. EKS Pod Identity supplies the link-local full endpoint and projected authorization token file. Grant `ecr:GetAuthorizationToken` on `*` and grant `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, and `ecr:BatchCheckLayerAvailability` for the repositories needed by scans. Cross-account repositories also require a repository policy that grants access to the role. For tag listing, grant `ecr:ListImages` where required. Exact scans can still be used if catalog listing is unavailable. An existing static credential can use username `AWS` and an ECR login password, which AWS issues for 12 hours. [AWS container credential provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html) · [ECR authorization token](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetAuthorizationToken.html) · [ECR IAM actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerregistry.html)

## Azure Container Registry

Select **Azure Container Registry**, enter its public-cloud login host ending in `.azurecr.io`, select **Use server workload identity**, and save. Configure a federated Microsoft Entra workload identity for the Certhia backend with `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and a rotating `AZURE_FEDERATED_TOKEN_FILE` projected with audience `api://AzureADTokenExchange`. For registry-wide RBAC, give the identity `AcrPull`. For an ABAC-enabled registry, assign **Container Registry Repository Reader** for the required repositories. Catalog enumeration can require **Container Registry Repository Catalog Lister** separately. The backend obtains an Entra access token and exchanges it for an ACR refresh token. [AKS Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) · [ACR authentication and authorization](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-troubleshoot-login-authn-authz) · [ACR OAuth flow](https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md)

The workload identity belongs to the backend deployment. Every opted-in connection uses that deployment identity for its provider. Cloud token renewal runs on demand and uses HTTPS with certificate verification. A bounded process-memory cache reuses provider tokens for at most one hour, with at least two minutes of expiry headroom. Saved profiles store the workload mode selection in the encrypted credential slot.

## Verification

Run the offline registry tests from `backend` with `SQLX_OFFLINE=true cargo test --locked --offline registries::`. They cover the independent GHCR HTTP outcomes and cloud credential host validation, ECR signing, the ACR exchange request, and token expiry.

The optional `forgejo_private_package_with_scoped_token` test uses a disposable Forgejo instance with a private organization called `fixture-org`, a fixture user named `registry-admin`, and an image pushed as `fixture-org/nested/demo:v1`. Bind the instance to loopback over HTTP and set Forgejo's root URL to the published address. Issue the fixture user a `read:package` token, write it to a private temporary file, and set `CERTHIA_TEST_FORGEJO_HOST` to the host and port and `CERTHIA_TEST_FORGEJO_TOKEN_FILE` to that file. Run `SQLX_OFFLINE=true cargo test --locked --offline forgejo_private_package_with_scoped_token -- --ignored`.

Cloud IAM assignments and full scans of private ECR, ACR, and GHCR images require credentials and repositories in the respective services.
