# ATO Readiness Code Examples

These code examples accompany Edensoft Labs' article ["An Engineer's Field Manual for ATO Readiness"](https://www.edensoftlabs.com/aefmfar).

### `BigBangCustom/`

GitOps configuration for deploying custom software to a Big Bang Kubernetes cluster. Based on the [Platform One customer template](https://repo1.dso.mil/big-bang/customers/template). See the article section "Deploy Helm chart referencing custom software" for context.

### `KeycloakIntegration/`

Example C# code demonstrating how to integrate a server-side web application with Keycloak for authentication. Shows:

- OIDC (OpenID Connect) authentication flow with redirect to Keycloak
- Cookie-based session management
- Claims mapping from Keycloak roles to application claims
- Configuration for both secure (HTTPS) and development (HTTP) environments

### `Syft/`

SBOM (Software Bill of Materials) generation examples that integrate with Anchore Syft. Includes:

- `SbomCommand.py` - Waf build system command that generates CycloneDX-compliant SBOMs from a custom dependency graph, addressing the limitations of post-hoc container scanning
- `Syft.py` - Wrapper for Syft to scan Docker images and filesystem directories
- `RunAnchoreSyftScanAgainstContainer.sh` - Lightweight shell script to run Syft in Docker against container images

The Python code demonstrates how to merge build-time dependency information with container scanning to produce complete SBOMs that meet DoD requirements.

### `Trivy/`

Container vulnerability scanning integration using Aqua Trivy. Includes:

- Docker image vulnerability scanning with HTML report generation
- SBOM-based vulnerability scanning to catch issues not visible in container images
- Cache management for efficient repeated scans
- Integration with custom build systems
