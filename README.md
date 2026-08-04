# keycloak-extensions-sit

Keycloak SPI extensions by **Südwestfalen-IT (SIT)** for multi-tenant SSO platforms.
Built with Claude.

## Extensions

### Authenticators

| Provider ID | Display Name | Type | Purpose |
|---|---|---|---|
| `sit-forward-acr-to-broker` | SIT: Forward Client ACR to Broker | Browser Flow | Forwards the requesting client's configured ACR (`minimum.acr.value` / `default.acr.values`) as `acr_values` to the upstream IdP. Place **before** the Identity Provider Redirector. Fixes [Keycloak #42625](https://github.com/keycloak/keycloak/issues/42625). |
| `sit-enforce-broker-acr` | SIT: Enforce Broker ACR (Post-Broker) | Post Broker Login | Reads the ACR actually reached at the upstream IdP from the validated ID token, writes it into the session (AcrStore), and optionally rejects logins that fall below the client's required level. Fixes [Keycloak #25335](https://github.com/keycloak/keycloak/issues/25335). |
| `sit-conditional-requested-loa` | Condition - Requested LOA (SIT) | Conditional | Matches on the LOA level **requested** by the client (not what has already been satisfied). Supports `equals`, `minimum`, and `maximum` operators, allowing step-up tiers to be made mutually exclusive by requested level. |

### Protocol Mappers

| Provider ID | Display Name | Purpose |
|---|---|---|
| `sit-oidc-filtered-group-claim-mapper` | SIT: Filtered Group Membership | Adds a filtered list of group paths to a JWT claim. Filter by path prefix and/or regex. |

### Identity Provider Mappers

| Provider ID | Display Name | Purpose |
|---|---|---|
| `sit-oidc-group-idp-mapper` | Group Membership from Claim | Syncs Keycloak group memberships from a JSON-array claim in the upstream IdP token. Supports nested groups via slash-separated paths, optional auto-creation, and scoped removal. |

### Required Actions

| Provider ID | Display Name | Purpose |
|---|---|---|
| `sit-webauthn-register-passwordless` | SIT: Webauthn Register Passwordless (attestation optional) | Passwordless WebAuthn registration that keeps the strict attestation verifiers but also accepts `fmt: none`. Lets the realm policy stay on `direct` (which preserves the real AAGUID) without breaking registration on devices whose platform authenticator cannot produce an attestation statement. |

services/src/main/java/org/keycloak/authentication/requiredactions/WebAuthnRegister.java
---

## ACR Step-Up via Broker (ForwardAcr + EnforceBrokerAcr)

These two authenticators work together in a broker realm to implement tamper-proof ACR step-up:

```
Browser Flow (Broker Realm):
  [REQUIRED] SIT: Forward Client ACR to Broker   ← sit-forward-acr-to-broker
  [REQUIRED] Identity Provider Redirector

Post Broker Login Flow (Broker Realm):
  [REQUIRED] SIT: Enforce Broker ACR (Post-Broker) ← sit-enforce-broker-acr
```

**How it works:**

1. `ForwardAcrToBrokerAuthenticator` reads `minimum.acr.value` (or `default.acr.values`) from the requesting client and writes it as the `acr_values` client note. The standard Identity Provider Redirector then forwards it to the upstream IdP.
2. After the upstream login, `EnforceBrokerAcrAuthenticator` reads the ACR claim from the validated upstream ID token, maps it via the realm's `acr.loa.map`, and stores the result in the session. If the reached level is below the client's required level and enforcement is enabled, the login is rejected – blocking `acr_values` downgrade attempts via browser URL manipulation.

The actual step-up enforcement (OTP/WebAuthn prompts) happens on the **upstream realm** via its own authentication flow and `acr.loa.map`.

---

## WebAuthn registration with optional attestation

### The problem

Keycloak builds its webauthn4j verifier list in
`WebAuthnRegister#createWebAuthnRegistrationManager`. The `NoneAttestationStatementVerifier`
is added **only** when the realm's attestation conveyance preference is `none` or unset:

```java
if (attestationPreference == null
        || Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED.equals(attestationPreference)
        || AttestationConveyancePreference.NONE.getValue().equals(attestationPreference)) {
    verifiers.add(new NoneAttestationStatementVerifier());
}
```

With `direct` or `indirect` the list is strict, and an authenticator that returns
`fmt: none` produces:

```
AttestationVerifier is not configured to handle the supplied AttestationStatement format 'none'
```

This is not a client defect. Windows Hello only emits a `tpm` statement when the machine can
obtain an AIK certificate from Microsoft's cloud CA; where that fails, the credential is still
TPM-backed, device-bound and user-verified, but carries no attestation statement. Registration
then fails for reasons the user cannot influence.

Switching the policy to `none` is not a workaround: the browser also replaces the AAGUID with
`00000000-0000-0000-0000-000000000000`, so authenticator identification is lost as well.

### What this provider changes

`SitWebAuthnPasswordlessRegister` overrides exactly one method and registers the none verifier
in addition to the strict list. Everything else - certificate path validation against the
truststore, self-attestation handling, TPM and packed verification - stays as upstream.

| Policy `attestation` | Built-in action | This provider |
|---|---|---|
| `none` / not specified | registers, AAGUID zeroed | same |
| `direct` / `indirect`, attestation present | registers, attestation verified | same |
| `direct` / `indirect`, `fmt: none` | **fails** | registers, real AAGUID preserved |

### Scope and reversibility

Attestation exists only during registration. The authenticator, the credential provider and the
stored credential are untouched, so:

- Login runs through the built-in `WebAuthnPasswordlessAuthenticator` as before.
- Credentials are written by the built-in `WebAuthnPasswordlessCredentialProvider` in the
  standard format and are indistinguishable from ones created by the built-in action.
- Removing the JAR does not invalidate any credential.

Keycloak records the format in the credential (`attestationStatementFormat` in the credential
data), so fleet coverage can be measured after the fact - which devices delivered `tpm` and
which delivered `none`.

### Limitation: acceptable AAGUIDs

If the WebAuthn policy defines acceptable AAGUIDs, Keycloak rejects `fmt: none` in
`checkAcceptedAuthenticator`, a private method that runs *after* verification:

```java
if (NoneAttestationStatement.FORMAT.equals(response.getAttestationObject().getFormat())) {
    throw new WebAuthnException("Acceptable AAGUIDs require an attestation format other than 'none'.");
}
```

That check cannot be overridden without copying the whole `processAction` method, which is not
worth the maintenance cost. **Leave the AAGUID list empty when using this provider**; the
provider logs a warning at registration time if it is not. Restricting authenticator models and
tolerating missing attestation are mutually exclusive in current Keycloak.

### Choosing a provider ID

Two factories are shipped; enable exactly one in
`META-INF/services/org.keycloak.authentication.RequiredActionFactory`.

`SitWebAuthnPasswordlessRegisterFactory` (default, ID `sit-webauthn-register-passwordless`)
adds a separate entry under *Authentication -> Required actions*. An admin assigns it instead
of the built-in one. The "Add passkey" button in the account console calls the built-in ID and
therefore keeps the strict behaviour.

`SitWebAuthnPasswordlessRegisterOverrideFactory` reuses the built-in ID
`webauthn-register-passwordless` with `order() = 100`, so Keycloak prefers it wherever the
built-in action is referenced - account console included - with no configuration change and no
database migration. In exchange it depends on undocumented behaviour and should be reviewed on
every major upgrade.

### Applying the same pattern to 2FA

For the two-factor WebAuthn policy, extend `WebAuthnRegister` and `WebAuthnRegisterFactory`
instead of the passwordless variants; the overridden method is identical.


---

## Build

**Requirements:** Docker

```bash
# Build for a specific Keycloak version
KC_VERSION=26.6.2 ./build_jar.sh

# Or via environment / .env file
cp .env.sample .env   # edit KC_VERSION, VERSION, etc.
./build_jar.sh
```

Output: `dist/keycloak-extensions-sit-v<VERSION>-kc<KC_VERSION>.jar`

**Without Docker (plain Maven):**

```bash
mvn clean package -Dkeycloak.version=26.6.2
```

**Behind a proxy:** Copy `settings.xml.sample` to `settings.xml` and adjust the proxy host/port. `build_jar.sh` picks it up automatically if present.

---

## Install

Copy the JAR into Keycloak's `providers/` directory and run `kc.sh build`.

```bash
cp dist/keycloak-extensions-sit-*.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
```

In Docker (multi-stage):

```dockerfile
COPY keycloak-extensions-sit-*.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
```

---

## Compatibility

| Extension version | Keycloak |
|---|---|
| 1.x | ≥ 24 (tested against 26.x) |

Requires Java 17+.

---

## License

Apache License 2.0
