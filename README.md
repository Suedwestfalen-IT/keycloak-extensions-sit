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
