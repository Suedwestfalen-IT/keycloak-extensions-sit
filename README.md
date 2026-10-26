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
| `sit-auth-otp-form-no-setup` | SIT: OTP Form (no self-setup) | Browser Flow | The built-in OTP Form without the fallback to OTP self-enrolment. A user without an OTP credential is not sent to *Configure OTP*; with requirement `REQUIRED` the login fails with `credentialSetupRequired` instead. For flows where OTP is provisioned by admins or an upstream process only. |
| `sit-auth-username-password-form` | SIT: Username Password Form (alternative allowed) | Browser Flow | The built-in Username Password Form with `ALTERNATIVE` as an additional requirement choice, so it can sit next to other first-factor options (Kerberos, passkey, IdP) without a wrapper sub-flow. As `REQUIRED` identical to the built-in form. |
| `sit-auth-spnego-button` | SIT: Kerberos (on demand) | Browser Flow | Kerberos/SPNEGO that the user starts from the login page (a "Sign in with Windows" button) instead of running automatically. Works around the built-in authenticator ending in *page expired* when chosen via *Try another way*. `ALTERNATIVE`, placed after the forms sub-flow. Verified end-to-end against a real KDC in CI. |

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

## Tests

Unit tests (JUnit 5 + Mockito) live in `src/test/java`. They run without a Keycloak server:
Keycloak's model interfaces are mocked, and the SPI jars are already on the test classpath
through the `provided` dependencies.

```bash
./run_tests.sh                              # via Docker, same .env as build_jar.sh
./run_tests.sh -Dtest=IdpGroupMapperTest    # single class
mvn test -Dkeycloak.version=26.8.1          # local Maven/JDK 17+
```

`build_jar.sh` and the image build keep using `-DskipTests`; the test code is compiled there
but not executed.

`ci/kerberos-e2e/run.sh` goes one step further for the on-demand Kerberos authenticator: it
sets up a throwaway MIT KDC, starts the real Keycloak distribution with the jar, configures a
realm through the admin API and plays the login with `curl --negotiate` (ticket accepted,
fallback without ticket, and the upstream "page expired" behaviour of the built-in
authenticator). `.github/workflows/kerberos-e2e.yml` runs it on every push. Needs root
(KDC, `/etc/hosts`), so it is meant for CI runners or throwaway VMs.

---

## Group Membership from Claim (`sit-oidc-group-idp-mapper`)

Identity provider mapper that reads a JSON-array claim from the upstream IdP token and
synchronises the brokered user's group memberships in this realm. Nested groups are expressed
as slash-separated paths (`org/team-a`).

| Option | Key | Purpose |
|---|---|---|
| Groups Claim Name | `claim` | JWT claim holding the list of groups. Default `groups`. |
| Group Path Prefixes to Strip | `groupPrefix` | One or more prefixes removed from every claim value before matching (see below). |
| Target Group Prefix | `targetPrefix` | Groups are placed below this group. A leading `/` matches the first segment at root level only. Also scopes the removal. |
| Create groups that do not exist | `createMissing` | Auto-creates missing groups including intermediate parents. |
| Remove group memberships not in claim | `removeNotListed` | Removes memberships that are not present in the claim, limited to the managed scope. |
| Managed Group Prefix | `managedPrefix` | Limits removal to groups below this prefix. Ignored when `targetPrefix` is set. |

### Stripping multiple prefixes

Upstream IdPs often keep the relevant groups below **several** top-level groups. To merge them
into one group on this side, enter one prefix per line in *Group Path Prefixes to Strip*:

```
Group Path Prefixes to Strip: /PartnerA
                              /PartnerB

Claim:                        ["/PartnerA/team-1", "/PartnerB/team-2"]
Target Group Prefix:          KC2
→ group memberships:          KC2/team-1, KC2/team-2
```

Details:

* The **longest matching prefix wins**, so `/PartnerA` and `/PartnerAB` can be configured side
  by side regardless of their order.
* Claim values matching **none** of the prefixes are used unchanged (only leading slashes are
  removed), so the mapper never silently drops groups.
* A claim value that **equals** a prefix (e.g. `/PartnerA` itself, often sent when the user is a
  direct member of the parent group) strips to an empty string and is ignored, so the user is
  never added to the target group itself.
* A prefix is matched as a plain string prefix, not segment-wise — `/SSO` also matches
  `/SSOX/a`. Use the full path segment (`/SSO`) to avoid surprises.
* Besides the new line, a comma and Keycloak's `##` delimiter are accepted as separators, so
  the mapper can also be configured via the admin REST API or a realm import. A previously
  configured single value keeps working unchanged.
* The option is a text field, **not** a multivalued one: the admin console posts a multivalued
  field as a JSON array, while `IdentityProviderMapperRepresentation.config` is a
  `Map<String, String>` — saving the mapper would fail with *Cannot parse the JSON*.

### Groups with administrative roles (Keycloak 26.8+)

Since 1.7.0 the mapper applies the same check as Keycloak's built-in group mappers
([CVE-2026-12388](https://github.com/keycloak/keycloak/issues/50444)): a group that carries an
administrative role (a `realm-management` role or a composite containing one, also inherited
from a parent group) is only **joined** when the identity provider has
*Allow granting admin roles via mappers* (`allowAdminRoleMapping`) enabled. The setting defaults
to `false`, also for identity providers that existed before the upgrade, and can only be changed
by an administrator with `manage-realm`.

* Blocked groups are skipped; all other groups of the claim are still synced. Keycloak logs a
  warning naming the mapper, the identity provider and the group.
* Existing memberships are never removed by this check (same as upstream). A blocked group that
  is still listed in the claim is not removed by *Remove group memberships not in claim* either.
* Groups without administrative roles — including groups created via *Create groups that do not
  exist* — are not affected.

If brokered users are meant to receive admin groups (e.g. `realm-admins`) enable the setting on
the identity provider **before or right after** upgrading, otherwise new admins are no longer
added — this applies to the built-in *Advanced Claim to Group* mapper as well.

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

## OTP Form without self-enrolment (`sit-auth-otp-form-no-setup`)

The built-in *OTP Form* (`auth-otp-form`) reports `isUserSetupAllowed() = true`. When it is
`REQUIRED` and the user has no OTP credential, `DefaultAuthenticationFlow` does not fail the
login but schedules the `CONFIGURE_TOTP` required action: the user enrols an authenticator app
on the spot and continues. In a flow that is meant to *enforce* an existing second factor, that
is a hole - anyone with a valid password can satisfy the step by enrolling their own OTP.

`OtpFormNoSetupAuthenticator` extends `OTPFormAuthenticator` and changes nothing about OTP
validation, the form template or the credential provider. The difference is in the factory:

- `isUserSetupAllowed()` returns `false`. With requirement `REQUIRED` and no OTP credential,
  the flow engine throws `CREDENTIAL_SETUP_REQUIRED` and the user sees the standard
  "credential setup required" error page.
- `setRequiredActions()` is overridden to a no-op as a safety net, so no code path through this
  execution can ever schedule OTP self-enrolment.
- `getReferenceCategory()` is `otp`, the same as the built-in form, so *Condition - user
  configured* and credential-based conditions treat both executions identically.
- Requirement choices are `REQUIRED`, `ALTERNATIVE` and `DISABLED`. No configuration.

| Requirement | User has OTP | Built-in `auth-otp-form` | This provider |
|---|---|---|---|
| `REQUIRED` | yes | OTP form | same |
| `REQUIRED` | no | redirect to *Configure OTP* | **login fails** (`credentialSetupRequired`) |
| `ALTERNATIVE` | no | execution skipped, next alternative | same |

OTP credentials have to be created by some other route: an admin via the account API or admin
console, a one-time onboarding flow that still uses the built-in form, or the required action
assigned explicitly to the user. Both authenticators can be used side by side in different
flows; the credential is identical.

---

## Username Password Form as alternative (`sit-auth-username-password-form`)

The built-in *Username Password Form* (`auth-username-password-form`) only offers `REQUIRED`.
To make it one of several first-factor options it has to be wrapped in a sub-flow of its own,
which exists only to carry the requirement:

```
First factor (sub-flow)          REQUIRED
├─ Password (sub-flow)           ALTERNATIVE   ← wrapper
│  └─ Username Password Form     REQUIRED
└─ Passkey / Kerberos / …        ALTERNATIVE
```

`UsernamePasswordFormAlternativeFactory` extends the built-in factory and adds `ALTERNATIVE`
(and `DISABLED`) to the requirement choices. Everything else is inherited: the authenticator
is the built-in `UsernamePasswordForm`, same template, reference category `password`, optional
passkey category for conditional UI, brute-force handling. The wrapper goes away:

```
First factor (sub-flow)              REQUIRED
├─ SIT: Username Password Form       ALTERNATIVE
└─ Passkey / Kerberos / …            ALTERNATIVE
```

Put the form first among the alternatives: the first one is what the login page shows. The
others are offered under *Try another way*. Keycloak derives the texts on that page from the
provider id (`<id>-display-name`, `<id>-help-text`); they ship in this jar under
`theme-resources/messages` (English, German), so no theme change is needed.

Keep in mind that `REQUIRED`/`CONDITIONAL` and `ALTERNATIVE` executions on the same level do
not mix (Keycloak then ignores the alternatives). Steps that follow the first factor, such as a
conditional OTP sub-flow, belong one level up, next to the first-factor sub-flow.

`ci/login-e2e/run.sh` (workflow `login-e2e.yml`) checks this against the real Keycloak
distribution: as `ALTERNATIVE` the form is shown first, *Try another way* lists it next to the
passkey with readable texts, a wrong password re-renders the form, the right one logs in, and a
user with the step-up role continues into the conditional OTP sub-flow; as `REQUIRED` it logs
in like the built-in form.

---

## Kerberos on demand (`sit-auth-spnego-button`)

The built-in *Kerberos* authenticator (`auth-spnego`) challenges on the first request it sees.
In a multi-tenant platform where only some users sit on a domain-joined machine, that means a
silent `401 Negotiate` for everyone, NTLM fallbacks and browser credential prompts. What we want
is Kerberos as a *choice* next to password and passkey: a button on the login page.

Keycloak already has the mechanism for that: executions that are `ALTERNATIVE` and whose
authenticator does not require a user are listed in `auth.authenticationSelections` of the
login form, and posting `authenticationExecution=<id>` switches the flow to that execution.
With the built-in authenticator this ends in **"Page has expired"**
([forum thread](https://forum.keycloak.org/t/access-with-kerberos-fails-if-we-choose-the-authentication/5137),
open since Keycloak 11), and the reason is structural:

1. The selection is a `POST` to `login-actions/authenticate?session_code=A&execution=<form>`.
2. `auth-spnego` answers it with `401 WWW-Authenticate: Negotiate`.
3. The browser repeats **the same POST** with the ticket. `session_code` is single use and was
   consumed in step 1, and `execution` still names the form while the flow engine already
   switched to Kerberos, so `AuthenticationProcessor#authenticationAction` shows *page expired*
   before the authenticator ever sees the token. Nothing is logged.

`SpnegoButtonAuthenticator` extends `SpnegoAuthenticator` and moves the challenge onto a
request whose retry is harmless, a `GET` of the flow's refresh URL (no `session_code`, no
`execution`):

| Request | What happens |
|---|---|
| first pass of the flow | the execution sits after the forms, so it is never reached; being unprocessed, it is listed in `authenticationSelections` (Keycloak drops executions that already reported *attempted*) |
| `POST` with `authenticationExecution=<this>` (button) | `AuthenticationProcessor.resetFlow()`, the `ALTERNATIVE` siblings on the way up to the top-level flow marked `ATTEMPTED` (so the next pass skips the forms), auth note `sit.spnego-button.requested=true`, `303` to `getRefreshUrl()` |
| `GET` refresh URL, note set | `401 Negotiate` with Keycloak's auto-submitting fallback form in the body |
| browser retry of that `GET` with `Authorization: Negotiate …` | built-in validation through the Kerberos user federation provider; a rejected ticket resets the flow back to the password form |
| any request with an `Authorization` header but without a prior click | header ignored, Kerberos stays on demand |
| no ticket: fallback form posts to this execution | `action()` resets the flow; the password form renders and the option is offered again |

Ticket validation, keytab handling and user lookup are untouched; the Kerberos settings live
in the LDAP/Kerberos user federation provider as before. The factory reports the `kerberos`
reference category like the built-in one and offers `ALTERNATIVE` and `DISABLED` only: the
button is always one choice among others.

Safety rules:

- A click only counts if the selection names this very execution.
- Only `ALTERNATIVE` executions are skipped (the alternatives of each `ALTERNATIVE` on the way
  to the top-level flow). `REQUIRED` and `CONDITIONAL` steps are never skipped and run as
  usual, e.g. a conditional OTP sub-flow after the first factor. An `ALTERNATIVE` on the way
  that sits next to a mandatory step (a placement Keycloak ignores anyway) refuses the click
  with a warning in the log.
- An `Authorization` header is only evaluated after the user clicked the button.

### Flow

```
Browser flow
├─ Cookie                        ALTERNATIVE
├─ Kerberos (built-in)           DISABLED
├─ Identity Provider Redirector  ALTERNATIVE
├─ Forms                         ALTERNATIVE
│  ├─ Username Password Form     REQUIRED
│  └─ …
└─ SIT: Kerberos (on demand)     ALTERNATIVE   ← after the forms, same level
```

The position matters in both directions. Placed *before* the forms, the execution runs on the
first pass, reports *attempted* and is no longer offered on the login page. Placed *after*
them, it is offered, and the button click takes care of being reached on the next pass by
skipping its siblings. Leave the built-in *Kerberos* execution `DISABLED` (or remove it).

### Step-up flow (bronze/silver)

```
Browser flow
├─ Cookie                        ALTERNATIVE
└─ Bronze/Silver                 ALTERNATIVE   (sub-flow)
   ├─ Bronze                     REQUIRED      (sub-flow)
   │  ├─ Username Password Form  ALTERNATIVE   (sit-auth-username-password-form, or a sub-flow)
   │  └─ SIT: Kerberos (on demand) ALTERNATIVE ← after the form
   └─ Silver                     CONDITIONAL   (sub-flow)
      ├─ <condition: requested ACR>
      └─ OTP Form                REQUIRED
```

The click skips the password form (and the cookie); silver is a later step and runs after
Kerberos as after the password.

### Only under a condition (e.g. internal network)

Keycloak has no "conditional alternative" requirement (proposed upstream in discussion
keycloak/keycloak#17152), hence a double wrapper:

```
Browser flow
├─ …
├─ Forms                         ALTERNATIVE
│  └─ …
└─ Kerberos                      ALTERNATIVE   (sub-flow, after the forms)
   └─ Kerberos intern            CONDITIONAL   (sub-flow)
      ├─ <condition>             REQUIRED
      └─ SIT: Kerberos (on demand) ALTERNATIVE
```

Both sub-flows are needed: Keycloak evaluates conditions only in a `CONDITIONAL` sub-flow, and
a `CONDITIONAL` sub-flow directly in the top-level flow would make Keycloak ignore all
top-level alternatives (cookie, forms, …). If the condition is false, the button is not
offered and a forged selection is rejected by Keycloak. The e2e test covers this placement
with a client-scope condition as stand-in.

### Theme

The login page gets the execution through `auth.authenticationSelections`; the only property
that identifies it is the authenticator id. A minimal `login.ftl` override adds one line, for
example right after the login `</form>`:

```ftl
<#include "sit-kerberos-button.ftl">
```

`sit-kerberos-button.ftl`:

```ftl
<#if auth?? && auth.authenticationSelections??>
  <#list auth.authenticationSelections as sel>
    <#if (sel.authenticationExecution.authenticator)! == "sit-auth-spnego-button">
      <form method="post" action="${url.loginAction}" class="sit-kerberos-form">
        <input type="hidden" name="authenticationExecution" value="${sel.authExecId}">
        <button type="submit"
                class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">
          ${msg("sit.kerberos.button", "Sign in with Windows")}
        </button>
      </form>
    </#if>
  </#list>
</#if>
```

`#kc-select-try-another-way-form` can be hidden with CSS if the button is the only alternative
that should be offered.

### Client side

The browser still has to be willing to send a ticket to the Keycloak host: Windows zone
*Local intranet* (or `AuthServerAllowlist` for Chrome/Edge, `network.negotiate-auth.trusted-uris`
for Firefox), SPN and keytab for `HTTP/<keycloak-host>` in the user's domain. A credential
prompt instead of a login means the browser refused to use SSPI for that host; a silent return
to the password form means it sent no ticket (check `chrome://net-export`, look for
`allows_default_credentials`).

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
KC_VERSION=26.8.1 ./build_jar.sh

# Or via environment / .env file
cp .env.sample .env   # edit KC_VERSION, VERSION, etc.
./build_jar.sh
```

Output: `dist/keycloak-extensions-sit-v<VERSION>-kc<KC_VERSION>.jar`

**Without Docker (plain Maven):**

```bash
mvn clean package -Dkeycloak.version=26.8.1
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
| 1.7.x | ≥ 26.8 (uses the IdP admin role mapping check introduced in 26.8.0) |
| 1.0 – 1.6 | ≥ 24 (tested against 26.x up to 26.7) |

Requires Java 17+.

### Automatic check against new Keycloak releases

`.github/workflows/keycloak-compat.yml` runs daily. When Maven Central has a final Keycloak
release newer than `keycloak.version` in `pom.xml`, it runs `ci/kc-compat/run-all.sh` and
opens an issue titled `[kc-compat] Keycloak <version> – compatibility check` with the result,
links to the upgrading guide and release notes, and everything about our superclasses (see below).
Each version is reported once. Delete the issue or start the workflow manually (optionally with
explicit versions) to check it again.

| Check | Fails when |
|---|---|
| Build the "old" jar against the baseline version | the baseline no longer builds |
| Build + unit tests against the new version | compilation or a test fails |
| Bytecode old vs. new | — (warns if the classes differ, i.e. the rebuilt jar should be rolled out) |
| Third-party libraries | — (warns on a minor/major bump of a library we import directly, e.g. webauthn4j) |
| API/linkage diff of every Keycloak type we use or extend | a referenced method/field/class is gone, an override no longer overrides, or a new abstract method appears; warns when an overridden method is no longer called from Keycloak's class hierarchy, or when a relevant class changed |
| Start Keycloak with the **old** jar | startup fails, a provider is not registered, configuring it via the admin API fails, the protocol mapper does not produce the expected claim, or the log contains `ERROR` lines |
| Start Keycloak with the **rebuilt** jar | same as above |
| Kerberos e2e (`ci/kerberos-e2e`) with the rebuilt jar | the on-demand Kerberos login no longer works as expected (flow-engine behaviour changed) |
| Login e2e (`ci/login-e2e`) with the rebuilt jar | `sit-auth-username-password-form` no longer behaves like the built-in form |

For every changed Keycloak class the report shows which of our classes are affected (including the
inheritance chain), the API changes as Java signatures, the source diff and the upstream commits
with links to their Keycloak PRs and issues. For our superclasses it additionally lists:

- the methods we override, whether they are unchanged and where Keycloak calls them from;
- methods newly added to them, where Keycloak itself calls them (e.g. new security checks its own
  subclasses adopt), the commit that introduced them, and that calling them pins the jar to the
  new version;
- types newly introduced in them, with constructors, methods and whether we can access them.

Keycloak is started from the official server distribution (`org.keycloak:keycloak-quarkus-dist`)
rather than the container image, so the check needs no Docker and runs locally the same way:

```bash
ci/kc-compat/run-all.sh                 # newest release vs. pom baseline
ci/kc-compat/run-all.sh 26.8.2 26.8.1   # explicit versions
OLD_JAR=dist/my.jar ci/kc-compat/run-all.sh   # use the jar that is actually deployed
```

Requires Java 21+, Maven, Python 3 and git (for the upstream commits, a partial fetch of a few MB
from github.com; the check still runs without it). The report ends up in `.kc-compat/report.md`. Add new
providers to `ci/kc-compat/expected-providers.txt`; the check fails if its count does not match
`META-INF/services`.

---

## License

Apache License 2.0
