package nrw.sit.keycloak.requiredaction;

import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnRegister;
import org.keycloak.models.KeycloakSession;

import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;

/**
 * Factory for {@link SitWebAuthnPasswordlessRegister} under its own provider ID.
 *
 * <p>The action appears in the admin console under <em>Authentication &rarr; Required actions</em>
 * as a separate entry next to the built-in one. Assign this instead of
 * {@code webauthn-register-passwordless} to the users who should be able to register even
 * without attestation.</p>
 *
 * <p>Note that the "Add passkey" button in the account console calls the built-in provider ID,
 * so the self-service path keeps using the strict verifier list. Use
 * {@link SitWebAuthnPasswordlessRegisterOverrideFactory} if that path needs to be covered too.</p>
 *
 * <p>Inherited from {@code WebAuthnRegisterFactory}: the truststore-backed certificate path
 * verifier and the {@code WEB_AUTHN} feature check.</p>
 */
public class SitWebAuthnPasswordlessRegisterFactory extends WebAuthnPasswordlessRegisterFactory {

    public static final String PROVIDER_ID = "sit-webauthn-register-passwordless";

    @Override
    protected WebAuthnRegister createProvider(KeycloakSession session,
                                              CertPathTrustworthinessVerifier trustVerifier) {
        return new SitWebAuthnPasswordlessRegister(session, trustVerifier);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "SIT: Webauthn Register Passwordless (attestation optional)";
    }
}
