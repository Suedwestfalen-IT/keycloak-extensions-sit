package nrw.sit.keycloak.requiredaction;

import org.jboss.logging.Logger;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegister;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.WebAuthnPolicy;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Passwordless WebAuthn registration that accepts a missing attestation statement.
 *
 * <p>Keycloak's {@code WebAuthnRegister#createWebAuthnRegistrationManager} registers the
 * {@code NoneAttestationStatementVerifier} only when the realm's attestation conveyance
 * preference is {@code none} or unset. With {@code direct} or {@code indirect} the verifier
 * list is strict, and a client that returns {@code fmt: none} makes webauthn4j throw
 * <em>"AttestationVerifier is not configured to handle the supplied AttestationStatement
 * format 'none'"</em> - the registration fails.</p>
 *
 * <p>That is a real problem for platform authenticators: Windows Hello only produces a
 * {@code tpm} statement when the machine can obtain an AIK certificate from Microsoft's
 * cloud CA. On a device where that fails, the credential itself is perfectly sound - it sits
 * in the TPM, is device-bound and user-verified - but carries no attestation statement.</p>
 *
 * <p>This subclass keeps the full strict verifier list <em>and</em> adds the none verifier.
 * Attestation is therefore still parsed and cryptographically verified wherever an
 * authenticator supplies it, including certificate path validation against the truststore,
 * while a missing statement no longer aborts the ceremony. The realm policy can stay on
 * {@code direct}, which is what keeps the real AAGUID in the response - with {@code none}
 * the browser replaces it with all zeroes.</p>
 *
 * <p><strong>Known limitation:</strong> if the WebAuthn policy defines acceptable AAGUIDs,
 * Keycloak rejects {@code fmt: none} in {@code checkAcceptedAuthenticator}, a private method
 * that runs after verification and cannot be overridden here. Leave the AAGUID list empty
 * when using this provider.</p>
 *
 * <p>Registered credentials are indistinguishable from ones created by the built-in action:
 * same credential type, same provider, same database format. Removing this JAR does not
 * invalidate them, and authentication never touches attestation at all.</p>
 */
public class SitWebAuthnPasswordlessRegister extends WebAuthnPasswordlessRegister {

    private static final Logger logger = Logger.getLogger(SitWebAuthnPasswordlessRegister.class);

    /** {@code WebAuthnRegister} keeps its own copy private, so we hold a second reference. */
    private final CertPathTrustworthinessVerifier certPathTrustVerifier;

    public SitWebAuthnPasswordlessRegister(KeycloakSession session,
                                           CertPathTrustworthinessVerifier certPathTrustVerifier) {
        super(session, certPathTrustVerifier);
        this.certPathTrustVerifier = certPathTrustVerifier;
    }

    /**
     * Mirrors the upstream verifier list but always includes the none verifier.
     */
    @Override
    protected WebAuthnRegistrationManager createWebAuthnRegistrationManager(WebAuthnPolicy policy) {
        List<AttestationStatementVerifier> verifiers = new ArrayList<>(6);
        verifiers.add(new NoneAttestationStatementVerifier());
        verifiers.add(new PackedAttestationStatementVerifier());
        verifiers.add(new TPMAttestationStatementVerifier());
        verifiers.add(new AndroidKeyAttestationStatementVerifier());
        verifiers.add(new AndroidSafetyNetAttestationStatementVerifier());
        verifiers.add(new FIDOU2FAttestationStatementVerifier());

        DefaultSelfAttestationTrustworthinessVerifier selfAttestationVerifier =
                new DefaultSelfAttestationTrustworthinessVerifier();
        final List<String> acceptableAaguids = policy.getAcceptableAaguids();
        // self attestation should be disabled to be sure the AAGUID can be trusted
        selfAttestationVerifier.setSelfAttestationAllowed(acceptableAaguids == null || acceptableAaguids.isEmpty());

        if (acceptableAaguids != null && !acceptableAaguids.isEmpty()) {
            logger.warnf("WebAuthn policy defines %d acceptable AAGUID(s). Keycloak rejects "
                            + "attestation format 'none' whenever that list is non-empty, so this provider "
                            + "cannot tolerate missing attestation. Clear the list to make it effective.",
                    acceptableAaguids.size());
        }

        logger.debugf("Creating lenient WebAuthnRegistrationManager (attestation preference '%s', "
                        + "none verifier always registered)",
                policy.getAttestationConveyancePreference());

        return new WebAuthnRegistrationManager(
                verifiers,
                certPathTrustVerifier,
                selfAttestationVerifier,
                Collections.emptyList(), // Custom Registration Verifier is not supported
                new ObjectConverter()
        );
    }
}
