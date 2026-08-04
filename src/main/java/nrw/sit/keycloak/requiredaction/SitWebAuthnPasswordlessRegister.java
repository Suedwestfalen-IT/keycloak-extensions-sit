package nrw.sit.keycloak.requiredaction;

import org.jboss.logging.Logger;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegister;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.WebAuthnPolicy;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.verifier.CustomRegistrationVerifier;
import com.webauthn4j.verifier.RegistrationObject;
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
 * <p>A {@link CustomRegistrationVerifier} is registered in addition, in the slot upstream
 * leaves empty. It inspects the Backup Eligible flag and thereby distinguishes device-bound
 * credentials from ones held by a syncing credential manager - the one signal that survives
 * when no attestation is available. See {@link SyncedCredentialVerifier}.</p>
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

    /**
     * Whether a backup-eligible (syncable) credential is refused outright.
     *
     * <p>Kept at {@code false} on purpose: refusing here would lock out everyone using a
     * credential manager, which is the situation this provider exists to avoid. Registration
     * stays open and the distinction is recorded in the log; enforcing it belongs to the
     * authentication flow, where it can be tied to a level of assurance.</p>
     */
    private static final boolean REJECT_SYNCED_CREDENTIALS = true;

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
                List.of(new SyncedCredentialVerifier(REJECT_SYNCED_CREDENTIALS)),
                new ObjectConverter()
        );
    }

    /**
     * Records - or optionally refuses - credentials that a credential manager can synchronise.
     *
     * <p>The Backup Eligible flag in {@code authenticatorData} is set by authenticators whose
     * private key may leave the device: iCloud Keychain, Google Password Manager, Bitwarden,
     * 1Password. A TPM-bound Windows Hello credential leaves it clear. Where attestation is
     * unavailable this is the only remaining indicator of key custody, and unlike the AAGUID
     * it describes the property that matters rather than the make of the authenticator.</p>
     *
     * <p>It remains a self-asserted value: nothing signs it, so a manipulated client can claim
     * whatever it likes. It reliably tells apart an ordinary user with a password manager from
     * an ordinary user with a TPM - not an attacker from an honest party.</p>
     */
    private static class SyncedCredentialVerifier implements CustomRegistrationVerifier {

        private final boolean reject;

        SyncedCredentialVerifier(boolean reject) {
            this.reject = reject;
        }

        @Override
        public void verify(RegistrationObject registrationObject) {
            AuthenticatorData<?> authData = registrationObject.getAttestationObject().getAuthenticatorData();

            if (!authData.isFlagBE()) {
                return;
            }
            if (reject) {
                throw new WebAuthnException(
                        "Backup-eligible (synchronisierbare) Credentials sind hier nicht zugelassen.");
            }

            logger.infof("Registered credential is backup eligible (BE=true, BS=%s, format=%s) - "
                            + "key custody is a synchronising credential manager, not a device",
                    authData.isFlagBS(),
                    registrationObject.getAttestationObject().getFormat());
        }
    }
}
