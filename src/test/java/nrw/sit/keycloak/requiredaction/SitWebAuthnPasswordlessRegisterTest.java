package nrw.sit.keycloak.requiredaction;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.WebAuthnPolicy;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SitWebAuthnPasswordlessRegisterTest {

    private final SitWebAuthnPasswordlessRegister action = new SitWebAuthnPasswordlessRegister(
            mock(KeycloakSession.class), mock(CertPathTrustworthinessVerifier.class));

    // ── registration manager ─────────────────────────────────────────────────

    @Test
    void noneVerifierIsRegisteredEvenWithDirectAttestationPreference() throws Exception {
        WebAuthnRegistrationManager manager = action.createWebAuthnRegistrationManager(policy("direct"));

        assertTrue(contains(manager, NoneAttestationStatementVerifier.class), "none verifier missing");
    }

    @Test
    void strictVerifiersAreKeptNextToTheNoneVerifier() throws Exception {
        WebAuthnRegistrationManager manager = action.createWebAuthnRegistrationManager(policy("direct"));

        assertTrue(contains(manager, PackedAttestationStatementVerifier.class), "packed verifier missing");
        assertTrue(contains(manager, TPMAttestationStatementVerifier.class), "tpm verifier missing");
    }

    @Test
    void syncedCredentialVerifierIsRegistered() throws Exception {
        WebAuthnRegistrationManager manager = action.createWebAuthnRegistrationManager(policy("none"));

        assertTrue(contains(manager, SitWebAuthnPasswordlessRegister.SyncedCredentialVerifier.class),
                "custom registration verifier missing");
    }

    @Test
    void managerIsStillCreatedWhenAaguidsAreConfigured() {
        WebAuthnPolicy policy = policy("direct");
        policy.setAcceptableAaguids(List.of("00000000-0000-0000-0000-000000000001"));

        assertDoesNotThrow(() -> action.createWebAuthnRegistrationManager(policy));
    }

    // ── SyncedCredentialVerifier ─────────────────────────────────────────────

    @Test
    void deviceBoundCredentialPassesRegardlessOfRejectFlag() {
        RegistrationObject registration = registration(false);

        assertDoesNotThrow(() -> new SitWebAuthnPasswordlessRegister.SyncedCredentialVerifier(true).verify(registration));
        assertDoesNotThrow(() -> new SitWebAuthnPasswordlessRegister.SyncedCredentialVerifier(false).verify(registration));
    }

    @Test
    void backupEligibleCredentialIsRejectedWhenConfigured() {
        RegistrationObject registration = registration(true);

        assertThrows(WebAuthnException.class,
                () -> new SitWebAuthnPasswordlessRegister.SyncedCredentialVerifier(true).verify(registration));
    }

    @Test
    void backupEligibleCredentialIsOnlyLoggedWhenNotConfiguredToReject() {
        RegistrationObject registration = registration(true);

        assertDoesNotThrow(() -> new SitWebAuthnPasswordlessRegister.SyncedCredentialVerifier(false).verify(registration));
    }

    // ── factory ──────────────────────────────────────────────────────────────

    @Test
    void factoryCreatesTheLenientActionUnderItsOwnId() {
        SitWebAuthnPasswordlessRegisterFactory factory = new SitWebAuthnPasswordlessRegisterFactory();

        assertEquals(SitWebAuthnPasswordlessRegisterFactory.PROVIDER_ID, factory.getId());
        assertNotEquals(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID, factory.getId());
        assertTrue(factory.createProvider(mock(KeycloakSession.class), mock(CertPathTrustworthinessVerifier.class))
                instanceof SitWebAuthnPasswordlessRegister);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static WebAuthnPolicy policy(String attestationConveyancePreference) {
        WebAuthnPolicy policy = new WebAuthnPolicy();
        policy.setAttestationConveyancePreference(attestationConveyancePreference);
        policy.setAcceptableAaguids(List.of());
        return policy;
    }

    private static RegistrationObject registration(boolean backupEligible) {
        AuthenticatorData<?> authData = mock(AuthenticatorData.class);
        when(authData.isFlagBE()).thenReturn(backupEligible);
        when(authData.isFlagBS()).thenReturn(backupEligible);
        AttestationObject attestationObject = mock(AttestationObject.class);
        when(attestationObject.getAuthenticatorData()).thenAnswer(inv -> authData);
        when(attestationObject.getFormat()).thenReturn("none");
        RegistrationObject registration = mock(RegistrationObject.class);
        when(registration.getAttestationObject()).thenReturn(attestationObject);
        return registration;
    }

    /**
     * webauthn4j does not expose its verifier lists, so walk the object graph of the manager
     * (only through webauthn4j classes and collections) and look for an instance of the type.
     */
    private static boolean contains(Object root, Class<?> type) throws IllegalAccessException {
        return contains(root, type, new IdentityHashMap<>(), 0);
    }

    private static boolean contains(Object obj, Class<?> type, Map<Object, Boolean> seen, int depth)
            throws IllegalAccessException {
        if (obj == null || depth > 6 || seen.put(obj, Boolean.TRUE) != null) return false;
        if (type.isInstance(obj)) return true;
        if (obj instanceof Iterable) {
            for (Object element : (Iterable<?>) obj) {
                if (contains(element, type, seen, depth + 1)) return true;
            }
            return false;
        }
        if (!obj.getClass().getName().startsWith("com.webauthn4j")) return false;
        for (Class<?> c = obj.getClass(); c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())) continue;
                field.setAccessible(true);
                if (contains(field.get(obj), type, seen, depth + 1)) return true;
            }
        }
        return false;
    }
}
