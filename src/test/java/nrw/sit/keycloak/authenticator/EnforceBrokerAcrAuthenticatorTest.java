package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The full post-broker path needs a deserialisable brokered context, which in turn
 * needs a registered identity provider and its factory. That is integration territory,
 * so this test covers the "wrong flow" guard end to end and the decision helpers directly.
 */
class EnforceBrokerAcrAuthenticatorTest {

    private static final Map<String, Integer> LOA_MAP = Map.of("bronze", 1, "silver", 2, "gold", 3);

    private final EnforceBrokerAcrAuthenticator authenticator = EnforceBrokerAcrAuthenticator.SINGLETON;
    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final ClientModel client = mock(ClientModel.class);
    private final Map<String, String> clientAttributes = new HashMap<>();

    @BeforeEach
    void setUp() {
        when(context.getSession()).thenReturn(mock(KeycloakSession.class));
        when(context.getRealm()).thenReturn(mock(RealmModel.class));
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(client.getClientId()).thenReturn("app");
        when(client.getAttribute(anyString())).thenAnswer(inv -> clientAttributes.get(inv.<String>getArgument(0)));
        when(client.getAttributes()).thenReturn(clientAttributes);
    }

    // ── authenticate ─────────────────────────────────────────────────────────

    @Test
    void succeedsWithoutBlockingWhenNoBrokeredContextIsPresent() {
        when(authSession.getAuthNote(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT)).thenReturn(null);

        authenticator.authenticate(context);

        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void actionIsANoOpThatSucceeds() {
        authenticator.action(context);

        verify(context).success();
    }

    // ── acrToLevel ───────────────────────────────────────────────────────────

    @Test
    void acrIsMappedThroughTheRealmLoaMap() {
        assertEquals(3, authenticator.acrToLevel("gold", LOA_MAP));
        assertEquals(1, authenticator.acrToLevel("bronze", LOA_MAP));
    }

    @Test
    void numericAcrIsUsedAsLevelWhenNotInTheMap() {
        assertEquals(2, authenticator.acrToLevel("2", LOA_MAP));
        assertEquals(2, authenticator.acrToLevel(" 2 ", LOA_MAP));
    }

    @Test
    void unknownOrMissingAcrIsLevelZero() {
        assertEquals(0, authenticator.acrToLevel("platinum", LOA_MAP));
        assertEquals(0, authenticator.acrToLevel(null, LOA_MAP));
        assertEquals(0, authenticator.acrToLevel("", LOA_MAP));
    }

    // ── resolveRequiredLevel ─────────────────────────────────────────────────

    @Test
    void requiredLevelComesFromMinimumAcrFirst() {
        clientAttributes.put(Constants.MINIMUM_ACR_VALUE, "gold");
        clientAttributes.put(Constants.DEFAULT_ACR_VALUES, "bronze");

        assertEquals(3, authenticator.resolveRequiredLevel(client, LOA_MAP));
    }

    @Test
    void requiredLevelFallsBackToFirstDefaultAcrValue() {
        clientAttributes.put(Constants.DEFAULT_ACR_VALUES, "silver##gold");

        assertEquals(2, authenticator.resolveRequiredLevel(client, LOA_MAP));
    }

    @Test
    void requiredLevelIsZeroWithoutClientConfiguration() {
        assertEquals(0, authenticator.resolveRequiredLevel(client, LOA_MAP));
    }

    // ── resolveUpstreamAcr ───────────────────────────────────────────────────

    @Test
    void readsAcrFromValidatedIdToken() {
        IDToken token = new IDToken();
        token.setAcr("gold");

        assertEquals("gold", authenticator.resolveUpstreamAcr(contextWith(token)));
    }

    @Test
    void readsAcrFromOtherClaimsOfAPlainJwt() {
        JsonWebToken token = new JsonWebToken();
        token.setOtherClaims(IDToken.ACR, "silver");

        assertEquals("silver", authenticator.resolveUpstreamAcr(contextWith(token)));
    }

    @Test
    void missingOrForeignTokenYieldsNoAcr() {
        assertNull(authenticator.resolveUpstreamAcr(contextWith(null)));
        assertNull(authenticator.resolveUpstreamAcr(contextWith("not-a-token")));
        assertNull(authenticator.resolveUpstreamAcr(contextWith(new IDToken())));
    }

    // ── isEnforce ────────────────────────────────────────────────────────────

    @Test
    void enforceIsOnByDefault() {
        when(context.getAuthenticatorConfig()).thenReturn(null);
        assertTrue(authenticator.isEnforce(context));

        when(context.getAuthenticatorConfig()).thenReturn(config(null));
        assertTrue(authenticator.isEnforce(context));

        when(context.getAuthenticatorConfig()).thenReturn(config(Map.of()));
        assertTrue(authenticator.isEnforce(context));
    }

    @Test
    void enforceFollowsExplicitConfiguration() {
        when(context.getAuthenticatorConfig()).thenReturn(config(Map.of(EnforceBrokerAcrAuthenticator.CONFIG_ENFORCE, "false")));
        assertFalse(authenticator.isEnforce(context));

        when(context.getAuthenticatorConfig()).thenReturn(config(Map.of(EnforceBrokerAcrAuthenticator.CONFIG_ENFORCE, "true")));
        assertTrue(authenticator.isEnforce(context));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static BrokeredIdentityContext contextWith(Object validatedIdToken) {
        IdentityProviderModel idp = new IdentityProviderModel();
        idp.setAlias("upstream");
        idp.setEnabled(true);
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("broker-user-id", idp);
        if (validatedIdToken != null) {
            ctx.getContextData().put(OIDCIdentityProvider.VALIDATED_ID_TOKEN, validatedIdToken);
        }
        return ctx;
    }

    private static AuthenticatorConfigModel config(Map<String, String> values) {
        AuthenticatorConfigModel cfg = new AuthenticatorConfigModel();
        cfg.setConfig(values);
        return cfg;
    }
}
