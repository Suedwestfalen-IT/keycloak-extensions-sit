package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RequestedLoaConditionalAuthenticatorTest {

    private final RequestedLoaConditionalAuthenticator condition = RequestedLoaConditionalAuthenticator.SINGLETON;
    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);

    @BeforeEach
    void setUp() {
        when(context.getSession()).thenReturn(mock(KeycloakSession.class));
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getTopLevelFlow()).thenReturn(mock(AuthenticationFlowModel.class));
        requested(2);
    }

    @Test
    void equalsMatchesExactlyTheRequestedLevel() {
        configure("2", RequestedLoaConditionalAuthenticator.OP_EQUALS);
        assertTrue(condition.matchCondition(context));

        configure("3", RequestedLoaConditionalAuthenticator.OP_EQUALS);
        assertFalse(condition.matchCondition(context));

        configure("1", RequestedLoaConditionalAuthenticator.OP_EQUALS);
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void minimumMatchesWhenRequestedIsAtLeastConfigured() {
        configure("1", RequestedLoaConditionalAuthenticator.OP_MINIMUM);
        assertTrue(condition.matchCondition(context));

        configure("2", RequestedLoaConditionalAuthenticator.OP_MINIMUM);
        assertTrue(condition.matchCondition(context));

        configure("3", RequestedLoaConditionalAuthenticator.OP_MINIMUM);
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void maximumMatchesWhenRequestedIsAtMostConfigured() {
        configure("3", RequestedLoaConditionalAuthenticator.OP_MAXIMUM);
        assertTrue(condition.matchCondition(context));

        configure("2", RequestedLoaConditionalAuthenticator.OP_MAXIMUM);
        assertTrue(condition.matchCondition(context));

        configure("1", RequestedLoaConditionalAuthenticator.OP_MAXIMUM);
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void missingOrBlankOperatorMeansEquals() {
        configure("2", null);
        assertTrue(condition.matchCondition(context));

        configure("2", "  ");
        assertTrue(condition.matchCondition(context));

        configure("1", null);
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void unknownOperatorFallsBackToEquals() {
        configure("2", "between");
        assertTrue(condition.matchCondition(context));

        configure("1", "between");
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void levelWithSurroundingWhitespaceIsAccepted() {
        configure(" 2 ", RequestedLoaConditionalAuthenticator.OP_EQUALS);
        assertTrue(condition.matchCondition(context));
    }

    @Test
    void withoutConfiguredLevelTheConditionIsFalse() {
        when(context.getAuthenticatorConfig()).thenReturn(null);
        assertFalse(condition.matchCondition(context));

        configure(null, RequestedLoaConditionalAuthenticator.OP_MINIMUM);
        assertFalse(condition.matchCondition(context));

        configure("", RequestedLoaConditionalAuthenticator.OP_MINIMUM);
        assertFalse(condition.matchCondition(context));
    }

    @Test
    void nonNumericLevelMakesTheConditionFalse() {
        configure("gold", RequestedLoaConditionalAuthenticator.OP_MINIMUM);
        assertFalse(condition.matchCondition(context));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private void requested(int level) {
        when(authSession.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION))
                .thenReturn(String.valueOf(level));
    }

    private void configure(String level, String operator) {
        Map<String, String> values = new HashMap<>();
        if (level != null) values.put(RequestedLoaConditionalAuthenticator.CONF_LEVEL, level);
        if (operator != null) values.put(RequestedLoaConditionalAuthenticator.CONF_OPERATOR, operator);
        AuthenticatorConfigModel cfg = new AuthenticatorConfigModel();
        cfg.setConfig(values);
        when(context.getAuthenticatorConfig()).thenReturn(cfg);
    }
}
