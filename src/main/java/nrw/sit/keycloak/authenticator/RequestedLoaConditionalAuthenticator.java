package nrw.sit.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

/**
 * Conditional authenticator that matches on the LOA level REQUESTED by the
 * client - independent of what has already been satisfied.
 *
 * The built-in "Condition - Level of Authentication" matches on
 * "requested >= configured AND not yet satisfied", which is cumulative and
 * order-sensitive. This condition instead looks only at the requested level
 * and supports an exact match (default), a minimum or a maximum. That makes
 * step-up tiers mutually exclusive by requested level, e.g. a Gold tier that
 * fires ONLY when Gold (3) is requested so it can offer Passkey alone, while
 * Silver/Bronze tiers stay untouched.
 *
 * Read-only: it does NOT update the session LOA. Pair it in the same subflow
 * with the built-in conditional-level-of-authentication, which sets the LOA
 * (acr) on success.
 */
public class RequestedLoaConditionalAuthenticator implements ConditionalAuthenticator {

    private static final Logger LOG = Logger.getLogger(RequestedLoaConditionalAuthenticator.class);

    static final RequestedLoaConditionalAuthenticator SINGLETON =
            new RequestedLoaConditionalAuthenticator();

    static final String CONF_LEVEL = "loa-condition-level";
    static final String CONF_OPERATOR = "operator";
    static final String OP_EQUALS = "equals";
    static final String OP_MINIMUM = "minimum";
    static final String OP_MAXIMUM = "maximum";

    private static final int NO_CONFIG = Integer.MIN_VALUE;

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        AcrStore acrStore = new AcrStore(context.getSession(), authSession);
        int requestedLoa = acrStore.getRequestedLevelOfAuthentication(context.getTopLevelFlow());

        int configured = getConfiguredLevel(context);
        if (configured == NO_CONFIG) {
            LOG.warn("RequestedLoaCondition without a configured level - evaluating to false");
            return false;
        }
        String operator = getOperator(context);

        boolean result;
        switch (operator) {
            case OP_MINIMUM:
                result = requestedLoa >= configured;
                break;
            case OP_MAXIMUM:
                result = requestedLoa <= configured;
                break;
            case OP_EQUALS:
            default:
                result = requestedLoa == configured;
                break;
        }
        LOG.tracef("RequestedLoaCondition: requested=%d %s %d -> %b",
                requestedLoa, operator, configured, result);
        return result;
    }

    private int getConfiguredLevel(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        if (cfg == null || cfg.getConfig() == null) {
            return NO_CONFIG;
        }
        Map<String, String> config = cfg.getConfig();
        String raw = config.get(CONF_LEVEL);
        if (raw == null || raw.trim().isEmpty()) {
            return NO_CONFIG;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            LOG.warnf("RequestedLoaCondition: level '%s' is not numeric", raw);
            return NO_CONFIG;
        }
    }

    private String getOperator(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        if (cfg == null || cfg.getConfig() == null) {
            return OP_EQUALS;
        }
        String op = cfg.getConfig().get(CONF_OPERATOR);
        return (op == null || op.trim().isEmpty()) ? OP_EQUALS : op.trim();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No interactive step.
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions.
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
