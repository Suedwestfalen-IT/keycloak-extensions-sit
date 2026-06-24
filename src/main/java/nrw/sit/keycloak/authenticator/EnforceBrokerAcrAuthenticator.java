package nrw.sit.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;
import java.util.Map;

/**
 * Post-Broker-Login Authenticator (SPI).
 *
 * Closes the response side of the broker step-up gap (Keycloak #25335):
 * after returning from the upstream IdP, it reads the ACR actually reached
 * upstream (from the validated upstream ID token), maps it to a level via this
 * realm's acr.loa.map, and records it on the broker session (AcrStore) so the
 * issued token reflects the real level.
 *
 * When "enforce" is enabled (default), it additionally compares the reached
 * level against the level the requesting client requires
 * (minimum.acr.value / default.acr.values) and REJECTS the login if it is
 * lower. This blocks acr_values downgrade attempts via the browser URL,
 * because the decision is made server-side from the upstream token, not from
 * the (user-controllable) request parameter.
 *
 * MUST run in the broker realm's Post Broker Login flow. The brokered context
 * is read from {@link PostBrokerLoginConstants#PBL_BROKERED_IDENTITY_CONTEXT}
 * (the post-broker note - NOT the first-broker-login note). Pairs with
 * {@link ForwardAcrToBrokerAuthenticator}.
 */
public class EnforceBrokerAcrAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(EnforceBrokerAcrAuthenticator.class);

    static final EnforceBrokerAcrAuthenticator SINGLETON = new EnforceBrokerAcrAuthenticator();

    static final String CONFIG_ENFORCE = "enforce";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                        authSession, PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT);
        if (serializedCtx == null) {
            // Not a post-broker login (authenticator placed in the wrong flow).
            // Cannot evaluate - do not break the login.
            LOG.warn("No brokered context found - this authenticator must run in the "
                    + "Post Broker Login flow. Skipping ACR enforcement.");
            context.success();
            return;
        }
        BrokeredIdentityContext brokerContext = serializedCtx.deserialize(session, authSession);

        ClientModel client = authSession.getClient();
        Map<String, Integer> loaMap = AcrUtils.getAcrLoaMap(realm);

        int requiredLevel = resolveRequiredLevel(client, loaMap);
        String upstreamAcr = resolveUpstreamAcr(brokerContext);
        int achievedLevel = acrToLevel(upstreamAcr, loaMap);

        AcrStore acrStore = new AcrStore(session, authSession);

        if (achievedLevel >= requiredLevel) {
            acrStore.setLevelAuthenticated(achievedLevel);
            LOG.debugf("Broker ACR ok for client %s: required %d, upstream reached %d (acr=%s)",
                    client.getClientId(), requiredLevel, achievedLevel, upstreamAcr);
            context.success();
            return;
        }

        if (isEnforce(context)) {
            LOG.warnf("Broker ACR downgrade blocked for client %s: required level %d, "
                            + "upstream only reached %d (acr=%s)",
                    client.getClientId(), requiredLevel, achievedLevel, upstreamAcr);
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        } else {
            acrStore.setLevelAuthenticated(achievedLevel);
            LOG.debugf("Broker ACR below required for client %s (required %d, reached %d) "
                            + "but enforcement disabled - adopting level only",
                    client.getClientId(), requiredLevel, achievedLevel);
            context.success();
        }
    }

    /**
     * Level required by the requesting client: minimum.acr.value takes
     * precedence, otherwise the first default.acr.values entry. 0 if none.
     */
    private int resolveRequiredLevel(ClientModel client, Map<String, Integer> loaMap) {
        String required = AcrUtils.getMinimumAcrValue(client);
        if (required == null || required.isEmpty()) {
            List<String> defaults = AcrUtils.getDefaultAcrValues(client);
            required = (defaults == null || defaults.isEmpty()) ? null : defaults.get(0);
        }
        return acrToLevel(required, loaMap);
    }

    /** Reads the acr claim from the validated upstream ID token, if present. */
    private String resolveUpstreamAcr(BrokeredIdentityContext brokerContext) {
        Object tokenObj = brokerContext.getContextData().get(OIDCIdentityProvider.VALIDATED_ID_TOKEN);
        if (!(tokenObj instanceof JsonWebToken)) {
            return null;
        }
        JsonWebToken token = (JsonWebToken) tokenObj;
        if (token instanceof IDToken) {
            String acr = ((IDToken) token).getAcr();
            if (acr != null && !acr.isEmpty()) {
                return acr;
            }
        }
        Object acrClaim = token.getOtherClaims().get(IDToken.ACR);
        return acrClaim == null ? null : acrClaim.toString();
    }

    /** Maps an ACR value to a numeric level via the realm map, with numeric fallback. */
    private int acrToLevel(String acr, Map<String, Integer> loaMap) {
        if (acr == null || acr.isEmpty()) {
            return 0;
        }
        Integer mapped = loaMap.get(acr);
        if (mapped != null) {
            return mapped;
        }
        try {
            return Integer.parseInt(acr.trim());
        } catch (NumberFormatException e) {
            LOG.warnf("ACR '%s' cannot be mapped to a level (not in acr.loa.map, not numeric)", acr);
            return 0;
        }
    }

    private boolean isEnforce(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        if (cfg == null || cfg.getConfig() == null) {
            return true; // secure by default
        }
        String value = cfg.getConfig().get(CONFIG_ENFORCE);
        return value == null || Boolean.parseBoolean(value);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No interactive step.
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
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
