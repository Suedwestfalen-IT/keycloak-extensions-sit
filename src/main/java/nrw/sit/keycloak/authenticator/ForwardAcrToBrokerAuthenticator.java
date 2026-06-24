package nrw.sit.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;

/**
 * Keycloak Authenticator (SPI).
 *
 * Bridges the gap (Keycloak #42625) where a broker realm does NOT forward a
 * client's configured ACR (minimum.acr.value / default.acr.values) to the
 * upstream IdP - only an explicit acr_values request parameter is forwarded.
 *
 * Placed BEFORE the Identity Provider Redirector in a broker realm's browser
 * flow, this authenticator reads the requesting client's configured ACR and
 * writes it into the "acr_values" client note. The standard redirector then
 * forwards that value to the upstream IdP (forwardParameters defaults to
 * acr_values), so the upstream realm enforces the requested step-up level.
 *
 * Because the value is taken from the client configuration (server-side) and
 * not from a browser-supplied request parameter, it cannot be tampered with
 * or lowered by the end user.
 *
 * Note: this only solves the forward/enforcement direction. The ACR claim in
 * the token issued by THIS realm is not affected (Keycloak #25335).
 */
public class ForwardAcrToBrokerAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(ForwardAcrToBrokerAuthenticator.class);

    static final ForwardAcrToBrokerAuthenticator SINGLETON = new ForwardAcrToBrokerAuthenticator();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ClientModel client = authSession.getClient();

        String acr = resolveClientAcr(client);
        if (acr != null && !acr.isEmpty()) {
            // The redirector forwards this note as acr_values to the upstream IdP.
            authSession.setClientNote(OAuth2Constants.ACR_VALUES, acr);
            LOG.debugf("Forwarding acr_values=%s to broker for client %s",
                    acr, client.getClientId());
        } else {
            LOG.tracef("No client ACR configured for %s - nothing to forward",
                    client.getClientId());
        }

        // Passive step: never blocks, just continues the flow.
        context.success();
    }

    /**
     * Resolve the ACR to forward from the client configuration.
     * minimum.acr.value (the enforced floor) takes precedence; otherwise the
     * first configured default.acr.values entry is used.
     */
    private String resolveClientAcr(ClientModel client) {
        String minimum = AcrUtils.getMinimumAcrValue(client);
        if (minimum != null && !minimum.isEmpty()) {
            return minimum;
        }
        List<String> defaults = AcrUtils.getDefaultAcrValues(client);
        if (defaults != null && !defaults.isEmpty()) {
            return defaults.get(0);
        }
        return null;
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
