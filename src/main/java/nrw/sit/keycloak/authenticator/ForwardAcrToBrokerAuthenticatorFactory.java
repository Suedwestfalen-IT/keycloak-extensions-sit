package nrw.sit.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

/**
 * Factory for {@link ForwardAcrToBrokerAuthenticator}.
 *
 * Add this authenticator as REQUIRED in a broker realm's browser flow,
 * before the Identity Provider Redirector.
 */
public class ForwardAcrToBrokerAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sit-forward-acr-to-broker";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.DISABLED,
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return ForwardAcrToBrokerAuthenticator.SINGLETON;
    }

    @Override
    public String getDisplayType() {
        return "SIT: Forward Client ACR to Broker";
    }

    @Override
    public String getReferenceCategory() {
        return "acr";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Forwards the requesting client's configured ACR "
                + "(minimum.acr.value / default.acr.values) to the upstream IdP "
                + "by setting the acr_values client note. Place before the "
                + "Identity Provider Redirector in a broker realm's browser flow.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do.
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
