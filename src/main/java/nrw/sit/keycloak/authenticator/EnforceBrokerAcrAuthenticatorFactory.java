package nrw.sit.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory for {@link EnforceBrokerAcrAuthenticator}.
 *
 * Add as REQUIRED in the broker realm's Post Broker Login flow.
 */
public class EnforceBrokerAcrAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sit-enforce-broker-acr";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.DISABLED,
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        ProviderConfigProperty enforce = new ProviderConfigProperty();
        enforce.setName(EnforceBrokerAcrAuthenticator.CONFIG_ENFORCE);
        enforce.setLabel("Enforce minimum level");
        enforce.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        enforce.setDefaultValue("true");
        enforce.setHelpText("Reject the login if the level of authentication reached at the "
                + "upstream IdP is below the level required by the requesting client "
                + "(minimum.acr.value / default.acr.values). If disabled, the upstream level is "
                + "only adopted into this realm's session without rejecting.");
        CONFIG_PROPERTIES = List.of(enforce);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return EnforceBrokerAcrAuthenticator.SINGLETON;
    }

    @Override
    public String getDisplayType() {
        return "SIT: Enforce Broker ACR (Post-Broker)";
    }

    @Override
    public String getReferenceCategory() {
        return "acr";
    }

    @Override
    public boolean isConfigurable() {
        return true;
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
        return "Post-Broker-Login: adopts the ACR reached at the upstream IdP into this realm's "
                + "session and (optionally) rejects logins that did not reach the client's required "
                + "level. Blocks acr_values downgrade via the browser URL.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void init(Config.Scope config) {
        // No global configuration.
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
