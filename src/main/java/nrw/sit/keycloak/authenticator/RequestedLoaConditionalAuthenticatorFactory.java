package nrw.sit.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * Factory for {@link RequestedLoaConditionalAuthenticator}.
 */
public class RequestedLoaConditionalAuthenticatorFactory
        implements ConditionalAuthenticatorFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "sit-conditional-requested-loa";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.DISABLED,
    };

    private static final List<ProviderConfigProperty> CONFIG = ProviderConfigurationBuilder.create()
            .property()
            .name(RequestedLoaConditionalAuthenticator.CONF_LEVEL)
            .label("Requested LOA level")
            .helpText("Numeric level of authentication to compare the REQUESTED level against "
                    + "(e.g. 1=bronze, 2=silver, 3=gold per the realm's acr.loa.map).")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(RequestedLoaConditionalAuthenticator.CONF_OPERATOR)
            .label("Comparison")
            .helpText("How to compare the requested level to the configured level: "
                    + "'equals' (exact requested level), 'minimum' (requested >= level), "
                    + "'maximum' (requested <= level, also matches when no level was requested).")
            .type(ProviderConfigProperty.LIST_TYPE)
            .options(RequestedLoaConditionalAuthenticator.OP_EQUALS,
                    RequestedLoaConditionalAuthenticator.OP_MINIMUM,
                    RequestedLoaConditionalAuthenticator.OP_MAXIMUM)
            .defaultValue(RequestedLoaConditionalAuthenticator.OP_EQUALS)
            .add()
            .build();

    @Override
    public ConditionalAuthenticator getSingleton() {
        return RequestedLoaConditionalAuthenticator.SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - Requested LOA (SIT)";
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
        return "Flow is executed only if the level of authentication REQUESTED by the client "
                + "matches the configured level (exact / minimum / maximum). Unlike the built-in "
                + "LOA condition it ignores what has already been satisfied, so tiers can be made "
                + "mutually exclusive by requested level. Does not change the session LOA itself.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.STEP_UP_AUTHENTICATION);
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
