package nrw.sit.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory for {@link OtpFormNoSetupAuthenticator}. Mirrors the built-in
 * {@code OTPFormAuthenticatorFactory} with {@link #isUserSetupAllowed()} = false.
 */
public class OtpFormNoSetupAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sit-auth-otp-form-no-setup";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.ALTERNATIVE,
            Requirement.DISABLED,
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        return OtpFormNoSetupAuthenticator.SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        // Same category as the built-in OTP form, so "Condition - user configured" /
        // credential conditions treat it identically.
        return OTPCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        // The one and only difference to auth-otp-form: never fall back to
        // the CONFIGURE_TOTP required action. REQUIRED + no OTP => flow fails.
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "SIT: OTP Form (no self-setup)";
    }

    @Override
    public String getHelpText() {
        return "Validates a OTP on a separate OTP form, exactly like the built-in OTP Form. "
                + "Users without a configured OTP credential are NOT redirected to the OTP setup; "
                + "the authentication fails with 'credential setup required' instead.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
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
