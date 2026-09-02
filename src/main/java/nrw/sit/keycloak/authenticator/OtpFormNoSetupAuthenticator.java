package nrw.sit.keycloak.authenticator;

import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Identical to the built-in OTP Form ({@code auth-otp-form}), except that a user
 * without a configured OTP credential is NOT sent to the CONFIGURE_TOTP required
 * action. The decision is made by the flow engine via
 * {@link OtpFormNoSetupAuthenticatorFactory#isUserSetupAllowed()} returning
 * {@code false}: with requirement REQUIRED, {@code DefaultAuthenticationFlow} then
 * throws {@code AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED} and the login
 * fails with the standard "credentialSetupRequired" error page.
 *
 * {@link #setRequiredActions} is overridden as a safety net so that no code path
 * can ever schedule an OTP self-enrolment through this execution.
 */
public class OtpFormNoSetupAuthenticator extends OTPFormAuthenticator {

    public static final OtpFormNoSetupAuthenticator SINGLETON = new OtpFormNoSetupAuthenticator();

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Intentionally empty: self-enrolment of OTP is not permitted here.
    }
}
