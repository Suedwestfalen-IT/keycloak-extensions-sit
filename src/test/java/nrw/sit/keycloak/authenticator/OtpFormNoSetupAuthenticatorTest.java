package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class OtpFormNoSetupAuthenticatorTest {

    private final OtpFormNoSetupAuthenticatorFactory factory = new OtpFormNoSetupAuthenticatorFactory();

    @Test
    void neverSchedulesOtpSelfEnrolment() {
        UserModel user = mock(UserModel.class);
        RealmModel realm = mock(RealmModel.class);
        KeycloakSession session = mock(KeycloakSession.class);

        OtpFormNoSetupAuthenticator.SINGLETON.setRequiredActions(session, realm, user);

        verifyNoInteractions(user, realm, session);
    }

    @Test
    void isTheBuiltInOtpFormWithSetupDisabled() {
        assertTrue(OtpFormNoSetupAuthenticator.SINGLETON instanceof OTPFormAuthenticator);
        assertFalse(factory.isUserSetupAllowed());
        assertFalse(factory.isConfigurable());
        assertSame(OtpFormNoSetupAuthenticator.SINGLETON, factory.create(mock(KeycloakSession.class)));
    }

    @Test
    void sharesReferenceCategoryWithBuiltInOtpForm() {
        assertEquals(OTPCredentialModel.TYPE, factory.getReferenceCategory());
        assertEquals(new OTPFormAuthenticatorFactory().getReferenceCategory(), factory.getReferenceCategory());
    }

    @Test
    void usesItsOwnProviderId() {
        assertEquals(OtpFormNoSetupAuthenticatorFactory.PROVIDER_ID, factory.getId());
        assertNotEquals(OTPFormAuthenticatorFactory.PROVIDER_ID, factory.getId());
    }

    @Test
    void offersRequiredAndAlternativeButNotConditional() {
        List<Requirement> choices = Arrays.asList(factory.getRequirementChoices());

        assertTrue(choices.containsAll(List.of(Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED)));
        assertFalse(choices.contains(Requirement.CONDITIONAL));
    }
}
