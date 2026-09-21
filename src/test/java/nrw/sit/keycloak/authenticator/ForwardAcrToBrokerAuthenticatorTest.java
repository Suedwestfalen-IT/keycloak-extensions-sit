package nrw.sit.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ForwardAcrToBrokerAuthenticatorTest {

    private final ForwardAcrToBrokerAuthenticator authenticator = ForwardAcrToBrokerAuthenticator.SINGLETON;
    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    private final ClientModel client = mock(ClientModel.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final Map<String, String> clientAttributes = new HashMap<>();
    private final Map<String, String> clientNotes = new HashMap<>();

    @BeforeEach
    void setUp() {
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getClient()).thenReturn(client);
        when(client.getRealm()).thenReturn(realm);
        when(client.getClientId()).thenReturn("app");
        when(client.getAttribute(anyString())).thenAnswer(inv -> clientAttributes.get(inv.<String>getArgument(0)));
        when(client.getAttributes()).thenReturn(clientAttributes);
        when(authSession.getClientNote(anyString())).thenAnswer(inv -> clientNotes.get(inv.<String>getArgument(0)));
        doAnswer(inv -> clientNotes.put(inv.getArgument(0), inv.getArgument(1)))
                .when(authSession).setClientNote(anyString(), anyString());
        when(realm.getAttribute(Constants.ACR_LOA_MAP))
                .thenReturn("{\"bronze\":1,\"silver\":2,\"gold\":3}");
    }

    @Test
    void forwardsConfiguredMinimumWhenNothingWasRequested() {
        clientAttributes.put(Constants.MINIMUM_ACR_VALUE, "silver");

        authenticator.authenticate(context);

        assertEquals("silver", clientNotes.get(OAuth2Constants.ACR_VALUES));
        verify(context).success();
        verify(context, never()).failure(any());
    }

    @Test
    void fallsBackToFirstDefaultAcrValue() {
        clientAttributes.put(Constants.DEFAULT_ACR_VALUES, "gold##silver");

        authenticator.authenticate(context);

        assertEquals("gold", clientNotes.get(OAuth2Constants.ACR_VALUES));
    }

    @Test
    void minimumTakesPrecedenceOverDefaults() {
        clientAttributes.put(Constants.MINIMUM_ACR_VALUE, "silver");
        clientAttributes.put(Constants.DEFAULT_ACR_VALUES, "gold");

        authenticator.authenticate(context);

        assertEquals("silver", clientNotes.get(OAuth2Constants.ACR_VALUES));
    }

    @Test
    void keepsRequestedValueWhenItIsHigherThanConfigured() {
        clientNotes.put(OAuth2Constants.ACR_VALUES, "gold");
        clientAttributes.put(Constants.MINIMUM_ACR_VALUE, "silver");

        authenticator.authenticate(context);

        assertEquals("gold", clientNotes.get(OAuth2Constants.ACR_VALUES));
        verify(authSession, never()).setClientNote(anyString(), anyString());
    }

    @Test
    void raisesRequestedValueToConfiguredMinimum() {
        clientNotes.put(OAuth2Constants.ACR_VALUES, "bronze");
        clientAttributes.put(Constants.MINIMUM_ACR_VALUE, "silver");

        authenticator.authenticate(context);

        assertEquals("silver", clientNotes.get(OAuth2Constants.ACR_VALUES));
    }

    @Test
    void keepsRequestedValueWhenEitherSideIsUnknownToTheLoaMap() {
        clientNotes.put(OAuth2Constants.ACR_VALUES, "custom");
        clientAttributes.put(Constants.MINIMUM_ACR_VALUE, "silver");

        authenticator.authenticate(context);

        assertEquals("custom", clientNotes.get(OAuth2Constants.ACR_VALUES));
    }

    @Test
    void keepsRequestedValueWhenNothingIsConfigured() {
        clientNotes.put(OAuth2Constants.ACR_VALUES, "gold");

        authenticator.authenticate(context);

        assertEquals("gold", clientNotes.get(OAuth2Constants.ACR_VALUES));
        verify(authSession, never()).setClientNote(anyString(), anyString());
    }

    @Test
    void leavesNoteUntouchedWhenNeitherRequestedNorConfigured() {
        authenticator.authenticate(context);

        assertNull(clientNotes.get(OAuth2Constants.ACR_VALUES));
        verify(authSession, never()).setClientNote(anyString(), anyString());
        verify(context).success();
    }
}
