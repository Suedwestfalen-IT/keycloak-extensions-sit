package nrw.sit.keycloak.mapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FilteredGroupClaimMapperTest {

    private final FilteredGroupClaimMapper mapper = new FilteredGroupClaimMapper();
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final KeycloakContext keycloakContext = mock(KeycloakContext.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final UserSessionModel userSession = mock(UserSessionModel.class);
    private final UserModel user = mock(UserModel.class);
    private final List<GroupModel> memberships = new ArrayList<>();

    @BeforeEach
    void setUp() {
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realm);
        when(userSession.getUser()).thenReturn(user);
        when(user.getUsername()).thenReturn("alice");
        when(user.getGroupsStream()).thenAnswer(inv -> new ArrayList<>(memberships).stream());
    }

    @Test
    void emitsSortedFullPathsByDefault() {
        member("/SSO/koki/koki-user");
        member("/Other/y");
        member("/SSO/admins");

        assertEquals(List.of("/Other/y", "/SSO/admins", "/SSO/koki/koki-user"), claim("groups"));
    }

    @Test
    void emitsLeafNamesWhenFullPathIsOff() {
        member("/SSO/koki/koki-user");
        member("/Other/y");

        assertEquals(List.of("koki-user", "y"),
                claim("groups", FilteredGroupClaimMapper.FULL_PATH, "false"));
    }

    @Test
    void prefixFilterKeepsOnlyMatchingPaths() {
        member("/SSO/koki/koki-user");
        member("/SSOX/trap");
        member("/Other/y");

        assertEquals(List.of("/SSO/koki/koki-user", "/SSOX/trap"),
                claim("groups", FilteredGroupClaimMapper.PATH_PREFIX, "/SSO"));
        assertEquals(List.of("/SSO/koki/koki-user"),
                claim("groups", FilteredGroupClaimMapper.PATH_PREFIX, "/SSO/"));
    }

    @Test
    void regexFilterMustMatchWholePath() {
        member("/SSO/koki/koki-user");
        member("/SSO/koki-admin");
        member("/SSO/other");

        assertEquals(List.of("/SSO/koki/koki-user"),
                claim("groups", FilteredGroupClaimMapper.REGEX, "^/SSO/koki/.*"));
        // no implicit .* around the pattern
        assertEquals(List.of(),
                claim("groups", FilteredGroupClaimMapper.REGEX, "koki"));
    }

    @Test
    void prefixAndRegexAreCombinedWithAnd() {
        member("/SSO/koki/koki-user");
        member("/SSO/koki/koki-admin");
        member("/Other/koki/koki-user");

        assertEquals(List.of("/SSO/koki/koki-user"),
                claim("groups",
                        FilteredGroupClaimMapper.PATH_PREFIX, "/SSO",
                        FilteredGroupClaimMapper.REGEX, ".*-user$"));
    }

    @Test
    void invalidRegexIsIgnoredInsteadOfFailingTheLogin() {
        member("/SSO/a");
        member("/SSO/b");

        assertEquals(List.of("/SSO/a", "/SSO/b"),
                claim("groups", FilteredGroupClaimMapper.REGEX, "[unclosed"));
    }

    @Test
    void claimNameIsConfigurable() {
        member("/SSO/a");

        assertEquals(List.of("/SSO/a"),
                claim("sit_groups", FilteredGroupClaimMapper.CLAIM_NAME, "sit_groups"));
    }

    @Test
    void userWithoutGroupsGetsEmptyList() {
        assertEquals(List.of(), claim("groups"));
    }

    @Test
    void blankConfigValuesFallBackToDefaults() {
        member("/SSO/a");

        assertEquals(List.of("/SSO/a"), claim("groups",
                FilteredGroupClaimMapper.CLAIM_NAME, "  ",
                FilteredGroupClaimMapper.FULL_PATH, "",
                FilteredGroupClaimMapper.PATH_PREFIX, "",
                FilteredGroupClaimMapper.REGEX, ""));
    }

    @Test
    void configPropertiesIncludeOwnOptionsAndTokenToggles() {
        List<String> names = mapper.getConfigProperties().stream()
                .map(ProviderConfigProperty::getName)
                .collect(Collectors.toList());

        assertTrue(names.containsAll(List.of(
                FilteredGroupClaimMapper.CLAIM_NAME,
                FilteredGroupClaimMapper.FULL_PATH,
                FilteredGroupClaimMapper.PATH_PREFIX,
                FilteredGroupClaimMapper.REGEX,
                "access.token.claim", "id.token.claim", "userinfo.token.claim")), names.toString());
        assertEquals(FilteredGroupClaimMapper.PROVIDER_ID, mapper.getId());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private List<String> claim(String claimName, String... configKeyValues) {
        Map<String, String> config = new HashMap<>();
        for (int i = 0; i < configKeyValues.length; i += 2) {
            config.put(configKeyValues[i], configKeyValues[i + 1]);
        }
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(config);
        IDToken token = new IDToken();

        mapper.setClaim(token, model, userSession, session, null);

        Object value = token.getOtherClaims().get(claimName);
        assertTrue(value instanceof List, "claim '" + claimName + "' should be a list but was " + value);
        return (List<String>) value;
    }

    /** Registers the user as member of the group at the given full path, building parents as needed. */
    private void member(String fullPath) {
        GroupModel parent = null;
        for (String segment : fullPath.substring(1).split("/")) {
            GroupModel g = mock(GroupModel.class, segment);
            when(g.getName()).thenReturn(segment);
            when(g.getParent()).thenReturn(parent);
            parent = g;
        }
        memberships.add(parent);
    }
}
