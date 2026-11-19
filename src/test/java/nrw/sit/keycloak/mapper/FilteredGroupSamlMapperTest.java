package nrw.sit.keycloak.mapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FilteredGroupSamlMapperTest {

    private final FilteredGroupSamlMapper mapper = new FilteredGroupSamlMapper();
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final UserSessionModel userSession = mock(UserSessionModel.class);
    private final UserModel user = mock(UserModel.class);
    private final List<GroupModel> memberships = new ArrayList<>();

    @BeforeEach
    void setUp() {
        when(userSession.getUser()).thenReturn(user);
        when(user.getUsername()).thenReturn("alice");
        when(user.getGroupsStream()).thenAnswer(inv -> new ArrayList<>(memberships).stream());
    }

    @Test
    void emitsOneAttributeWithSortedFullPathsByDefault() {
        member("/SSO/koki/koki-user");
        member("/Other/y");

        List<AttributeType> attrs = attributes("member");
        assertEquals(1, attrs.size());
        assertEquals("member", attrs.get(0).getName());
        assertEquals(List.of("/Other/y", "/SSO/koki/koki-user"), values(attrs.get(0)));
    }

    @Test
    void emitsOneAttributePerGroupWhenSingleIsOff() {
        member("/SSO/a");
        member("/SSO/b");

        List<AttributeType> attrs = attributes("member", FilteredGroupSamlMapper.SINGLE_ATTRIBUTE, "false");
        assertEquals(2, attrs.size());
        assertEquals(List.of("/SSO/a"), values(attrs.get(0)));
        assertEquals(List.of("/SSO/b"), values(attrs.get(1)));
    }

    @Test
    void caseKeepLowerUpper() {
        member("/SSO/Koki/Koki-User");

        assertEquals(List.of("/SSO/Koki/Koki-User"), singleValues());
        assertEquals(List.of("/SSO/Koki/Koki-User"), singleValues(FilteredGroups.GROUP_CASE, "keep"));
        assertEquals(List.of("/sso/koki/koki-user"), singleValues(FilteredGroups.GROUP_CASE, "lower"));
        assertEquals(List.of("/SSO/KOKI/KOKI-USER"), singleValues(FilteredGroups.GROUP_CASE, "upper"));
        assertEquals(List.of("koki-user"), singleValues(
                FilteredGroups.GROUP_CASE, "lower", FilteredGroups.FULL_PATH, "false"));
    }

    @Test
    void filtersSeeOriginalCase() {
        member("/SSO/Admins");
        member("/sso/other");

        assertEquals(List.of("/sso/admins"), singleValues(
                FilteredGroups.GROUP_CASE, "lower",
                FilteredGroups.PATH_PREFIX, "/SSO",
                FilteredGroups.REGEX, ".*/Admins"));
    }

    @Test
    void groupsThatBecomeEqualAreEmittedOnce() {
        member("/A/Team");
        member("/B/team");

        assertEquals(List.of("team"), singleValues(
                FilteredGroups.GROUP_CASE, "lower", FilteredGroups.FULL_PATH, "false"));
    }

    @Test
    void prefixAndRegexFilter() {
        member("/SSO/koki/koki-user");
        member("/SSO/koki/koki-admin");
        member("/SSOX/koki-user");

        assertEquals(List.of("/SSO/koki/koki-user"), singleValues(
                FilteredGroups.PATH_PREFIX, "SSO/",
                FilteredGroups.REGEX, ".*-user$"));
    }

    @Test
    void noAttributeWhenNoGroupMatches() {
        member("/Other/y");

        assertEquals(List.of(), attributes("member", FilteredGroups.PATH_PREFIX, "/SSO"));
    }

    @Test
    void configPropertiesIncludeSamlAttributeOptions() {
        List<String> names = mapper.getConfigProperties().stream()
                .map(ProviderConfigProperty::getName)
                .collect(Collectors.toList());

        assertTrue(names.containsAll(List.of(
                AttributeStatementHelper.SAML_ATTRIBUTE_NAME,
                AttributeStatementHelper.FRIENDLY_NAME,
                AttributeStatementHelper.SAML_ATTRIBUTE_NAMEFORMAT,
                FilteredGroupSamlMapper.SINGLE_ATTRIBUTE,
                FilteredGroups.FULL_PATH,
                FilteredGroups.GROUP_CASE,
                FilteredGroups.PATH_PREFIX,
                FilteredGroups.REGEX)), names.toString());
        assertEquals(FilteredGroupSamlMapper.PROVIDER_ID, mapper.getId());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private List<String> singleValues(String... configKeyValues) {
        List<AttributeType> attrs = attributes("member", configKeyValues);
        assertEquals(1, attrs.size());
        return values(attrs.get(0));
    }

    private List<AttributeType> attributes(String attributeName, String... configKeyValues) {
        Map<String, String> config = new HashMap<>();
        config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAME, attributeName);
        for (int i = 0; i < configKeyValues.length; i += 2) {
            config.put(configKeyValues[i], configKeyValues[i + 1]);
        }
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(config);
        AttributeStatementType statement = new AttributeStatementType();

        mapper.transformAttributeStatement(statement, model, session, userSession, null);

        return statement.getAttributes().stream()
                .map(AttributeStatementType.ASTChoiceType::getAttribute)
                .collect(Collectors.toList());
    }

    private static List<String> values(AttributeType attribute) {
        return attribute.getAttributeValue().stream().map(String::valueOf).collect(Collectors.toList());
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
