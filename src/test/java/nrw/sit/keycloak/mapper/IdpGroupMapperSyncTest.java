package nrw.sit.keycloak.mapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Exercises {@link IdpGroupMapper#importNewUser} end to end against an in-memory
 * group tree built from Mockito mocks. The brokered context is a real
 * {@link BrokeredIdentityContext} carrying a real ID token, so the claim lookup
 * inherited from {@code AbstractClaimMapper} runs unmodified.
 */
class IdpGroupMapperSyncTest {

    private final IdpGroupMapper mapper = new IdpGroupMapper();
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final AtomicInteger ids = new AtomicInteger();

    /** every group of the realm (top-level and nested), like RealmModel#getGroupsStream */
    private final Map<GroupModel, List<GroupModel>> children = new IdentityHashMap<>();
    private final List<GroupModel> topLevel = new ArrayList<>();
    private final List<GroupModel> memberships = new ArrayList<>();

    private RealmModel realm;
    private UserModel user;

    @BeforeEach
    void setUp() {
        realm = mock(RealmModel.class);
        when(realm.getGroupsStream()).thenAnswer(inv -> new ArrayList<>(children.keySet()).stream());
        when(realm.getGroupById(anyString())).thenAnswer(inv -> children.keySet().stream()
                .filter(g -> inv.getArgument(0).equals(g.getId()))
                .findFirst().orElse(null));
        when(realm.createGroup(anyString())).thenAnswer(inv -> group(inv.getArgument(0), null));
        when(realm.createGroup(anyString(), any(GroupModel.class)))
                .thenAnswer(inv -> group(inv.getArgument(0), inv.getArgument(1)));

        user = mock(UserModel.class);
        when(user.getUsername()).thenReturn("alice");
        when(user.getGroupsStream()).thenAnswer(inv -> new ArrayList<>(memberships).stream());
        when(user.isMemberOf(any())).thenAnswer(inv -> memberships.contains(inv.<GroupModel>getArgument(0)));
        doAnswer(inv -> { memberships.add(inv.getArgument(0)); return null; }).when(user).joinGroup(any());
        doAnswer(inv -> { memberships.remove(inv.<GroupModel>getArgument(0)); return null; }).when(user).leaveGroup(any());
    }

    // ── plain matching ───────────────────────────────────────────────────────

    @Test
    void joinsExistingGroupNamedInClaim() {
        group("admins", null);

        sync(claim("admins"));

        assertTrue(isMember("admins"));
        verify(realm, never()).createGroup(anyString());
        verify(realm, never()).createGroup(anyString(), any(GroupModel.class));
    }

    @Test
    void leadingSlashInClaimValueIsIgnoredWithoutAnyPrefix() {
        group("admins", null);

        sync(claim("/admins"));

        assertTrue(isMember("admins"));
    }

    @Test
    void nestedPathResolvesChildBelowParent() {
        GroupModel org = group("org", null);
        group("team-a", org);

        sync(claim("org/team-a"));

        assertTrue(isMember("org/team-a"));
        assertFalse(isMember("org"));
    }

    @Test
    void commaSeparatedStringClaimIsAccepted() {
        group("a", null);
        group("b", null);

        sync(claim("a, b"));

        assertTrue(isMember("a"));
        assertTrue(isMember("b"));
    }

    @Test
    void missingClaimChangesNothing() {
        group("admins", null);

        sync(claim((Object) null));

        assertTrue(memberships.isEmpty());
    }

    // ── prefix handling ──────────────────────────────────────────────────────

    @Test
    void singlePrefixConfigurationKeepsWorking() {
        // configuration that existed before multi-prefix support
        GroupModel kc2 = group("KC2", null);
        GroupModel koki = group("koki", kc2);
        group("koki-user", koki);

        sync(claim("/SSO/koki/koki-user"),
                IdpGroupMapper.GROUP_PREFIX, "/SSO",
                IdpGroupMapper.TARGET_PREFIX, "KC2");

        assertTrue(isMember("KC2/koki/koki-user"));
    }

    @Test
    void multiplePrefixesMergeIntoOneTargetGroup() {
        GroupModel kc2 = group("KC2", null);
        group("team-1", kc2);
        group("team-2", kc2);

        sync(claim("/PartnerA/team-1", "/PartnerB/team-2"),
                IdpGroupMapper.GROUP_PREFIX, "/PartnerA\n/PartnerB",
                IdpGroupMapper.TARGET_PREFIX, "KC2");

        assertTrue(isMember("KC2/team-1"));
        assertTrue(isMember("KC2/team-2"));
        assertFalse(isMember("KC2"));
    }

    @Test
    void claimValueEqualToPrefixDoesNotJoinTargetGroupItself() {
        GroupModel kc2 = group("KC2", null);
        group("team-1", kc2);

        sync(claim("/PartnerA", "/PartnerA/team-1"),
                IdpGroupMapper.GROUP_PREFIX, "/PartnerA",
                IdpGroupMapper.TARGET_PREFIX, "KC2");

        assertTrue(isMember("KC2/team-1"));
        assertFalse(isMember("KC2"));
    }

    // ── create missing ───────────────────────────────────────────────────────

    @Test
    void unknownGroupIsSkippedWhenCreateMissingIsOff() {
        sync(claim("nope/really"));

        assertTrue(memberships.isEmpty());
        assertTrue(children.isEmpty());
    }

    @Test
    void wholeChainIsCreatedWhenCreateMissingIsOn() {
        sync(claim("koki/koki-user"),
                IdpGroupMapper.TARGET_PREFIX, "KC2",
                IdpGroupMapper.CREATE_MISSING, "true");

        assertNotNull(find("KC2"));
        assertNotNull(find("KC2/koki"));
        assertTrue(isMember("KC2/koki/koki-user"));
        assertFalse(isMember("KC2"));
        assertFalse(isMember("KC2/koki"));
    }

    // ── remove not listed ────────────────────────────────────────────────────

    @Test
    void removeNotListedOnlyTouchesGroupsBelowTargetPrefix() {
        GroupModel kc2 = group("KC2", null);
        GroupModel old = group("old", kc2);
        group("new", kc2);
        GroupModel manual = group("Manual", null);
        memberships.add(old);
        memberships.add(manual);

        sync(claim("new"),
                IdpGroupMapper.TARGET_PREFIX, "KC2",
                IdpGroupMapper.REMOVE_NOT_LISTED, "on");

        assertTrue(isMember("KC2/new"));
        assertFalse(isMember("KC2/old"));
        assertTrue(isMember("Manual"));
    }

    @Test
    void managedPrefixScopesRemovalWhenNoTargetPrefixIsSet() {
        GroupModel sso = group("SSO", null);
        GroupModel stale = group("stale", sso);
        GroupModel manual = group("Manual", null);
        memberships.add(stale);
        memberships.add(manual);

        sync(claim("SSO/fresh"),
                IdpGroupMapper.MANAGED_PREFIX, "SSO",
                IdpGroupMapper.REMOVE_NOT_LISTED, "true",
                IdpGroupMapper.CREATE_MISSING, "true");

        assertTrue(isMember("SSO/fresh"));
        assertFalse(isMember("SSO/stale"));
        assertTrue(isMember("Manual"));
    }

    @Test
    void removeNotListedWithoutAnyScopeRemovesEveryGroupNotInClaim() {
        GroupModel keep = group("keep", null);
        GroupModel manual = group("Manual", null);
        memberships.add(keep);
        memberships.add(manual);

        sync(claim("keep"), IdpGroupMapper.REMOVE_NOT_LISTED, "true");

        assertTrue(isMember("keep"));
        assertFalse(isMember("Manual"));
    }

    @Test
    void removeNotListedIsOffByDefault() {
        GroupModel stale = group("stale", null);
        group("fresh", null);
        memberships.add(stale);

        sync(claim("fresh"));

        assertTrue(isMember("fresh"));
        assertTrue(isMember("stale"));
    }

    // ── absolute vs. relative target prefix ──────────────────────────────────

    @Test
    void relativeTargetPrefixMayMatchSameNamedSubGroup() {
        GroupModel probe = group("Probe", null);
        GroupModel nestedSso = group("SSO", probe);
        group("x", nestedSso);

        sync(claim("x"), IdpGroupMapper.TARGET_PREFIX, "SSO");

        assertTrue(isMember("Probe/SSO/x"));
    }

    @Test
    void absoluteTargetPrefixMatchesRootLevelOnly() {
        GroupModel probe = group("Probe", null);
        GroupModel nestedSso = group("SSO", probe);
        group("x", nestedSso);

        sync(claim("x"), IdpGroupMapper.TARGET_PREFIX, "/SSO");

        assertTrue(memberships.isEmpty());
        assertNull(find("SSO"));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private void sync(BrokeredIdentityContext ctx, String... configKeyValues) {
        Map<String, String> config = new HashMap<>();
        for (int i = 0; i < configKeyValues.length; i += 2) {
            config.put(configKeyValues[i], configKeyValues[i + 1]);
        }
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setConfig(config);
        mapper.importNewUser(session, realm, user, model, ctx);
    }

    /** Builds a brokered context whose validated ID token carries the given "groups" claim. */
    private static BrokeredIdentityContext claim(Object groupsClaim) {
        IdentityProviderModel idp = new IdentityProviderModel();
        idp.setAlias("upstream");
        idp.setEnabled(true);
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("broker-user-id", idp);
        JsonWebToken idToken = new JsonWebToken();
        if (groupsClaim != null) {
            idToken.setOtherClaims("groups", groupsClaim);
        }
        ctx.getContextData().put(OIDCIdentityProvider.VALIDATED_ID_TOKEN, idToken);
        return ctx;
    }

    private static BrokeredIdentityContext claim(String... groups) {
        return claim((Object) List.of(groups));
    }

    private GroupModel group(String name, GroupModel parent) {
        GroupModel g = mock(GroupModel.class, name);
        when(g.getId()).thenReturn("g" + ids.incrementAndGet());
        when(g.getName()).thenReturn(name);
        String parentId = parent == null ? null : parent.getId(); // outside of when(): nested mock call
        when(g.getParent()).thenReturn(parent);
        when(g.getParentId()).thenReturn(parentId);
        children.put(g, new ArrayList<>());
        when(g.getSubGroupsStream()).thenAnswer(inv -> new ArrayList<>(children.get(g)).stream());
        if (parent == null) {
            topLevel.add(g);
        } else {
            children.get(parent).add(g);
        }
        return g;
    }

    private GroupModel find(String path) {
        GroupModel current = null;
        for (String segment : path.split("/")) {
            List<GroupModel> candidates = current == null ? topLevel : children.get(current);
            current = candidates.stream().filter(g -> g.getName().equals(segment)).findFirst().orElse(null);
            if (current == null) return null;
        }
        return current;
    }

    private boolean isMember(String path) {
        GroupModel g = find(path);
        return g != null && memberships.contains(g);
    }
}
