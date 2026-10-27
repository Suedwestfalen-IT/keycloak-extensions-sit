package nrw.sit.keycloak.mapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
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

    private final IdentityProviderModel upstreamIdp = new IdentityProviderModel();

    private RealmModel realm;
    private UserModel user;

    @BeforeEach
    void setUp() {
        upstreamIdp.setAlias("upstream");
        IdentityProviderStorageProvider idps = mock(IdentityProviderStorageProvider.class);
        when(idps.getByAlias("upstream")).thenReturn(upstreamIdp);
        when(session.identityProviders()).thenReturn(idps);

        realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test");
        when(realm.getGroupsStream()).thenAnswer(inv -> new ArrayList<>(children.keySet()).stream());
        when(realm.getTopLevelGroupsStream()).thenAnswer(inv -> new ArrayList<>(topLevel).stream());
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

    // ── admin role mapping (Keycloak 26.8+, CVE-2026-12388) ──────────────────

    @Test
    void adminGroupIsNotJoinedWhileIdpDisallowsAdminRoleMapping() {
        GroupModel admins = group("realm-admins", null);
        grantAdminRole(admins);
        group("users", null);

        sync(claim("realm-admins", "users"));

        assertFalse(isMember("realm-admins"));
        assertTrue(isMember("users"));
    }

    @Test
    void adminGroupIsJoinedWhenIdpAllowsAdminRoleMapping() {
        upstreamIdp.setAllowAdminRoleMapping(true);
        GroupModel admins = group("realm-admins", null);
        grantAdminRole(admins);

        sync(claim("realm-admins"));

        assertTrue(isMember("realm-admins"));
    }

    @Test
    void adminRoleInheritedFromParentGroupAlsoBlocksJoin() {
        GroupModel sso = group("SSO", null);
        grantAdminRole(sso);
        group("team", sso);

        sync(claim("team"), IdpGroupMapper.TARGET_PREFIX, "/SSO");

        assertFalse(isMember("SSO/team"));
    }

    @Test
    void blockedAdminGroupKeepsExistingMembership() {
        GroupModel sso = group("SSO", null);
        GroupModel admins = group("admins", sso);
        grantAdminRole(admins);
        memberships.add(admins);

        sync(claim("admins"),
                IdpGroupMapper.TARGET_PREFIX, "/SSO",
                IdpGroupMapper.REMOVE_NOT_LISTED, "true");

        assertTrue(isMember("SSO/admins"));
    }

    @Test
    void groupsWithoutAdminRolesNeverConsultTheIdp() {
        group("users", null);

        sync(claim("users"));

        assertTrue(isMember("users"));
        verify(session, never()).identityProviders();
    }

    // ── sync modes ───────────────────────────────────────────────────────────

    @Test
    void supportsImportLegacyAndForce() {
        assertTrue(mapper.supportsSyncMode(IdentityProviderSyncMode.IMPORT));
        assertTrue(mapper.supportsSyncMode(IdentityProviderSyncMode.LEGACY));
        assertTrue(mapper.supportsSyncMode(IdentityProviderSyncMode.FORCE));
        assertFalse(mapper.supportsSyncMode(null));
    }

    /**
     * Guard for Keycloak upgrades: a new sync mode is not supported until someone has checked
     * what it means for this mapper and added it to {@link IdpGroupMapper#SUPPORTED_SYNC_MODES}.
     */
    @Test
    void everyKeycloakSyncModeHasBeenReviewed() {
        assertEquals(EnumSet.allOf(IdentityProviderSyncMode.class), IdpGroupMapper.SUPPORTED_SYNC_MODES,
                "IdentityProviderSyncMode gained a value: decide whether the mapper supports it");
    }

    @Test
    void sharedParentsAreResolvedOncePerSync() {
        GroupModel sso = group("SSO", null);
        GroupModel org = group("ORG", sso);
        group("team-a", org);
        group("team-b", org);
        group("team-c", org);

        sync(claim("/SSO/ORG/team-a", "/SSO/ORG/team-b", "/SSO/ORG/team-c"),
                IdpGroupMapper.GROUP_PREFIX, "/SSO/ORG",
                IdpGroupMapper.TARGET_PREFIX, "/SSO/ORG");

        assertTrue(isMember("SSO/ORG/team-a"));
        assertTrue(isMember("SSO/ORG/team-b"));
        assertTrue(isMember("SSO/ORG/team-c"));
        // "SSO" and "SSO/ORG" are shared by all three claimed groups: one lookup each, not three
        verify(realm, times(1)).getTopLevelGroupsStream();
        verify(sso, times(1)).getSubGroupsStream();
        verify(org, times(3)).getSubGroupsStream();
        verify(realm, never()).getGroupsStream();
    }

    @Test
    void relativeTargetPrefixStillScansAllGroups() {
        GroupModel probe = group("Probe", null);
        GroupModel nestedSso = group("SSO", probe);
        group("x", nestedSso);

        sync(claim("x"), IdpGroupMapper.TARGET_PREFIX, "SSO");

        assertTrue(isMember("Probe/SSO/x"));
        verify(realm, never()).getTopLevelGroupsStream();
    }

    @Test
    void updateBrokeredUserSyncsLikeImportNewUser() {
        GroupModel kc2 = group("KC2", null);
        GroupModel old = group("old", kc2);
        group("new", kc2);
        memberships.add(old);

        IdentityProviderMapperModel model = model(IdpGroupMapper.TARGET_PREFIX, "KC2",
                IdpGroupMapper.REMOVE_NOT_LISTED, "true");
        mapper.updateBrokeredUser(session, realm, user, model, claim("new"));

        assertTrue(isMember("KC2/new"));
        assertFalse(isMember("KC2/old"));
    }

    @Test
    void preprocessFederatedIdentityDoesNothing() {
        // the inherited no-op: groups are only synced via importNewUser / updateBrokeredUser
        group("users", null);
        IdentityProviderMapperModel model = model();
        mapper.preprocessFederatedIdentity(session, realm, model, claim("users"));

        verifyNoInteractions(session, realm, user);
    }

    // ── summary log line ─────────────────────────────────────────────────────
    // jboss-logging has no backend on the test classpath and falls back to java.util.logging,
    // so the summary can be captured there (DEBUG -> FINE, WARN -> WARNING).

    @Test
    void unchangedSyncLogsSummaryOnDebugOnly() {
        GroupModel users = group("users", null);
        memberships.add(users);

        List<LogRecord> records = capture(() -> sync(claim("users")));

        assertEquals(1, records.size(), records.toString());
        assertEquals(Level.FINE, records.get(0).getLevel());
        assertTrue(records.get(0).getMessage().startsWith("IdpGroupMapper: user=alice idp=upstream mapper=groups "));
    }

    @Test
    void changedSyncLogsSummaryOnInfo() {
        group("users", null);

        List<LogRecord> records = capture(() -> sync(claim("users")));

        assertEquals(1, records.size(), records.toString());
        assertEquals(Level.INFO, records.get(0).getLevel());
        assertTrue(records.get(0).getMessage().contains("added=[users]"));
    }

    @Test
    void unresolvedGroupLogsSummaryOnWarn() {
        List<LogRecord> records = capture(() -> sync(claim("nope")));

        assertEquals(1, records.size(), records.toString());
        assertEquals(Level.WARNING, records.get(0).getLevel());
        assertTrue(records.get(0).getMessage().contains("notFound=[nope]"));
    }

    /** Runs the action and returns the summary lines the mapper logged, at any level. */
    private static List<LogRecord> capture(Runnable action) {
        java.util.logging.Logger jul = java.util.logging.Logger.getLogger(IdpGroupMapper.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override public void publish(LogRecord r) {
                if (r.getMessage() != null && r.getMessage().startsWith("IdpGroupMapper: user=")
                        && r.getMessage().contains(" idp=")) records.add(r);
            }
            @Override public void flush() {}
            @Override public void close() {}
        };
        Level before = jul.getLevel();
        jul.setLevel(Level.ALL);
        jul.addHandler(handler);
        try {
            action.run();
        } finally {
            jul.removeHandler(handler);
            jul.setLevel(before);
        }
        return records;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Maps the realm-management role "manage-users" to the group. */
    private static void grantAdminRole(GroupModel group) {
        ClientModel realmManagement = mock(ClientModel.class);
        when(realmManagement.getClientId()).thenReturn(Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel role = mock(RoleModel.class);
        when(role.getId()).thenReturn("role-manage-users");
        when(role.getName()).thenReturn("manage-users");
        when(role.getContainer()).thenReturn(realmManagement);
        when(group.getRoleMappingsStream()).thenAnswer(inv -> Stream.of(role));
    }

    private void sync(BrokeredIdentityContext ctx, String... configKeyValues) {
        mapper.importNewUser(session, realm, user, model(configKeyValues), ctx);
    }

    private static IdentityProviderMapperModel model(String... configKeyValues) {
        Map<String, String> config = new HashMap<>();
        for (int i = 0; i < configKeyValues.length; i += 2) {
            config.put(configKeyValues[i], configKeyValues[i + 1]);
        }
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setConfig(config);
        model.setName("groups");
        model.setIdentityProviderAlias("upstream");
        return model;
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
