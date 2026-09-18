package nrw.sit.keycloak.mapper;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Keycloak Identity Provider Mapper (SPI).
 *
 * Reads a JSON array claim (default: "groups") from the upstream IdP token
 * and synchronises the brokered user's group memberships in this realm.
 *
 * Features:
 *  - Nested groups via slash-separated paths, e.g. "org/team-a"
 *  - Multiple group path prefixes can be stripped from the claim values,
 *    so several top-level groups of the upstream IdP can be merged into one
 *    target group (see GROUP_PREFIX)
 *  - Optional auto-creation of missing groups (including intermediate parents)
 *  - Optional removal of memberships for groups NOT in the claim,
 *    scoped to a configurable managed-prefix so manually assigned groups
 *    are left untouched
 *  - Target Group Prefix starting with "/" is treated as absolute (root-only match),
 *    preventing accidental matches against same-named sub-groups
 */
public class IdpGroupMapper extends AbstractClaimMapper {

    private static final Logger LOG = Logger.getLogger(IdpGroupMapper.class);

    public static final String PROVIDER_ID = "sit-oidc-group-idp-mapper";

    // ── Config keys ──────────────────────────────────────────────────────────
    static final String CLAIM_NAME        = "claim";
    static final String TARGET_PREFIX     = "targetPrefix";
    static final String GROUP_PREFIX      = "groupPrefix";
    static final String REMOVE_NOT_LISTED = "removeNotListed";
    static final String MANAGED_PREFIX    = "managedPrefix";
    static final String CREATE_MISSING    = "createMissing";

    /** Splits the GROUP_PREFIX config value at comma, new line or Keycloak's '##' delimiter. */
    private static final Pattern PREFIX_SEPARATOR = Pattern.compile("##|[,\\r\\n]");

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = new ArrayList<>();

        ProviderConfigProperty claim = new ProviderConfigProperty();
        claim.setName(CLAIM_NAME);
        claim.setLabel("Groups Claim Name");
        claim.setHelpText("JWT claim that contains the list of groups (e.g. 'groups').");
        claim.setType(ProviderConfigProperty.STRING_TYPE);
        claim.setDefaultValue("groups");
        CONFIG_PROPERTIES.add(claim);

        ProviderConfigProperty prefix = new ProviderConfigProperty();
        prefix.setName(GROUP_PREFIX);
        prefix.setLabel("Group Path Prefixes to Strip");
        prefix.setHelpText(
            "Prefixes stripped from every claim value before matching. Enter one prefix per " +
            "line (a comma works too), one for each top-level group of the upstream IdP, " +
            "e.g. '/PartnerA' and '/PartnerB' both map '/PartnerX/team-1' to 'team-1'. " +
            "The longest matching prefix wins; claim values matching no prefix are used unchanged."
        );
        // NOTE: deliberately not MULTIVALUED_STRING_TYPE. The admin console posts such a field
        // as a JSON array, but IdentityProviderMapperRepresentation.config is a
        // Map<String, String> – saving the mapper then fails with "Cannot parse the JSON".
        prefix.setType(ProviderConfigProperty.TEXT_TYPE);
        prefix.setDefaultValue("");
        CONFIG_PROPERTIES.add(prefix);

        ProviderConfigProperty targetPrefix = new ProviderConfigProperty();
        targetPrefix.setName(TARGET_PREFIX);
        targetPrefix.setLabel("Target Group Prefix");
        targetPrefix.setHelpText(
            "If set, groups are placed under this prefix group, e.g. 'KC2' turns 'koki/koki-user' into 'KC2/koki/koki-user'. " +
            "Also scopes removal to only groups under this prefix. " +
            "If the value starts with '/', the first segment is matched exclusively at root level " +
            "(prevents accidental matches against same-named sub-groups like /Probe/SSO)."
        );
        targetPrefix.setType(ProviderConfigProperty.STRING_TYPE);
        targetPrefix.setDefaultValue("");
        CONFIG_PROPERTIES.add(targetPrefix);

        ProviderConfigProperty create = new ProviderConfigProperty();
        create.setName(CREATE_MISSING);
        create.setLabel("Create groups that do not exist");
        create.setHelpText("Auto-create missing groups (including parent groups for nested paths).");
        create.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        create.setDefaultValue("false");
        CONFIG_PROPERTIES.add(create);

        ProviderConfigProperty remove = new ProviderConfigProperty();
        remove.setName(REMOVE_NOT_LISTED);
        remove.setLabel("Remove group memberships not in claim");
        remove.setHelpText("Remove the user from groups not present in the claim. Only affects groups matching the Managed Prefix.");
        remove.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        remove.setDefaultValue("false");
        CONFIG_PROPERTIES.add(remove);

        ProviderConfigProperty managed = new ProviderConfigProperty();
        managed.setName(MANAGED_PREFIX);
        managed.setLabel("Managed Group Prefix");
        managed.setHelpText("Only groups whose name starts with this prefix are considered for removal. Leave empty to manage all groups.");
        managed.setType(ProviderConfigProperty.STRING_TYPE);
        managed.setDefaultValue("");
        CONFIG_PROPERTIES.add(managed);
    }

    // ── SPI metadata ─────────────────────────────────────────────────────────

    @Override public String getId()              { return PROVIDER_ID; }
    @Override public String getDisplayType()     { return "Group Membership from Claim"; }
    @Override public String getDisplayCategory() { return "Group Importer"; }
    @Override public String getHelpText() {
        return "Syncs Keycloak group memberships from a JSON-array claim in the upstream IdP token. Supports nested groups via slash-separated paths.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG_PROPERTIES; }
    @Override public String[] getCompatibleProviders() { return new String[]{ "oidc" }; }


    // ── Entry points ─────────────────────────────────────────────────────────

    /** Called on first login. */
    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
                              IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        syncGroups(realm, user, mapperModel, context);
    }

    /** Called on subsequent logins when sync mode is FORCE. */
    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
                                   IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        syncGroups(realm, user, mapperModel, context);
    }

    /**
     * Called on every login regardless of sync mode – before importNewUser/updateBrokeredUser.
     * Used as reliable fallback for FORCE sync when updateBrokeredUser is not triggered.
     * The federated user is looked up via the brokered identity.
     */
    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
                                            IdentityProviderMapperModel mapperModel,
                                            BrokeredIdentityContext context) {
        String brokerUserId = context.getBrokerUserId();
        if (brokerUserId == null) return;

        UserModel user = session.users().getUserByFederatedIdentity(realm,
                new org.keycloak.models.FederatedIdentityModel(
                        context.getIdpConfig().getAlias(),
                        context.getBrokerUserId(),
                        context.getUsername()));

        if (user == null) return; // new user – importNewUser will handle it

        syncGroups(realm, user, mapperModel, context);
    }


    // ── Core logic ───────────────────────────────────────────────────────────

    private void syncGroups(RealmModel realm, UserModel user,
                            IdentityProviderMapperModel mapperModel,
                            BrokeredIdentityContext context) {

        String  claimName       = cfg(mapperModel, CLAIM_NAME,        "groups");
        List<String> prefixes   = parsePrefixes(mapperModel.getConfig().get(GROUP_PREFIX));
        String  managedPrefix   = stripLeadingSlash(cfg(mapperModel, MANAGED_PREFIX, ""));
        boolean removeNotListed = cfgBool(mapperModel, REMOVE_NOT_LISTED);
        boolean createMissing   = cfgBool(mapperModel, CREATE_MISSING);

        // Preserve leading slash as "absolute" signal before stripping
        String  rawTargetPrefix         = cfg(mapperModel, TARGET_PREFIX, "");
        boolean targetPrefixAbsolute    = rawTargetPrefix.startsWith("/");
        String  targetPrefix            = stripLeadingSlash(rawTargetPrefix);

        // effective managed scope: targetPrefix wins over managedPrefix if set
        String effectiveScope = !targetPrefix.isEmpty() ? targetPrefix : managedPrefix;

        Set<String> claimedRaw = extractGroupsFromClaim(context, claimName, prefixes);
        LOG.debugf("IdpGroupMapper: user=%s prefixes=%s claimedRaw=%s targetPrefix=%s (absolute=%b)",
                user.getUsername(), prefixes, claimedRaw, targetPrefix, targetPrefixAbsolute);
        LOG.infof("IdpGroupMapper: syncGroups removeNotListed=%b createMissing=%b effectiveScope='%s'",
                removeNotListed, createMissing, effectiveScope);

        // Build full paths including targetPrefix, e.g. "KC2/koki/koki-user"
        Set<String> claimedFull = new java.util.LinkedHashSet<>();
        for (String p : claimedRaw) {
            claimedFull.add(targetPrefix.isEmpty() ? p : targetPrefix + "/" + p);
        }

        // Add
        for (String fullPath : claimedFull) {
            GroupModel group = resolveGroup(realm, fullPath, createMissing, targetPrefixAbsolute);
            if (group != null && !user.isMemberOf(group)) {
                user.joinGroup(group);
                LOG.infof("IdpGroupMapper: added '%s' → group '%s'", user.getUsername(), fullPath);
            }
        }

        // Remove (only within managed scope)
        if (removeNotListed) {
            List<GroupModel> currentGroups = user.getGroupsStream().collect(Collectors.toList());
            LOG.infof("IdpGroupMapper: currentGroups=%s",
                    currentGroups.stream().map(g -> groupPath(realm, g)).collect(Collectors.toList()));
            LOG.infof("IdpGroupMapper: claimedFull=%s", claimedFull);
            LOG.infof("IdpGroupMapper: effectiveScope='%s'", effectiveScope);

            for (GroupModel g : currentGroups) {
                String path = groupPath(realm, g);
                boolean managed = isManagedGroup(realm, g, effectiveScope);
                boolean inClaim = claimedFull.contains(path);
                LOG.infof("IdpGroupMapper: group='%s' managed=%b inClaim=%b", path, managed, inClaim);
                if (managed && !inClaim) {
                    user.leaveGroup(g);
                    LOG.infof("IdpGroupMapper: removed '%s' from group '%s'", user.getUsername(), path);
                }
            }
        }
    }

    // ── Group resolution (nested) ─────────────────────────────────────────────

    /**
     * Resolves a slash-separated group path, e.g. "org/team-a".
     * Each segment is matched as a child of the previous one.
     * Creates intermediate groups when {@code createMissing} is true.
     *
     * @param rootOnly if true, the first path segment is matched exclusively
     *                 against top-level groups (parentId == null), preventing
     *                 accidental matches against same-named sub-groups.
     */
    private GroupModel resolveGroup(RealmModel realm, String path, boolean createMissing, boolean rootOnly) {
        String[] segments = path.split("/");
        GroupModel current = null;

        for (String segment : segments) {
            if (segment.isBlank()) continue;
            if (current == null) {
                current = findTopLevel(realm, segment, createMissing, rootOnly);
            } else {
                current = findChild(realm, current, segment, createMissing);
            }
            if (current == null) return null; // not found and not created
        }
        return current;
    }

    /** Convenience overload — defaults to rootOnly=true (safe default). */
    private GroupModel resolveGroup(RealmModel realm, String path, boolean createMissing) {
        return resolveGroup(realm, path, createMissing, true);
    }

    /**
     * Finds (or creates) a top-level group by name.
     *
     * @param rootOnly if true, only groups with parentId == null are considered,
     *                 preventing false matches against sub-groups with the same name.
     */
    private GroupModel findTopLevel(RealmModel realm, String name, boolean createMissing, boolean rootOnly) {
        Optional<GroupModel> found = realm.getGroupsStream()
                .filter(g -> !rootOnly || g.getParentId() == null)
                .filter(g -> name.equals(g.getName()))
                .findFirst();
        if (found.isPresent()) return found.get();
        if (!createMissing) {
            LOG.warnf("IdpGroupMapper: top-level group '%s' not found (rootOnly=%b), createMissing=false",
                    name, rootOnly);
            return null;
        }
        GroupModel g = realm.createGroup(name);
        LOG.infof("IdpGroupMapper: created top-level group '%s'", name);
        return g;
    }

    private GroupModel findChild(RealmModel realm, GroupModel parent, String name, boolean createMissing) {
        Optional<GroupModel> found = parent.getSubGroupsStream()
                .filter(g -> name.equals(g.getName()))
                .findFirst();
        if (found.isPresent()) return found.get();
        if (!createMissing) {
            LOG.warnf("IdpGroupMapper: child group '%s' under '%s' not found, createMissing=false",
                    name, parent.getName());
            return null;
        }
        GroupModel g = realm.createGroup(name, parent);
        LOG.infof("IdpGroupMapper: created child group '%s' under '%s'", name, parent.getName());
        return g;
    }

    /** Returns the slash-separated path of a group for claim matching, e.g. "SIT/koki/koki-user". */
    private String groupPath(RealmModel realm, GroupModel group) {
        Deque<String> parts = new ArrayDeque<>();
        GroupModel g = group;
        while (g != null) {
            parts.addFirst(g.getName());
            // getParent() may return null even when getParentId() is set (not loaded in session cache)
            GroupModel parent = g.getParent();
            if (parent == null && g.getParentId() != null) {
                parent = realm.getGroupById(g.getParentId());
            }
            g = parent;
        }
        return String.join("/", parts);
    }

    private boolean isManagedGroup(RealmModel realm, GroupModel group, String managedPrefix) {
        return managedPrefix.isEmpty() || groupPath(realm, group).startsWith(managedPrefix);
    }

    // ── Claim extraction ─────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private Set<String> extractGroupsFromClaim(BrokeredIdentityContext context,
                                               String claimName, List<String> prefixes) {
        Object raw = getClaimValue(context, claimName); // from AbstractClaimMapper
        if (raw == null) {
            LOG.debugf("IdpGroupMapper: claim '%s' not present", claimName);
            return Collections.emptySet();
        }

        List<String> values;
        if (raw instanceof List) {
            values = (List<String>) raw;
        } else if (raw instanceof String) {
            values = Arrays.asList(((String) raw).split("[,\\s]+"));
        } else {
            LOG.warnf("IdpGroupMapper: unexpected claim type %s", raw.getClass().getName());
            return Collections.emptySet();
        }

        return values.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> stripPrefix(s, prefixes))
                .collect(Collectors.toSet());
    }

    private String stripLeadingSlash(String value) {
        if (value == null) return "";
        String v = value;
        while (v.startsWith("/")) v = v.substring(1);
        return v;
    }

    /**
     * Parses the configured prefix list. Prefixes are separated by a new line, a comma or
     * Keycloak's '##' delimiter, so a value entered in the textarea, a previously configured
     * single value and a value set via the admin REST API all work. The result is
     * sorted by length descending,
     * so that {@link #stripPrefix} always removes the longest matching prefix
     * (e.g. "/PartnerAB" wins over "/PartnerA").
     */
    static List<String> parsePrefixes(String raw) {
        if (raw == null || raw.isBlank()) return Collections.emptyList();
        String value = raw.trim();
        // Tolerate a JSON array, e.g. from a hand-edited realm export: ["/A", "/B"]
        if (value.startsWith("[") && value.endsWith("]")) {
            value = value.substring(1, value.length() - 1);
        }
        return PREFIX_SEPARATOR.splitAsStream(value)
                .map(String::trim)
                .map(IdpGroupMapper::unquote)
                .filter(s -> !s.isEmpty())
                .distinct()
                .sorted(Comparator.comparingInt(String::length).reversed())
                .collect(Collectors.toList());
    }

    /** Strips surrounding double quotes left over from a JSON-array style config value. */
    private static String unquote(String value) {
        return (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\""))
                ? value.substring(1, value.length() - 1).trim() : value;
    }

    /**
     * Removes the first matching prefix (longest one first) from a claim value.
     * Values matching none of the prefixes are returned unchanged apart from
     * leading slashes.
     */
    static String stripPrefix(String value, List<String> prefixes) {
        String result = value;
        for (String prefix : prefixes) {
            if (value.startsWith(prefix)) {
                result = value.substring(prefix.length());
                break;
            }
        }
        // Remove leading slashes left after stripping (e.g. "/SSO/a" → strip "/SSO" → "/a" → "a")
        while (result.startsWith("/")) result = result.substring(1);
        return result;
    }

    private String cfg(IdentityProviderMapperModel model, String key, String def) {
        String v = model.getConfig().get(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    /** Parses boolean config values – KC stores toggles as "true" or "on". */
    private boolean cfgBool(IdentityProviderMapperModel model, String key) {
        String v = model.getConfig().get(key);
        if (v == null) return false;
        return "true".equalsIgnoreCase(v) || "on".equalsIgnoreCase(v) || "yes".equalsIgnoreCase(v);
    }

}
