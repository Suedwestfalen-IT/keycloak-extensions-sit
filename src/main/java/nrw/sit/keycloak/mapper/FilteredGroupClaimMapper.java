package nrw.sit.keycloak.mapper;

import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * OIDC Protocol Mapper that adds a filtered list of group paths to a JWT claim.
 *
 * Filters (both optional, combined with AND):
 *  - pathPrefix : only groups whose full path starts with this value (e.g. /SSO)
 *  - regex      : only groups whose full path matches this regular expression
 *
 * The claim value is a JSON array of full group paths (e.g. ["/SSO/koki/koki-user"]).
 */
public class FilteredGroupClaimMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final Logger LOG = Logger.getLogger(FilteredGroupClaimMapper.class);

    public static final String PROVIDER_ID = "sit-oidc-filtered-group-claim-mapper";

    static final String PATH_PREFIX = "pathPrefix";
    static final String REGEX       = "groupRegex";
    static final String CLAIM_NAME  = "claimName";
    static final String FULL_PATH   = "fullPath";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = new ArrayList<>();

        ProviderConfigProperty claimName = new ProviderConfigProperty();
        claimName.setName(CLAIM_NAME);
        claimName.setLabel("Claim Name");
        claimName.setHelpText("Name of the JWT claim to populate (e.g. 'groups').");
        claimName.setType(ProviderConfigProperty.STRING_TYPE);
        claimName.setDefaultValue("groups");
        CONFIG_PROPERTIES.add(claimName);

        ProviderConfigProperty fullPath = new ProviderConfigProperty();
        fullPath.setName(FULL_PATH);
        fullPath.setLabel("Full group path");
        fullPath.setHelpText("If ON, emit full paths like '/SSO/koki/koki-user'. If OFF, emit only the group name.");
        fullPath.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fullPath.setDefaultValue("true");
        CONFIG_PROPERTIES.add(fullPath);

        ProviderConfigProperty prefix = new ProviderConfigProperty();
        prefix.setName(PATH_PREFIX);
        prefix.setLabel("Path Prefix Filter");
        prefix.setHelpText("Only include groups whose full path starts with this prefix (e.g. '/SSO'). Leave empty to skip this filter.");
        prefix.setType(ProviderConfigProperty.STRING_TYPE);
        prefix.setDefaultValue("");
        CONFIG_PROPERTIES.add(prefix);

        ProviderConfigProperty regex = new ProviderConfigProperty();
        regex.setName(REGEX);
        regex.setLabel("Regex Filter");
        regex.setHelpText("Only include groups whose full path matches this regex (e.g. '^/SSO/koki/.*'). Leave empty to skip this filter.");
        regex.setType(ProviderConfigProperty.STRING_TYPE);
        regex.setDefaultValue("");
        CONFIG_PROPERTIES.add(regex);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, FilteredGroupClaimMapper.class);
    }

    @Override public String getId()              { return PROVIDER_ID; }
    @Override public String getDisplayType()     { return "SIT: Filtered Group Membership"; }
    @Override public String getDisplayCategory() { return "Token mapper"; }
    @Override public String getHelpText() {
        return "Adds a filtered list of group paths to a JWT claim. Filter by path prefix and/or regex.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG_PROPERTIES; }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession session,
                            ClientSessionContext clientSessionCtx) {

        UserModel user      = userSession.getUser();
        RealmModel realm    = session.getContext().getRealm();
        String claimName    = cfg(mappingModel, CLAIM_NAME, "groups");
        boolean fullPath    = Boolean.parseBoolean(cfg(mappingModel, FULL_PATH, "true"));
        String prefix       = cfg(mappingModel, PATH_PREFIX, "");
        String regexStr     = cfg(mappingModel, REGEX, "");

        Pattern pattern = null;
        if (!regexStr.isEmpty()) {
            try {
                pattern = Pattern.compile(regexStr);
            } catch (Exception e) {
                LOG.warnf("FilteredGroupClaimMapper: invalid regex '%s': %s", regexStr, e.getMessage());
            }
        }

        final Pattern finalPattern = pattern;

        List<String> groups = user.getGroupsStream()
                .map(g -> buildPath(realm, g))
                .filter(path -> prefix.isEmpty() || path.startsWith(prefix))
                .filter(path -> finalPattern == null || finalPattern.matcher(path).matches())
                .map(path -> fullPath ? path : leafName(path))
                .sorted()
                .collect(Collectors.toList());

        LOG.debugf("FilteredGroupClaimMapper: user=%s claim=%s groups=%s", user.getUsername(), claimName, groups);

        token.getOtherClaims().put(claimName, groups);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** Builds the full path of a group, e.g. /SSO/koki/koki-user */
    private String buildPath(RealmModel realm, GroupModel group) {
        Deque<String> parts = new ArrayDeque<>();
        GroupModel g = group;
        while (g != null) {
            parts.addFirst(g.getName());
            g = g.getParent();
        }
        return "/" + String.join("/", parts);
    }

    /** Returns the last segment of a path, e.g. "koki-user" from "/SSO/koki/koki-user" */
    private String leafName(String path) {
        int idx = path.lastIndexOf('/');
        return idx >= 0 ? path.substring(idx + 1) : path;
    }

    private String cfg(ProtocolMapperModel model, String key, String def) {
        String v = model.getConfig().get(key);
        return (v == null || v.isBlank()) ? def : v;
    }
}
