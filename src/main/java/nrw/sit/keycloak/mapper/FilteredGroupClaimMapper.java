package nrw.sit.keycloak.mapper;

import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

/**
 * OIDC Protocol Mapper that adds a filtered list of group paths to a JWT claim.
 *
 * Filters (both optional, combined with AND):
 *  - pathPrefix : only groups at or below this path (e.g. /SSO), compared segment by segment
 *                 (see GroupPath): /SSO matches /SSO/koki but not /SSOX/a
 *  - regex      : only groups whose full path matches this regular expression
 *
 * The claim value is a JSON array of full group paths (e.g. ["/SSO/koki/koki-user"]).
 */
public class FilteredGroupClaimMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final Logger LOG = Logger.getLogger(FilteredGroupClaimMapper.class);

    public static final String PROVIDER_ID = "sit-oidc-filtered-group-claim-mapper";

    static final String PATH_PREFIX = FilteredGroups.PATH_PREFIX;
    static final String REGEX       = FilteredGroups.REGEX;
    static final String CLAIM_NAME  = "claimName";
    static final String FULL_PATH   = FilteredGroups.FULL_PATH;

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
        prefix.setHelpText(
            "Only include groups at or below this path (e.g. '/SSO'). Compared segment by segment: " +
            "'/SSO' matches '/SSO/koki' but not '/SSOX/a'; leading and trailing slashes do not matter. " +
            "Leave empty to skip this filter."
        );
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

        UserModel user    = userSession.getUser();
        String claimName  = FilteredGroups.cfg(mappingModel, CLAIM_NAME, "groups");
        List<String> groups = FilteredGroups.collect(user, mappingModel);

        LOG.debugf("FilteredGroupClaimMapper: user=%s claim=%s groups=%s", user.getUsername(), claimName, groups);

        token.getOtherClaims().put(claimName, groups);
    }
}
