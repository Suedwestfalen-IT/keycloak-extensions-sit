package nrw.sit.keycloak.mapper;

import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * SAML counterpart of {@link FilteredGroupClaimMapper}: adds a filtered list of group paths as
 * SAML attribute, with the same path prefix / regex / full path options plus a case option
 * (keep, lower, upper).
 *
 * Like Keycloak's built-in SAML group mapper it emits either one attribute with all groups as
 * values (default) or one attribute per group.
 */
public class FilteredGroupSamlMapper extends AbstractSAMLProtocolMapper
        implements SAMLAttributeStatementMapper {

    private static final Logger LOG = Logger.getLogger(FilteredGroupSamlMapper.class);

    public static final String PROVIDER_ID = "sit-saml-filtered-group-mapper";

    static final String SINGLE_ATTRIBUTE = "single";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        // Friendly Name, SAML Attribute Name, SAML Attribute NameFormat
        AttributeStatementHelper.setConfigProperties(CONFIG_PROPERTIES);
        for (ProviderConfigProperty p : CONFIG_PROPERTIES) {
            if (AttributeStatementHelper.SAML_ATTRIBUTE_NAME.equals(p.getName())) {
                p.setDefaultValue("member");
            }
        }

        ProviderConfigProperty single = new ProviderConfigProperty();
        single.setName(SINGLE_ATTRIBUTE);
        single.setLabel("Single Group Attribute");
        single.setHelpText("If ON, all groups are values of one attribute. If OFF, one attribute per group "
                + "(same name repeated).");
        single.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        single.setDefaultValue("true");
        CONFIG_PROPERTIES.add(single);

        ProviderConfigProperty fullPath = new ProviderConfigProperty();
        fullPath.setName(FilteredGroups.FULL_PATH);
        fullPath.setLabel("Full group path");
        fullPath.setHelpText("If ON, emit full paths like '/SSO/koki/koki-user'. If OFF, emit only the group name.");
        fullPath.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        fullPath.setDefaultValue("true");
        CONFIG_PROPERTIES.add(fullPath);

        ProviderConfigProperty groupCase = new ProviderConfigProperty();
        groupCase.setName(FilteredGroups.GROUP_CASE);
        groupCase.setLabel("Group name case");
        groupCase.setHelpText("'keep' emits groups as they are, 'lower' in lower case, 'upper' in upper case. "
                + "Applied after filtering, so prefix and regex always see the original names. "
                + "Groups that become equal are emitted once.");
        groupCase.setType(ProviderConfigProperty.LIST_TYPE);
        groupCase.setOptions(FilteredGroups.CASE_OPTIONS);
        groupCase.setDefaultValue(FilteredGroups.CASE_KEEP);
        CONFIG_PROPERTIES.add(groupCase);

        ProviderConfigProperty prefix = new ProviderConfigProperty();
        prefix.setName(FilteredGroups.PATH_PREFIX);
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
        regex.setName(FilteredGroups.REGEX);
        regex.setLabel("Regex Filter");
        regex.setHelpText("Only include groups whose full path matches this regex (e.g. '^/SSO/koki/.*'). "
                + "Leave empty to skip this filter.");
        regex.setType(ProviderConfigProperty.STRING_TYPE);
        regex.setDefaultValue("");
        CONFIG_PROPERTIES.add(regex);
    }

    @Override public String getId()              { return PROVIDER_ID; }
    @Override public String getDisplayType()     { return "SIT: Filtered Group Membership (SAML)"; }
    @Override public String getDisplayCategory() { return AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY; }
    @Override public String getHelpText() {
        return "Adds a filtered list of group paths as SAML attribute. Filter by path prefix and/or regex, "
                + "optionally convert to lower or upper case.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG_PROPERTIES; }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel,
                                            KeycloakSession session, UserSessionModel userSession,
                                            AuthenticatedClientSessionModel clientSession) {
        UserModel user = userSession.getUser();
        List<String> groups = FilteredGroups.collect(user, mappingModel);
        boolean single = Boolean.parseBoolean(FilteredGroups.cfg(mappingModel, SINGLE_ATTRIBUTE, "true"));

        LOG.debugf("FilteredGroupSamlMapper: user=%s single=%s groups=%s", user.getUsername(), single, groups);

        // like the built-in mapper: no attribute at all when no group matches
        if (groups.isEmpty()) return;

        if (single) {
            AttributeType attribute = AttributeStatementHelper.createAttributeType(mappingModel);
            groups.forEach(attribute::addAttributeValue);
            attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
        } else {
            for (String group : groups) {
                AttributeType attribute = AttributeStatementHelper.createAttributeType(mappingModel);
                attribute.addAttributeValue(group);
                attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
            }
        }
    }
}
