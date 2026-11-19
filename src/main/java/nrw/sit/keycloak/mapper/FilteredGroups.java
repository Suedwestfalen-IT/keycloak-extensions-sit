package nrw.sit.keycloak.mapper;

import org.jboss.logging.Logger;
import org.keycloak.models.GroupModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Group filtering shared by {@link FilteredGroupClaimMapper} (OIDC) and
 * {@link FilteredGroupSamlMapper} (SAML).
 *
 * Filters (both optional, combined with AND) always work on the original full path:
 *  - path prefix : segment by segment, see {@link GroupPath}
 *  - regex       : must match the whole path
 * Afterwards the value is reduced to the leaf name (if full path is off), its case is converted,
 * duplicates are removed and the list is sorted.
 */
final class FilteredGroups {

    private static final Logger LOG = Logger.getLogger(FilteredGroups.class);

    static final String PATH_PREFIX = "pathPrefix";
    static final String REGEX       = "groupRegex";
    static final String FULL_PATH   = "fullPath";
    static final String GROUP_CASE  = "groupCase";

    static final String CASE_KEEP  = "keep";
    static final String CASE_LOWER = "lower";
    static final String CASE_UPPER = "upper";
    static final List<String> CASE_OPTIONS = List.of(CASE_KEEP, CASE_LOWER, CASE_UPPER);

    private FilteredGroups() {}

    static List<String> collect(UserModel user, ProtocolMapperModel model) {
        boolean fullPath = Boolean.parseBoolean(cfg(model, FULL_PATH, "true"));
        String prefix    = cfg(model, PATH_PREFIX, "");
        Pattern pattern  = compile(cfg(model, REGEX, ""));
        String groupCase = cfg(model, GROUP_CASE, CASE_KEEP);

        return user.getGroupsStream()
                .map(FilteredGroups::buildPath)
                .filter(path -> GroupPath.matches(path, prefix))
                .filter(path -> pattern == null || pattern.matcher(path).matches())
                .map(path -> fullPath ? path : leafName(path))
                .map(value -> applyCase(value, groupCase))
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    static String applyCase(String value, String groupCase) {
        switch (groupCase) {
            case CASE_LOWER: return value.toLowerCase(Locale.ROOT);
            case CASE_UPPER: return value.toUpperCase(Locale.ROOT);
            default:         return value;
        }
    }

    /** Builds the full path of a group, e.g. /SSO/koki/koki-user */
    static String buildPath(GroupModel group) {
        Deque<String> parts = new ArrayDeque<>();
        for (GroupModel g = group; g != null; g = g.getParent()) {
            parts.addFirst(g.getName());
        }
        return "/" + String.join("/", parts);
    }

    /** Returns the last segment of a path, e.g. "koki-user" from "/SSO/koki/koki-user" */
    static String leafName(String path) {
        int idx = path.lastIndexOf('/');
        return idx >= 0 ? path.substring(idx + 1) : path;
    }

    static String cfg(ProtocolMapperModel model, String key, String def) {
        String v = model.getConfig().get(key);
        return (v == null || v.isBlank()) ? def : v;
    }

    private static Pattern compile(String regex) {
        if (regex.isEmpty()) return null;
        try {
            return Pattern.compile(regex);
        } catch (Exception e) {
            LOG.warnf("Filtered group mapper: invalid regex '%s' ignored: %s", regex, e.getMessage());
            return null;
        }
    }
}
