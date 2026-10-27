package nrw.sit.keycloak.mapper;

import java.util.ArrayList;
import java.util.List;

/**
 * Slash-separated group paths, compared segment by segment.
 *
 * A configured prefix such as {@code /SSO/ORG}, {@code SSO/ORG} or {@code /SSO/ORG/} always
 * means the two segments {@code SSO} and {@code ORG}: leading, trailing and doubled slashes are
 * ignored, and a prefix only matches a path at a segment boundary. {@code /SSO/ORG} matches
 * {@code /SSO/ORG/team} and {@code /SSO/ORG} itself, but not {@code /SSO/ORGX/team}.
 *
 * Used by {@link IdpGroupMapper} (prefixes to strip, target prefix, managed prefix) and
 * {@link FilteredGroupClaimMapper} (path prefix filter).
 */
final class GroupPath {

    private GroupPath() {}

    /** Splits a path into its non-empty segments: {@code "/SSO//ORG/"} → {@code [SSO, ORG]}. */
    static List<String> segments(String path) {
        List<String> result = new ArrayList<>();
        if (path == null) return result;
        for (String s : path.split("/")) {
            String t = s.trim();
            if (!t.isEmpty()) result.add(t);
        }
        return result;
    }

    /** Canonical form without leading, trailing or doubled slashes: {@code "/SSO//ORG/"} → {@code "SSO/ORG"}. */
    static String normalize(String path) {
        return String.join("/", segments(path));
    }

    /**
     * True when {@code path} is the prefix itself or lies below it. An empty prefix matches
     * every path.
     */
    static boolean matches(String path, String prefix) {
        return strip(path, prefix) != null;
    }

    /**
     * Removes {@code prefix} from the start of {@code path} and returns the normalized remainder
     * ({@code ""} when the path equals the prefix), or {@code null} when the prefix does not
     * match at a segment boundary.
     */
    static String strip(String path, String prefix) {
        List<String> p = segments(path);
        List<String> q = segments(prefix);
        if (q.size() > p.size() || !p.subList(0, q.size()).equals(q)) return null;
        return String.join("/", p.subList(q.size(), p.size()));
    }
}
