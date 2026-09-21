package nrw.sit.keycloak.mapper;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdpGroupMapperTest {

    // ── parsePrefixes ────────────────────────────────────────────────────────

    @Test
    void parsePrefixesReturnsEmptyListForBlankConfig() {
        assertTrue(IdpGroupMapper.parsePrefixes(null).isEmpty());
        assertTrue(IdpGroupMapper.parsePrefixes("").isEmpty());
        assertTrue(IdpGroupMapper.parsePrefixes("   ").isEmpty());
    }

    @Test
    void parsePrefixesKeepsSingleValueForBackwardsCompatibility() {
        assertEquals(List.of("/SSO"), IdpGroupMapper.parsePrefixes("/SSO"));
        assertEquals(List.of("/SSO"), IdpGroupMapper.parsePrefixes("  /SSO  "));
    }

    @Test
    void parsePrefixesSplitsAtCommaNewlineAndKeycloakDelimiter() {
        assertEquals(List.of("/AA", "/B"), IdpGroupMapper.parsePrefixes("/AA, /B"));
        assertEquals(List.of("/AA", "/B"), IdpGroupMapper.parsePrefixes("/AA\n/B"));
        assertEquals(List.of("/AA", "/B"), IdpGroupMapper.parsePrefixes("/AA\r\n/B"));
        assertEquals(List.of("/AA", "/B"), IdpGroupMapper.parsePrefixes("/AA##/B"));
    }

    @Test
    void parsePrefixesAcceptsJsonArrayStyleValues() {
        assertEquals(List.of("/AA", "/B"), IdpGroupMapper.parsePrefixes("[\"/AA\", \"/B\"]"));
    }

    @Test
    void parsePrefixesDropsEmptyAndDuplicateEntries() {
        assertEquals(List.of("/A"), IdpGroupMapper.parsePrefixes("/A,,/A, "));
    }

    @Test
    void parsePrefixesSortsByLengthDescending() {
        assertEquals(List.of("/PartnerAB", "/PartnerA"),
                IdpGroupMapper.parsePrefixes("/PartnerA, /PartnerAB"));
    }

    // ── stripPrefix ──────────────────────────────────────────────────────────

    @Test
    void stripPrefixRemovesAnyOfTheConfiguredPrefixes() {
        List<String> prefixes = IdpGroupMapper.parsePrefixes("/PartnerA, /PartnerB, /PartnerC");
        assertEquals("team-1", IdpGroupMapper.stripPrefix("/PartnerA/team-1", prefixes));
        assertEquals("team-2", IdpGroupMapper.stripPrefix("/PartnerB/team-2", prefixes));
        assertEquals("team-9", IdpGroupMapper.stripPrefix("/PartnerC/team-9", prefixes));
    }

    @Test
    void stripPrefixKeepsNestedPathBelowThePrefix() {
        List<String> prefixes = IdpGroupMapper.parsePrefixes("/PartnerA");
        assertEquals("koki/koki-user", IdpGroupMapper.stripPrefix("/PartnerA/koki/koki-user", prefixes));
    }

    @Test
    void stripPrefixPassesNonMatchingValuesThrough() {
        List<String> prefixes = IdpGroupMapper.parsePrefixes("/PartnerA, /PartnerB");
        assertEquals("Other/y", IdpGroupMapper.stripPrefix("/Other/y", prefixes));
        assertEquals("Other/y", IdpGroupMapper.stripPrefix("Other/y", prefixes));
    }

    @Test
    void stripPrefixPrefersTheLongestMatchingPrefix() {
        List<String> prefixes = IdpGroupMapper.parsePrefixes("/PartnerA, /PartnerAB");
        assertEquals("x", IdpGroupMapper.stripPrefix("/PartnerAB/x", prefixes));
        assertEquals("y", IdpGroupMapper.stripPrefix("/PartnerA/y", prefixes));
    }

    @Test
    void stripPrefixStripsLeadingSlashesWithoutConfiguredPrefix() {
        assertEquals("admins", IdpGroupMapper.stripPrefix("/admins", Collections.emptyList()));
        assertEquals("admins", IdpGroupMapper.stripPrefix("/admins", IdpGroupMapper.parsePrefixes("/")));
    }
}
