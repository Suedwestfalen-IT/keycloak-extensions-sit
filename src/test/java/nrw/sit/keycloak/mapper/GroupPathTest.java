package nrw.sit.keycloak.mapper;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GroupPathTest {

    @Test
    void segmentsDropEmptyPartsAndWhitespace() {
        assertEquals(List.of("SSO", "ORG"), GroupPath.segments("/SSO/ORG"));
        assertEquals(List.of("SSO", "ORG"), GroupPath.segments("SSO/ORG/"));
        assertEquals(List.of("SSO", "ORG"), GroupPath.segments("//SSO// ORG //"));
        assertEquals(List.of(), GroupPath.segments("/"));
        assertEquals(List.of(), GroupPath.segments(""));
        assertEquals(List.of(), GroupPath.segments(null));
    }

    @Test
    void normalizeProducesCanonicalForm() {
        assertEquals("SSO/ORG", GroupPath.normalize("/SSO/ORG/"));
        assertEquals("SSO/ORG", GroupPath.normalize("SSO//ORG"));
        assertEquals("", GroupPath.normalize("/"));
        assertEquals("", GroupPath.normalize(null));
    }

    @Test
    void matchesOnlyAtSegmentBoundaries() {
        assertTrue(GroupPath.matches("/SSO/ORG/team", "/SSO/ORG"));
        assertTrue(GroupPath.matches("/SSO/ORG", "/SSO/ORG"));
        assertTrue(GroupPath.matches("SSO/ORG/team", "/SSO/ORG/"));
        assertFalse(GroupPath.matches("/SSO/ORGX/team", "/SSO/ORG"));
        assertFalse(GroupPath.matches("/SSO/OR", "/SSO/ORG"));
        assertFalse(GroupPath.matches("/SSO", "/SSO/ORG"));
        assertFalse(GroupPath.matches("/Probe/SSO/ORG/team", "/SSO/ORG"));
    }

    @Test
    void emptyPrefixMatchesEverything() {
        assertTrue(GroupPath.matches("/SSO/ORG/team", ""));
        assertTrue(GroupPath.matches("/SSO/ORG/team", "/"));
        assertTrue(GroupPath.matches("", ""));
        assertEquals("SSO/ORG/team", GroupPath.strip("/SSO/ORG/team", ""));
    }

    @Test
    void stripReturnsRemainderOrNull() {
        assertEquals("team", GroupPath.strip("/SSO/ORG/team", "/SSO/ORG"));
        assertEquals("a/b", GroupPath.strip("/SSO/ORG/a/b/", "SSO/ORG/"));
        assertEquals("", GroupPath.strip("/SSO/ORG", "/SSO/ORG"));
        assertNull(GroupPath.strip("/SSO/ORGX/team", "/SSO/ORG"));
        assertNull(GroupPath.strip("/SSO", "/SSO/ORG"));
    }
}
