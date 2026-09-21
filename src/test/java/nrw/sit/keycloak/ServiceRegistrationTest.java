package nrw.sit.keycloak;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.provider.ProviderFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the META-INF/services registration: every listed class must exist, implement the
 * SPI it is registered for, be instantiable by Keycloak's service loader and carry a unique,
 * non-blank provider id. A typo here would only surface as a missing provider at server start.
 */
class ServiceRegistrationTest {

    private static final Path SERVICES = Path.of("src/main/resources/META-INF/services");

    @Test
    void authenticatorFactories() throws Exception {
        assertRegistered(AuthenticatorFactory.class, 4);
    }

    @Test
    void requiredActionFactories() throws Exception {
        assertRegistered(RequiredActionFactory.class, 1);
    }

    @Test
    void identityProviderMappers() throws Exception {
        assertRegistered(IdentityProviderMapper.class, 1);
    }

    @Test
    void protocolMappers() throws Exception {
        assertRegistered(ProtocolMapper.class, 1);
    }

    private static void assertRegistered(Class<? extends ProviderFactory<?>> spi, int expectedCount) throws Exception {
        List<String> classNames = readServiceFile(spi);
        assertTrue(classNames.size() == expectedCount,
                spi.getSimpleName() + ": expected " + expectedCount + " entries but found " + classNames);

        Set<String> ids = new HashSet<>();
        for (String className : classNames) {
            Class<?> clazz = Class.forName(className);
            assertTrue(spi.isAssignableFrom(clazz), className + " does not implement " + spi.getName());

            ProviderFactory<?> factory = (ProviderFactory<?>) clazz.getDeclaredConstructor().newInstance();
            String id = factory.getId();
            assertFalse(id == null || id.isBlank(), className + " has a blank provider id");
            assertTrue(ids.add(id), "duplicate provider id '" + id + "' in " + spi.getSimpleName());
        }
    }

    private static List<String> readServiceFile(Class<?> spi) throws IOException {
        Path file = SERVICES.resolve(spi.getName());
        assertTrue(Files.exists(file), "missing service file " + file);
        return Files.readAllLines(file).stream()
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .collect(Collectors.toList());
    }
}
