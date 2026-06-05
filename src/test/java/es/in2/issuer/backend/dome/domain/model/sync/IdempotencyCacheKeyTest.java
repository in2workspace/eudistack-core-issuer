package es.in2.issuer.backend.dome.domain.model.sync;

import es.in2.issuer.backend.dome.DomeSyncFixtureFactory;
import es.in2.issuer.backend.shared.domain.util.Constants;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class IdempotencyCacheKeyTest {

    @Test
    @DisplayName("ES-05: equals() and hashCode() must work correctly to avoid collisions")
    void testEqualsAndHashCode() {
        IdempotencyKey idempotencyKey = new IdempotencyKey(UUID.fromString("018f3a3c-b3a1-7b34-8c11-9a1f2b3c4d5e"));
        HolderKeyThumbprint thumbprint = new HolderKeyThumbprint(DomeSyncFixtureFactory.HOLDER_1_THUMBPRINT);

        IdempotencyCacheKey key1 = new IdempotencyCacheKey(Constants.TENANT_DOME, idempotencyKey, thumbprint);
        IdempotencyCacheKey key2 = new IdempotencyCacheKey(Constants.TENANT_DOME, idempotencyKey, thumbprint);

        assertEquals(key1, key2, "Two objects with same data must be equal");
        assertEquals(key1.hashCode(), key2.hashCode(), "The hashCode must match");
    }

    @Test
    @DisplayName("ES-05: Different holders with the same idempotency key must not collide")
    void testCollisionsProtection() {

        IdempotencyKey sharedIdempotencyKey = new IdempotencyKey(UUID.fromString("018f3a3c-b3a1-7b34-8c11-9a1f2b3c4d5e"));

        HolderKeyThumbprint thumbprintHolder1 = new HolderKeyThumbprint(DomeSyncFixtureFactory.HOLDER_1_THUMBPRINT);
        HolderKeyThumbprint thumbprintHolder2 = new HolderKeyThumbprint(DomeSyncFixtureFactory.HOLDER_2_THUMBPRINT);

        IdempotencyCacheKey keyHolder1 = new IdempotencyCacheKey(Constants.TENANT_DOME, sharedIdempotencyKey, thumbprintHolder1);
        IdempotencyCacheKey keyHolder2 = new IdempotencyCacheKey(Constants.TENANT_DOME, sharedIdempotencyKey, thumbprintHolder2);

        assertNotEquals(keyHolder1, keyHolder2, "Keys from different holders must not be equal");

        Set<IdempotencyCacheKey> cacheSet = new HashSet<>();
        cacheSet.add(keyHolder1);
        cacheSet.add(keyHolder2);

        assertEquals(2, cacheSet.size(), "Both keys must coexist in a Set without overwriting each other");
    }
}