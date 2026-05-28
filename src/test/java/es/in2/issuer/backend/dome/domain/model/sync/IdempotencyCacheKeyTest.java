package es.in2.issuer.backend.dome.domain.model.sync;

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
        String tenant = "dome";
        IdempotencyKey idempotencyKey = new IdempotencyKey(UUID.fromString("018f3a3c-b3a1-7b34-8c11-9a1f2b3c4d5e"));
        HolderKeyThumbprint thumbprint = new HolderKeyThumbprint("N-5a-s1M9T8y3t1jP_Z2vQ-X5lY8K7G6V_x_Q_abc123=");

        IdempotencyCacheKey key1 = new IdempotencyCacheKey(tenant, idempotencyKey, thumbprint);
        IdempotencyCacheKey key2 = new IdempotencyCacheKey(tenant, idempotencyKey, thumbprint);

        assertEquals(key1, key2, "Two objects with same data must be equal");
        assertEquals(key1.hashCode(), key2.hashCode(), "The hashCode must match");
    }

    @Test
    @DisplayName("ES-05: Different holders with the same idempotency key must not collide")
    void testCollisionsProtection() {
        String tenant = "dome";
        IdempotencyKey sharedIdempotencyKey = new IdempotencyKey(UUID.fromString("018f3a3c-b3a1-7b34-8c11-9a1f2b3c4d5e"));

        HolderKeyThumbprint thumbprintHolder1 = new HolderKeyThumbprint("thumbprint-holder-1");
        HolderKeyThumbprint thumbprintHolder2 = new HolderKeyThumbprint("thumbprint-holder-2");

        IdempotencyCacheKey keyHolder1 = new IdempotencyCacheKey(tenant, sharedIdempotencyKey, thumbprintHolder1);
        IdempotencyCacheKey keyHolder2 = new IdempotencyCacheKey(tenant, sharedIdempotencyKey, thumbprintHolder2);

        assertNotEquals(keyHolder1, keyHolder2, "Keys from different holders must not be equal");

        Set<IdempotencyCacheKey> cacheSet = new HashSet<>();
        cacheSet.add(keyHolder1);
        cacheSet.add(keyHolder2);

        assertEquals(2, cacheSet.size(), "Both keys must coexist in a Set without overwriting each other");
    }
}