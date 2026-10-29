package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceIdsTest {

    @Test
    void IssuanceIds_parse_acceptsACanonicalUuid() {
        UUID id = UUID.randomUUID();

        assertThat(IssuanceIds.parse(id.toString())).contains(id);
    }

    @Test
    void IssuanceIds_parse_acceptsACanonicalUuidInUpperCase() {
        UUID id = UUID.randomUUID();

        assertThat(IssuanceIds.parse(id.toString().toUpperCase())).contains(id);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "not-a-uuid", "1-1-1-1-1", "0c0dbbc0-0110-43d1-be43-32c0780f0ed6x"})
    void IssuanceIds_parse_rejectsAnythingElse(String id) {
        assertThat(IssuanceIds.parse(id)).isEmpty();
    }
}
