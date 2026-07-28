package es.in2.issuer.backend.shared.domain.model.enums;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DeliveryModeTest {

    @Test
    void parse_deduplicatesRepeatedModes() {
        Set<DeliveryMode> modes = DeliveryMode.parse("direct,direct,email");

        assertEquals(2, modes.size());
        assertTrue(modes.contains(DeliveryMode.DIRECT));
        assertTrue(modes.contains(DeliveryMode.EMAIL));
    }

    @Test
    void parse_singleModeRepeated_collapsesToOne() {
        Set<DeliveryMode> modes = DeliveryMode.parse("direct,direct");

        assertEquals(1, modes.size());
        assertTrue(modes.contains(DeliveryMode.DIRECT));
    }

    @Test
    void parse_trimsWhitespaceAndIgnoresEmptySegments() {
        Set<DeliveryMode> modes = DeliveryMode.parse(" direct , , email ");

        assertEquals(Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL), modes);
    }

    @Test
    void isDirect_trueOnlyForDirectMode() {
        assertTrue(DeliveryMode.DIRECT.isDirect());
        assertFalse(DeliveryMode.EMAIL.isDirect());
        assertFalse(DeliveryMode.UI.isDirect());
    }

    @Test
    void parse_nullDelivery_throws() {
        assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse(null));
    }

    @Test
    void parse_blankDelivery_throws() {
        assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse("  "));
    }

    @Test
    void parse_unknownMode_throws() {
        assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse("carrier-pigeon"));
    }

    @Test
    void parse_onlySeparators_throws() {
        assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse(",,,"));
    }
}
