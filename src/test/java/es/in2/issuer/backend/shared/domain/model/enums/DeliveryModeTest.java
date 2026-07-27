package es.in2.issuer.backend.shared.domain.model.enums;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DeliveryModeTest {

    @Nested
    class Parse {

        @Test
        void parse_singleMode_returnsMatchingEnum() {
            Set<DeliveryMode> modes = DeliveryMode.parse("email");

            assertEquals(Set.of(DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_multipleModes_returnsAllMatchingEnums() {
            Set<DeliveryMode> modes = DeliveryMode.parse("direct,email");

            assertEquals(Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_duplicatesAndWhitespace_dedupesToSingleEntry() {
            Set<DeliveryMode> modes = DeliveryMode.parse(" email , email ");

            assertEquals(Set.of(DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_unknownMode_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse("carrier-pigeon"));
        }

        @Test
        void parse_blankInput_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse("   "));
        }

        @Test
        void parse_nullInput_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse(null));
        }
    }

    @Nested
    class ToCanonicalCsv {

        @Test
        void toCanonicalCsv_multipleModes_returnsAlphabeticallySortedCsv() {
            String csv = DeliveryMode.toCanonicalCsv(EnumSet.of(DeliveryMode.UI, DeliveryMode.DIRECT, DeliveryMode.EMAIL));

            assertEquals("direct,email,ui", csv);
        }

        @Test
        void toCanonicalCsv_singleMode_returnsThatModeValue() {
            String csv = DeliveryMode.toCanonicalCsv(Set.of(DeliveryMode.EMAIL));

            assertEquals("email", csv);
        }

        @Test
        void toCanonicalCsv_emptySet_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.toCanonicalCsv(Set.of()));
        }

        @Test
        void toCanonicalCsv_nullSet_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.toCanonicalCsv(null));
        }

        @Test
        void toCanonicalCsv_thenParse_roundTripsToOriginalSet() {
            Set<DeliveryMode> original = EnumSet.of(DeliveryMode.DIRECT, DeliveryMode.UI);

            Set<DeliveryMode> roundTripped = DeliveryMode.parse(DeliveryMode.toCanonicalCsv(original));

            assertEquals(original, roundTripped);
        }

        @Test
        void toCanonicalCsv_orderOfInputDoesNotAffectOutput() {
            String csvA = DeliveryMode.toCanonicalCsv(new java.util.LinkedHashSet<>(java.util.List.of(DeliveryMode.EMAIL, DeliveryMode.DIRECT)));
            String csvB = DeliveryMode.toCanonicalCsv(new java.util.LinkedHashSet<>(java.util.List.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL)));

            assertEquals(csvA, csvB);
        }
    }
}
