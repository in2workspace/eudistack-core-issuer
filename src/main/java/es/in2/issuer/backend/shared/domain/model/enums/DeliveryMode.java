package es.in2.issuer.backend.shared.domain.model.enums;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public enum DeliveryMode {

    EMAIL("email",   true,  false),
    UI   ("ui",      true,  true),
    DIRECT("direct", false, false);

    public final String value;
    public final boolean isOid4vci;
    public final boolean returnsUri;

    DeliveryMode(String value, boolean isOid4vci, boolean returnsUri) {
        this.value = value;
        this.isOid4vci = isOid4vci;
        this.returnsUri = returnsUri;
    }

    public static Set<DeliveryMode> parse(String delivery) {
        if (delivery == null || delivery.isBlank()) {
            throw new IllegalArgumentException("Delivery mode must not be null or blank");
        }

        Set<DeliveryMode> modes = Arrays.stream(delivery.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> Arrays.stream(values())
                        .filter(m -> m.value.equals(s))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("Unknown delivery mode: " + s)))
                .collect(Collectors.toSet());

        if (modes.isEmpty()) {
            throw new IllegalArgumentException("At least one delivery mode is required");
        }

        return modes;
    }
}
