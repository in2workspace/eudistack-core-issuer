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
        return Arrays.stream(delivery.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> Arrays.stream(values())
                        .filter(m -> m.value.equals(s))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("Unknown delivery mode: " + s)))
                .collect(Collectors.toSet());
    }
}
