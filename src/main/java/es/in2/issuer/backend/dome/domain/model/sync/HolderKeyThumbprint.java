package es.in2.issuer.backend.dome.domain.model.sync;

import es.in2.issuer.backend.shared.validation.HexString;

public record HolderKeyThumbprint (
        @HexString(length = 64)
        String value
) {}

