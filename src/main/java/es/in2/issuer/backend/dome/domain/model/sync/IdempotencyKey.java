package es.in2.issuer.backend.dome.domain.model.sync;

import es.in2.issuer.backend.shared.validation.ValidUuidV7;
import java.util.UUID;

public record IdempotencyKey (
        @ValidUuidV7
        UUID value
) {}
