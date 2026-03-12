package es.in2.issuer.backend.statuslist.domain.model;

import java.time.Instant;
import java.util.UUID;

public record StatusListIndexData(
        Long id,
        Long statusListId,
        Integer idx,
        UUID issuanceId,
        Instant createdAt
) { }
