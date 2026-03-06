package es.in2.issuer.backend.statuslist.domain.model;

import java.time.Instant;

public record StatusListData(
        Long id,
        String purpose,
        String format,
        String encodedList,
        String signedCredential,
        Instant createdAt,
        Instant updatedAt
) { }
