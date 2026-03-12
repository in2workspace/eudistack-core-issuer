package es.in2.issuer.backend.statuslist.domain.model;

import lombok.Builder;

@Builder
public record StatusListEntry(
        String id,
        String type,
        StatusPurpose statusPurpose,
        String statusListIndex,
        String statusListCredential
) {
}
