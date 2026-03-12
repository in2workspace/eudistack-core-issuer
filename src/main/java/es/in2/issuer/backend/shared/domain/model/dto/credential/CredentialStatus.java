package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import lombok.Builder;

@Builder
public record CredentialStatus(
        @JsonProperty("id") String id,
        @JsonProperty("type") String type,
        @JsonProperty("statusPurpose") String statusPurpose,
        @JsonProperty("statusListIndex") String statusListIndex,
        @JsonProperty("statusListCredential") String statusListCredential
) {
    public static CredentialStatus fromStatusListEntry(StatusListEntry entry) {
        return CredentialStatus.builder()
                .id(entry.id())
                .type(entry.type())
                .statusPurpose(entry.statusPurpose().value())
                .statusListIndex(entry.statusListIndex())
                .statusListCredential(entry.statusListCredential())
                .build();
    }
}
