package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record IssuanceList(

        @JsonProperty("credential_procedures") List<IssuanceList.IssuanceEntry> credentialProcedures
) {

    @Builder
    public record IssuanceEntry(
            @JsonProperty("credential_procedure")
            IssuanceSummary credentialProcedure
    ){}

}
