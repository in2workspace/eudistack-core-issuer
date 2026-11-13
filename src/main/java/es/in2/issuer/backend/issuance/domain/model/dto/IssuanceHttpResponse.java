package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The HTTP wire envelope of {@code POST /api/v1/issuances} (EUD-254): one {@link
 * ChannelResponse}, for the requested delivery mode. Projected from the domain-shaped {@link
 * IssuanceResponse} by {@code IssuanceHttpEnvelopeMapper} -- the workflow keeps producing the flat
 * {@code signed_credential}/{@code credential_offer_uri}/{@code delivery_results} shape unchanged.
 */
public record IssuanceHttpResponse(
        @JsonProperty("responses") List<ChannelResponse> responses
) {
}
