package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelBody;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceHttpResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Projects the domain-shaped {@link IssuanceResponse} onto the HTTP envelope of the EUD-254 contract:
 * one {@code responses[]} entry, for the requested mode, with status 200. {@code direct} carries
 * {@code signed_credential} in its {@code body}, {@code ui} carries {@code credential_offer_uri} in it
 * <em>only when there is one</em> (see {@link #offerBody}), and {@code email} has no body -- the URI
 * was delivered inside the email, not returned to the API caller. A failed delivery never reaches this
 * mapper: the workflow raises it and it is answered as a problem.
 */
@Component
public class IssuanceHttpEnvelopeMapper {

    public IssuanceHttpResponse toHttpResponse(IssuanceResponse response) {
        List<DeliveryResult> results = response.deliveryResults();
        List<ChannelResponse> channels = results == null
                ? List.of()
                : results.stream().map(result -> toChannelResponse(result, response)).toList();
        return new IssuanceHttpResponse(channels);
    }

    private ChannelResponse toChannelResponse(DeliveryResult result, IssuanceResponse response) {
        return ChannelResponse.builder()
                .channel(result.mode())
                .status(200)
                .body(buildChannelBody(result, response))
                .build();
    }

    private ChannelBody buildChannelBody(DeliveryResult result, IssuanceResponse response) {
        DeliveryMode mode = DeliveryMode.fromValue(result.mode()).orElse(null);
        if (mode != null && mode.isDirect()) {
            return ChannelBody.builder()
                    .signedCredential(response.signedCredential())
                    .build();
        }

        if (mode != null && mode.returnsUri) {
            return offerBody(response.credentialOfferUri());
        }

        return null;
    }

    private ChannelBody offerBody(String credentialOfferUri) {
        return credentialOfferUri != null
                ? ChannelBody.builder().credentialOfferUri(credentialOfferUri).build()
                : null;
    }
}
