package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelBody;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelError;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceHttpResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Projects the domain-shaped {@link IssuanceResponse} (still flat: {@code signedCredential} /
 * {@code credentialOfferUri} / {@code deliveryResults}, produced by {@code IssuanceWorkflowImpl}
 * unchanged) onto the HTTP envelope EUD-167 D-5/D-6 specifies: one {@code responses[]} entry per
 * requested channel, {@code direct} carrying {@code signed_credential} in its {@code body} and
 * {@code ui}/{@code email} carrying {@code credential_offer_uri} -- or an RFC 9457 {@code error} for
 * a failed channel. {@link IssuanceController} decides the response-line HTTP status (200/207/500)
 * from the same {@code deliveryResults}; this mapper only shapes the body.
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
        return result.status() == DeliveryResult.DeliveryOutcome.FAILED
                ? failedChannel(result)
                : succeededChannel(result, response);
    }

    private ChannelResponse succeededChannel(DeliveryResult result, IssuanceResponse response) {
        // direct signs synchronously in this same request and returns the credential itself; ui/email
        // both point at the same dispatched OID4VCI offer, just delivered through a different channel.
        ChannelBody body = DeliveryMode.DIRECT.value.equals(result.mode())
                ? ChannelBody.builder().signedCredential(response.signedCredential()).build()
                : ChannelBody.builder().credentialOfferUri(response.credentialOfferUri()).build();
        return ChannelResponse.builder()
                .channel(result.mode())
                .status(200)
                .body(body)
                .build();
    }

    private ChannelResponse failedChannel(DeliveryResult result) {
        // A stuck dependency times out (504); every other classified stage is a dependency/processing
        // failure the caller cannot retry differently (503). Never the caller's fault -> never 4xx here.
        int status = DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.value().equals(result.error())
                ? 504
                : 503;
        ChannelError error = ChannelError.builder()
                .type(result.error())
                .title(titleFor(result.error()))
                .status(status)
                .detail("Delivery failed for channel '" + result.mode() + "'")
                .build();
        return ChannelResponse.builder()
                .channel(result.mode())
                .status(status)
                .error(error)
                .build();
    }

    private String titleFor(String code) {
        for (DeliveryErrorCode candidate : DeliveryErrorCode.values()) {
            if (candidate.value().equals(code)) {
                return candidate.title();
            }
        }
        return "Delivery failed";
    }
}
