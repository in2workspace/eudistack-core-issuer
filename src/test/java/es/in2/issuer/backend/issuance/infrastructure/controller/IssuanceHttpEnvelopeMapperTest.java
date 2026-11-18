package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.CredentialOfferRenewal;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceHttpEnvelopeMapperTest {

    private final IssuanceHttpEnvelopeMapper mapper = new IssuanceHttpEnvelopeMapper();

    @Test
    void toHttpResponse_DirectSucceeded_BodyCarriesSignedCredential() {
        IssuanceResponse response = IssuanceResponse.builder()
                .signedCredential("signed-jwt")
                .deliveryResults(List.of(DeliveryResult.delivered("direct")))
                .build();

        List<ChannelResponse> channels = mapper.toHttpResponse(response).responses();

        assertThat(channels).hasSize(1);
        assertThat(channels.get(0).channel()).isEqualTo("direct");
        assertThat(channels.get(0).status()).isEqualTo(200);
        assertThat(channels.get(0).body().signedCredential()).isEqualTo("signed-jwt");
        assertThat(channels.get(0).body().credentialOfferUri()).isNull();
    }

    @Test
    void toHttpResponse_UiSucceeded_BodyCarriesCredentialOfferUri() {
        IssuanceResponse response = IssuanceResponse.builder()
                .credentialOfferUri("openid-credential-offer://x")
                .deliveryResults(List.of(DeliveryResult.dispatched("ui")))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.channel()).isEqualTo("ui");
        assertThat(channel.status()).isEqualTo(200);
        assertThat(channel.body().credentialOfferUri()).isEqualTo("openid-credential-offer://x");
        assertThat(channel.body().signedCredential()).isNull();
    }

    /**
     * B1 (code-review, 2026-09-04): an email dispatch never gets a URI -- {@code CredentialOfferServiceImpl}
     * only builds one for a mode that {@code returnsUri} -- so the channel reports a genuine absence (no
     * {@code body} at all), not an uninformative empty object.
     */
    @Test
    void toHttpResponse_EmailSucceeded_HasNoBody() {
        IssuanceResponse response = IssuanceResponse.builder()
                .credentialOfferUri(null)
                .deliveryResults(List.of(DeliveryResult.dispatched("email")))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.channel()).isEqualTo("email");
        assertThat(channel.status()).isEqualTo(200);
        assertThat(channel.body()).isNull();
    }

    @Test
    void toHttpResponse_NoDeliveryResults_ReturnsEmptyResponsesList() {
        IssuanceResponse response = IssuanceResponse.builder().build();

        assertThat(mapper.toHttpResponse(response).responses()).isEmpty();
    }

    @Test
    void toRenewalResponse_ui_hasOneEntryWithTheOfferUri() {
        var response = new IssuanceHttpEnvelopeMapper().toRenewalResponse(
                new CredentialOfferRenewal(
                        DeliveryMode.UI, "offer-uri"));

        assertThat(response.responses()).hasSize(1);
        assertThat(response.responses().getFirst().channel()).isEqualTo("ui");
        assertThat(response.responses().getFirst().body().credentialOfferUri())
                .isEqualTo("offer-uri");
    }

    @Test
    void toRenewalResponse_email_hasOneEntryWithoutBody() {
        var response = new IssuanceHttpEnvelopeMapper().toRenewalResponse(
                new CredentialOfferRenewal(
                        DeliveryMode.EMAIL, null));

        assertThat(response.responses()).hasSize(1);
        assertThat(response.responses().getFirst().channel()).isEqualTo("email");
        assertThat(response.responses().getFirst().status()).isEqualTo(200);
        assertThat(response.responses().getFirst().body()).isNull();
    }
}
