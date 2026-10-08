package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.impl.CredentialOfferWorkflowImpl;
import es.in2.issuer.backend.oidc4vci.domain.repository.impl.CredentialOfferCacheRepositoryImpl;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.config.CacheConfig;
import es.in2.issuer.backend.shared.infrastructure.controller.SharedExceptionHandler;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Wire-level coverage of GET /oid4vci/v1/credential-offer/{nonce}: the real controller, workflow,
 * repository, Guava-backed {@link CacheStore} (with its production TTL) and
 * {@link SharedExceptionHandler} are wired together and exercised over HTTP, asserting the full
 * RFC 7807 payload for 404 (unknown offer) and 410 (expired or consumed offer). Only the email
 * port is mocked and the clock is controllable, so expiry is tested without waiting.
 */
class CredentialOfferEndpointIntegrationTest {

    private static final String PATH = "/oid4vci/v1/credential-offer/{nonce}";
    private static final Instant START = Instant.parse("2026-09-30T10:00:00Z");

    private MutableClock clock;
    private EmailService emailService;
    private CredentialOfferCacheRepositoryImpl repository;
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(START);
        emailService = mock(EmailService.class);
        CacheStore<CredentialOfferData> store =
                new CacheStore<>(new CacheConfig().getCacheRetentionForCredentialOffer(), TimeUnit.MINUTES);
        repository = new CredentialOfferCacheRepositoryImpl(store, clock);
        CredentialOfferController controller =
                new CredentialOfferController(new CredentialOfferWorkflowImpl(repository, emailService));
        client = WebTestClient.bindToController(controller)
                .controllerAdvice(new SharedExceptionHandler(new ErrorResponseFactory()))
                .build();
    }

    @Test
    void getCredentialOffer_validOffer_returns200WithOffer() {
        String nonce = storeOffer(null);

        client.get().uri(PATH, nonce).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_issuer").isEqualTo("https://issuer.example")
                .jsonPath("$.credential_configuration_ids[0]").isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void getCredentialOffer_unknownNonce_returns404ProblemDetails() {
        client.get().uri(PATH, "hIDaRQRSQHWOX7gM8fsihQ").exchange()
                .expectStatus().isEqualTo(HttpStatus.NOT_FOUND)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("credential_offer_not_found")
                .jsonPath("$.title").isEqualTo("Credential offer not found")
                .jsonPath("$.status").isEqualTo(404)
                .jsonPath("$.detail").isEqualTo("CredentialOffer not found for nonce: hIDaRQRSQHWOX7gM8fsihQ")
                .jsonPath("$.instance").isNotEmpty();
    }

    @Test
    void getCredentialOffer_expiredOffer_returns410ProblemDetails() {
        String nonce = storeOffer(null);
        clock.advance(Duration.ofMinutes(10));

        client.get().uri(PATH, nonce).exchange()
                .expectStatus().isEqualTo(HttpStatus.GONE)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("credential_offer_expired")
                .jsonPath("$.title").isEqualTo("Credential offer expired")
                .jsonPath("$.status").isEqualTo(410)
                .jsonPath("$.detail").isEqualTo("The credential offer has expired.")
                .jsonPath("$.instance").isNotEmpty();
    }

    @Test
    void getCredentialOffer_offerExpiredHoursAgo_stillReturns410WithinRetention() {
        String nonce = storeOffer(null);
        clock.advance(Duration.ofHours(23));

        client.get().uri(PATH, nonce).exchange()
                .expectStatus().isEqualTo(HttpStatus.GONE)
                .expectBody().jsonPath("$.type").isEqualTo("credential_offer_expired");
    }

    @Test
    void getCredentialOffer_consumedOffer_returns410AndDoesNotResendTxCode() {
        String nonce = storeOffer("1234");
        when(emailService.sendTxCodeNotification(anyString(), anyString(), anyString())).thenReturn(Mono.empty());

        client.get().uri(PATH, nonce).exchange().expectStatus().isOk();

        client.get().uri(PATH, nonce).exchange()
                .expectStatus().isEqualTo(HttpStatus.GONE)
                .expectBody()
                .jsonPath("$.type").isEqualTo("credential_already_issued")
                .jsonPath("$.title").isEqualTo("Credential already issued")
                .jsonPath("$.status").isEqualTo(410)
                .jsonPath("$.detail").isEqualTo("The credential offer has already been used.");

        verify(emailService, times(1)).sendTxCodeNotification("holder@example.com", "email.tx-code", "1234");
    }

    @Test
    void getCredentialOffer_tamperedNonce_returns404() {
        String nonce = storeOffer(null);
        String tampered = nonce.substring(0, nonce.length() - 1) + (nonce.endsWith("A") ? "B" : "A");

        client.get().uri(PATH, tampered).exchange()
                .expectStatus().isEqualTo(HttpStatus.NOT_FOUND)
                .expectBody().jsonPath("$.type").isEqualTo("credential_offer_not_found");
    }

    @Test
    void getCredentialOffer_malformedNonce_returns404() {
        client.get().uri(PATH, "not a nonce!").exchange()
                .expectStatus().isEqualTo(HttpStatus.NOT_FOUND)
                .expectBody().jsonPath("$.type").isEqualTo("credential_offer_not_found");
    }

    private String storeOffer(String txCode) {
        CredentialOffer offer = CredentialOffer.builder()
                .credentialIssuer("https://issuer.example")
                .credentialConfigurationIds(List.of("learcredential.employee.w3c.4"))
                .build();
        return repository.saveCredentialOffer(CredentialOfferData.builder()
                        .credentialOffer(offer)
                        .credentialEmail("holder@example.com")
                        .txCode(txCode)
                        .build())
                .block();
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}