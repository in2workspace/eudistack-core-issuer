package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalInvalidIssuanceIdException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalIssuanceNotFoundException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalPermissionDeniedException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalTenantMismatchException;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-295: every failure of the renewal is application/problem+json, with the type the contract
 * fixes for its status. Uses the real {@link ErrorResponseFactory} so the headers are checked too.
 */
class CredentialOfferRenewalErrorHandlingTest {

    private static final String ID = "0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90";

    private IssuanceExceptionHandler handler;
    private ServerHttpRequest request;

    @BeforeEach
    void setUp() {
        handler = new IssuanceExceptionHandler(new ErrorResponseFactory());
        request = MockServerHttpRequest.post("/api/v1/issuances/" + ID + "/credential-offer").build();
    }

    @Test
    void renewal_invalidId_isBadRequestProblem() {
        var response = handler.handleRenewalInvalidIssuanceId(new RenewalInvalidIssuanceIdException("abc"), request);

        assertProblem(response, 400, "BAD_REQUEST");
    }

    @Test
    void renewal_tenantMismatch_isTenantMismatchProblem() {
        var response = handler.handleRenewalTenantMismatch(new RenewalTenantMismatchException("kpmg"), request);

        assertProblem(response, 403, "tenant_mismatch");
    }

    @Test
    void renewal_permissionDenied_isInsufficientPermissionProblem() {
        var response = handler.handleRenewalPermissionDenied(new RenewalPermissionDeniedException("no power"), request);

        assertProblem(response, 403, "insufficient_permission");
    }

    @Test
    void renewal_notFound_isIssuanceNotFoundProblemWithoutTheId() {
        var response = handler.handleRenewalIssuanceNotFound(
                new RenewalIssuanceNotFoundException("Issuance " + ID + " not found"), request);

        assertProblem(response, 404, "issuance_not_found");
        assertThat(response.getBody().detail()).doesNotContain(ID);
    }

    @Test
    void renewal_notRenewable_isOfferNotRenewableProblem() {
        var response = handler.handleOfferNotRenewable(new OfferNotRenewableException("REVOKED"), request);

        assertProblem(response, 409, "offer_not_renewable");
    }

    @Test
    void renewal_deliveryFailed_isWalletDeliveryTimeoutProblemWithRetryAfter() {
        var response = handler.handleRenewalDeliveryFailed(new RenewalDeliveryFailedException("smtp"), request);

        assertProblem(response, 503, "wallet_delivery_timeout");
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
    }

    private static void assertProblem(ResponseEntity<GlobalErrorMessage> response, int status, String type) {
        assertThat(response.getStatusCode().value()).isEqualTo(status);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().type()).isEqualTo(type);
        assertThat(response.getBody().status()).isEqualTo(status);
        assertThat(response.getBody().title()).isNotBlank();
    }
}
