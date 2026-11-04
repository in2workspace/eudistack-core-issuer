package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The detail of a process of another organization answers like one that does not exist, so an
 * organization administrator holding an id cannot tell whether it exists. An id that is not a UUID cannot
 * name a process, so it answers 400 and discloses nothing (EUD-307).
 */
class IssuanceDetailNotFoundIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final String ORGANIZATION = "org-of-the-caller-detail-it";
    private static final String OTHER_ORGANIZATION = "other-org-detail-it";
    private static final String INSTANCE = "instance";

    @Autowired
    private IssuancePort issuancePort;

    @Test
    void getIssuance_outOfScopeAndUnknown_answerTheSame() {
        // Given
        String outOfScope = seedIssuanceOf(OTHER_ORGANIZATION).toString();
        String unknown = UUID.randomUUID().toString();

        // When
        Map<String, Object> outOfScopeBody = errorBody(outOfScope, HttpStatus.NOT_FOUND);
        Map<String, Object> unknownBody = errorBody(unknown, HttpStatus.NOT_FOUND);

        // Then
        assertThat(outOfScopeBody).containsEntry("type", "issuance_not_found");
        assertThat(withoutInstance(unknownBody)).isEqualTo(withoutInstance(outOfScopeBody));
        assertThat(outOfScopeBody.toString()).doesNotContain(outOfScope);
        assertThat(unknownBody.toString()).doesNotContain(unknown);
    }

    @Test
    void getIssuance_malformedId_answersBadRequestWithoutEchoingIt() {
        // Given
        String malformed = "not-a-uuid";

        // When
        Map<String, Object> body = errorBody(malformed, HttpStatus.BAD_REQUEST);

        // Then
        assertThat(body).containsEntry("type", "BAD_REQUEST");
        assertThat(body.toString()).doesNotContain(malformed);
    }

    private Map<String, Object> errorBody(String id, HttpStatus status) {
        return webTestClient()
                .get().uri("/api/v1/issuances/{id}", id)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, ORGANIZATION))
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectStatus().isEqualTo(status)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult()
                .getResponseBody();
    }

    private static Map<String, Object> withoutInstance(Map<String, Object> body) {
        Map<String, Object> copy = new HashMap<>(body);
        copy.remove(INSTANCE);
        return copy;
    }

    private UUID seedIssuanceOf(String organization) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{}")
                .credentialStatus(CredentialStatusEnum.VALID)
                .organizationIdentifier(organization)
                .credentialType("learcredential.employee.w3c.4")
                .email("holder@example.com")
                .delivery("email")
                .build();
        return issuancePort.insert(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .map(Issuance::getIssuanceId)
                .block();
    }
}
