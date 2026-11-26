package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.query.PagePosition;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-255 FR-03, FR-04 and AC-01 to AC-03 over real HTTP and Postgres: cursor pages that walk the
 * caller's scope once, newest last change first, the filters, and the shape errors of the contract.
 */
class IssuanceListIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final Instant T = Instant.parse("2026-10-01T09:00:00Z");

    @Autowired
    private IssuancePort issuancePort;

    @Test
    void thePages_walkTheOrganizationOnce_newestFirst_evenOnTies() {
        String organization = uniqueOrganization();
        List<Issuance> seeded = new ArrayList<>();
        seeded.add(seed(organization, T.plusSeconds(3), CredentialStatusEnum.VALID, "doctor.sd.1"));
        // Two processes with the same last change, on each side of the uuid sign bit.
        seeded.add(seed(organization, T.plusSeconds(2), CredentialStatusEnum.VALID, "doctor.sd.1", highUuid()));
        seeded.add(seed(organization, T.plusSeconds(2), CredentialStatusEnum.VALID, "doctor.sd.1", lowUuid()));
        seeded.add(seed(organization, T.plusSeconds(1), CredentialStatusEnum.REVOKED, "doctor.sd.1"));
        seeded.add(seed(organization, T, CredentialStatusEnum.DRAFT, "other.sd.1"));
        seed(uniqueOrganization(), T.plusSeconds(10), CredentialStatusEnum.VALID, "doctor.sd.1");

        List<String> walked = new ArrayList<>();
        String cursor = null;
        int pages = 0;
        do {
            Map<String, Object> page = page(organization, cursor, Map.of("limit", "2"));
            issuances(page).forEach(issuance -> walked.add((String) issuance.get("id")));
            cursor = (String) page.get("next_cursor");
            pages++;
        } while (cursor != null && pages < 10);

        List<String> expected = seeded.stream()
                .sorted(Comparator.comparing(PagePosition::of, PagePosition.NEWEST_FIRST))
                .map(issuance -> issuance.getIssuanceId().toString())
                .toList();
        assertThat(walked).containsExactlyElementsOf(expected);
        assertThat(pages).isEqualTo(3);
    }

    @Test
    void theFilters_combine() {
        String organization = uniqueOrganization();
        Issuance validDoctor = seed(organization, T.plusSeconds(3), CredentialStatusEnum.VALID, "doctor.sd.1");
        Issuance revokedDoctor = seed(organization, T.plusSeconds(2), CredentialStatusEnum.REVOKED, "doctor.sd.1");
        seed(organization, T.plusSeconds(1), CredentialStatusEnum.VALID, "other.sd.1");
        seed(organization, T, CredentialStatusEnum.DRAFT, "doctor.sd.1");

        Map<String, Object> page = page(organization, null, Map.of(
                "life_cycle_status", "VALID,REVOKED", "credential_configuration_id", "doctor.sd.1"));

        assertThat(issuances(page)).extracting(issuance -> issuance.get("id")).containsExactly(
                validDoctor.getIssuanceId().toString(), revokedDoctor.getIssuanceId().toString());
        assertThat(issuances(page).getFirst())
                .containsEntry("life_cycle_status", "VALID")
                .containsEntry("credential_configuration_id", "doctor.sd.1")
                .containsEntry("organization_identifier", organization)
                .containsEntry("updated", "2026-10-01T09:00:03Z")
                .doesNotContainKeys("credential", "tenant", "credential_offer_refresh_token", "version");
        assertThat(page).containsEntry("next_cursor", null);
    }

    /**
     * EC-04: a process already returned that changes state in the middle of a walk goes up to the top of the listing
     * and does not come out again in that walk, which goes on where it was.
     */
    @Test
    void aProcessThatChangesStateDuringAWalk_goesToTheTop_andDoesNotComeOutAgain() {
        String organization = uniqueOrganization();
        Issuance first = seed(organization, T.plusSeconds(4), CredentialStatusEnum.VALID, "doctor.sd.1");
        Issuance second = seed(organization, T.plusSeconds(3), CredentialStatusEnum.VALID, "doctor.sd.1");
        Issuance third = seed(organization, T.plusSeconds(2), CredentialStatusEnum.VALID, "doctor.sd.1");
        Issuance fourth = seed(organization, T.plusSeconds(1), CredentialStatusEnum.VALID, "doctor.sd.1");
        Map<String, Object> firstPage = page(organization, null, Map.of("limit", "2"));

        // The first process returned is revoked: its last change is now
        Issuance changed = issuancePort.findById(first.getIssuanceId())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
        changed.setCredentialStatus(CredentialStatusEnum.REVOKED);
        issuancePort.save(changed).contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        Map<String, Object> secondPage = page(organization, (String) firstPage.get("next_cursor"), Map.of("limit", "2"));

        assertThat(ids(firstPage)).containsExactly(id(first), id(second));
        assertThat(ids(secondPage)).containsExactly(id(third), id(fourth));
        assertThat(secondPage).containsEntry("next_cursor", null);
        assertThat(ids(page(organization, null, Map.of("limit", "1")))).containsExactly(id(first));
    }

    /** EC-02: limit=200, the most, and limit=1, the least, are accepted. */
    @Test
    void theLimitsOfLimit_areAccepted() {
        String organization = uniqueOrganization();
        Issuance only = seed(organization, T, CredentialStatusEnum.VALID, "doctor.sd.1");

        assertThat(ids(page(organization, null, Map.of("limit", "200")))).containsExactly(id(only));
        assertThat(ids(page(organization, null, Map.of("limit", "1")))).containsExactly(id(only));
    }

    @Test
    void aMalformedQuery_isAnInvalidRequest_withOneViolationPerField() {
        Map<String, Object> problem = problem(uniqueOrganization(), Map.of(
                "life_cycle_status", "ACTIVE", "limit", "0", "cursor", "nope"));

        assertThat(problem).containsEntry("type", "invalid_request");
        assertThat(fields(problem)).containsExactly("life_cycle_status", "limit", "cursor");
    }

    @Test
    void aCursorOfOtherFilters_isAnInvalidRequest() {
        String organization = uniqueOrganization();
        seed(organization, T.plusSeconds(2), CredentialStatusEnum.VALID, "doctor.sd.1");
        seed(organization, T.plusSeconds(1), CredentialStatusEnum.VALID, "doctor.sd.1");
        String cursor = (String) page(organization, null, Map.of("limit", "1")).get("next_cursor");

        Map<String, Object> problem = problem(organization, Map.of(
                "limit", "1", "life_cycle_status", "VALID", "cursor", cursor));

        assertThat(fields(problem)).containsExactly("cursor");
    }

    @Test
    void theTenantFilter_outsideThePlatformTenant_isAnInvalidRequest() {
        Map<String, Object> problem = problem(uniqueOrganization(), Map.of("tenant", "sandbox"));

        assertThat(fields(problem)).containsExactly("tenant");
    }

    private Map<String, Object> page(String organization, String cursor, Map<String, String> parameters) {
        UriComponentsBuilder uri = UriComponentsBuilder.fromPath("/api/v1/issuances");
        parameters.forEach(uri::queryParam);
        if (cursor != null) {
            uri.queryParam("cursor", cursor);
        }
        return webTestClient()
                .get().uri(uri.build().toUriString())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, organization))
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult()
                .getResponseBody();
    }

    private Map<String, Object> problem(String organization, Map<String, String> parameters) {
        UriComponentsBuilder uri = UriComponentsBuilder.fromPath("/api/v1/issuances");
        parameters.forEach(uri::queryParam);
        return webTestClient()
                .get().uri(uri.build().toUriString())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, organization))
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult()
                .getResponseBody();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> issuances(Map<String, Object> page) {
        return (List<Map<String, Object>>) page.get("issuances");
    }

    private static List<Object> ids(Map<String, Object> page) {
        return issuances(page).stream().map(issuance -> issuance.get("id")).toList();
    }

    private static String id(Issuance issuance) {
        return issuance.getIssuanceId().toString();
    }

    @SuppressWarnings("unchecked")
    private static List<String> fields(Map<String, Object> problem) {
        return ((List<Map<String, Object>>) problem.get("violations")).stream()
                .map(violation -> (String) violation.get("field"))
                .toList();
    }

    private Issuance seed(String organization, Instant lastChangedAt, CredentialStatusEnum status, String entry) {
        return seed(organization, lastChangedAt, status, entry, UUID.randomUUID());
    }

    private Issuance seed(String organization, Instant lastChangedAt, CredentialStatusEnum status, String entry, UUID id) {
        Issuance issuance = Issuance.builder()
                .issuanceId(id)
                .credentialFormat("dc+sd-jwt")
                .credentialDataSet("{}")
                .credentialStatus(status)
                .organizationIdentifier(organization)
                .credentialType(entry)
                .email("holder@example.com")
                .delivery("email")
                .lastChangedAt(lastChangedAt.truncatedTo(ChronoUnit.MICROS))
                .build();
        return issuancePort.insert(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
    }

    private static String uniqueOrganization() {
        return "VATES-LIST-" + UUID.randomUUID();
    }

    /** First byte 0x80 or more: negative for UUID.compareTo, greater for Postgres. */
    private static UUID highUuid() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return new UUID(random.nextLong() | Long.MIN_VALUE, random.nextLong());
    }

    private static UUID lowUuid() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return new UUID(random.nextLong() & Long.MAX_VALUE, random.nextLong());
    }
}
