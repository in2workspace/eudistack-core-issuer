package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.OrgContext;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceSummary;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssuanceRecordControllerTest {

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private AccessTokenService accessTokenService;

    @InjectMocks
    private IssuanceRecordController issuanceController;

    @Test
    void getAllIssuanceList() {
        // Arrange
        String organizationId = "testOrganizationId";
        OrgContext orgContext = new OrgContext(organizationId, false);

        IssuanceSummary procedureBasicInfo = IssuanceSummary.builder()
                .issuanceId(UUID.randomUUID())
                .subject("testFullName")
                .status("testStatus")
                .updated(Instant.now())
                .organizationIdentifier("id")
                .build();

        IssuanceList.IssuanceEntry issuance =
                new IssuanceList.IssuanceEntry(procedureBasicInfo);

        IssuanceList issuances = IssuanceList.builder()
                .issuances(List.of(issuance))
                .build();

        when(accessTokenService.getOrganizationContext(anyString()))
                .thenReturn(Mono.just(orgContext));

        when(issuanceService.getAllIssuancesVisibleFor(organizationId, false))
                .thenReturn(Mono.just(issuances));

        // Act
        Mono<IssuanceList> result =
                issuanceController.getAllIssuanceList("Bearer testToken");

        // Assert
        StepVerifier.create(result)
                .assertNext(procedures -> assertEquals(issuances, procedures))
                .verifyComplete();
    }

    @Test
    void getCredentialByProcedureId() {
        // Arrange
        String organizationId = "testOrganizationId";
        String issuanceId = "testProcedureId";
        OrgContext orgContext = new OrgContext(organizationId, false);

        CredentialDetails credentialDetails = CredentialDetails.builder()
                .issuanceId(UUID.randomUUID())
                .lifeCycleStatus("testCredentialStatus")
                .credential(null)
                .build();

        when(accessTokenService.getOrganizationContext(anyString()))
                .thenReturn(Mono.just(orgContext));

        when(issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(organizationId, issuanceId, false))
                .thenReturn(Mono.just(credentialDetails));

        // Act
        Mono<CredentialDetails> result =
                issuanceController.getCredentialByProcedureId("Bearer testToken", issuanceId);

        // Assert
        StepVerifier.create(result)
                .assertNext(details -> assertEquals(credentialDetails, details))
                .verifyComplete();
    }
}
