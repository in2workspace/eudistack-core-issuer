package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.domain.util.sdjwt.SdJwtPayloadBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
class CredentialSignerWorkflowImplTest {

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private SigningProvider signingProvider;

    @Mock
    private GenericCredentialBuilder genericCredentialBuilder;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @Mock
    private SdJwtPayloadBuilder sdJwtPayloadBuilder;

    @InjectMocks
    private CredentialSignerWorkflowImpl credentialSignerWorkflow;

    private final String token = "some-token";
    private final String issuanceId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
    private final String email = "alice@example.com";

    private CredentialProfile buildProfile(String credentialType) {
        return CredentialProfile.builder()
                .credentialConfigurationId(credentialType + "_config")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", credentialType)).build())
                .build();
    }

    @Test
    void signCredential_jwtVcJson_success() {
        String enrichedDataSet = "enrichedData";
        String unsignedPayload = "{\"vc\":{\"credentialSubject\":{\"name\":\"Test\"}}}";
        String signedCredential = "signed-jwt";

        CredentialProfile profile = buildProfile("learcredential.employee.w3c.4");
        when(credentialProfileRegistry.getByConfigurationId("learcredential.employee.w3c.4")).thenReturn(profile);

        when(genericCredentialBuilder.buildJwtPayload(eq(profile), eq(enrichedDataSet), any()))
                .thenReturn(Mono.just(unsignedPayload));
        when(signingProvider.sign(any()))
                .thenReturn(Mono.just(new SigningResult(SigningType.JADES, signedCredential)));

        StepVerifier.create(
                        credentialSignerWorkflow.signCredential(
                                token, enrichedDataSet, "learcredential.employee.w3c.4",
                                JWT_VC_JSON, Collections.emptyMap(), issuanceId, email)
                )
                .assertNext(result -> assertEquals(signedCredential, result))
                .verifyComplete();

        verify(genericCredentialBuilder).buildJwtPayload(eq(profile), eq(enrichedDataSet), any());
        verify(signingProvider).sign(any());
    }

    @Test
    void signCredential_unsupportedCredentialType_throwsError() {
        when(credentialProfileRegistry.getByConfigurationId("UNKNOWN_TYPE")).thenReturn(null);

        StepVerifier.create(
                        credentialSignerWorkflow.signCredential(
                                token, "dataSet", "UNKNOWN_TYPE",
                                JWT_VC_JSON, Collections.emptyMap(), issuanceId, email)
                )
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().contains("Unsupported credential type: UNKNOWN_TYPE")
                )
                .verify();
    }

    @Test
    void signCredential_unsupportedFormat_throwsError() {
        String enrichedDataSet = "enrichedData";

        CredentialProfile profile = buildProfile("learcredential.employee.w3c.4");
        when(credentialProfileRegistry.getByConfigurationId("learcredential.employee.w3c.4")).thenReturn(profile);

        when(genericCredentialBuilder.buildJwtPayload(eq(profile), eq(enrichedDataSet), any()))
                .thenReturn(Mono.just("{\"vc\":{}}"));

        StepVerifier.create(
                        credentialSignerWorkflow.signCredential(
                                token, enrichedDataSet, "learcredential.employee.w3c.4",
                                "unsupported_format", Collections.emptyMap(), issuanceId, email)
                )
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().contains("Unsupported credential format")
                )
                .verify();
    }

    @Test
    void signCredential_withNullCnf_defaultsToEmptyMap() {
        String enrichedDataSet = "enrichedData";
        String unsignedPayload = "{\"vc\":{\"credentialSubject\":{\"name\":\"Test\"}}}";
        String signedCredential = "signed-jwt";

        CredentialProfile profile = buildProfile("learcredential.machine.w3c.3");
        when(credentialProfileRegistry.getByConfigurationId("learcredential.machine.w3c.3")).thenReturn(profile);

        when(genericCredentialBuilder.buildJwtPayload(eq(profile), eq(enrichedDataSet), any()))
                .thenReturn(Mono.just(unsignedPayload));
        when(signingProvider.sign(any()))
                .thenReturn(Mono.just(new SigningResult(SigningType.JADES, signedCredential)));

        StepVerifier.create(
                        credentialSignerWorkflow.signCredential(
                                token, enrichedDataSet, "learcredential.machine.w3c.3",
                                JWT_VC_JSON, null, issuanceId, email)
                )
                .assertNext(result -> assertEquals(signedCredential, result))
                .verifyComplete();
    }

    @Test
    void signCredential_setsSubFromCredentialSubjectId() {
        String enrichedDataSet = "enrichedData";
        String unsignedPayload = "{\"vc\":{\"credentialSubject\":{\"id\":\"did:example:123\",\"name\":\"Test\"}}}";
        String signedCredential = "signed-jwt-with-sub";

        CredentialProfile profile = buildProfile("learcredential.employee.w3c.4");
        when(credentialProfileRegistry.getByConfigurationId("learcredential.employee.w3c.4")).thenReturn(profile);

        when(genericCredentialBuilder.buildJwtPayload(eq(profile), eq(enrichedDataSet), any()))
                .thenReturn(Mono.just(unsignedPayload));
        when(signingProvider.sign(any()))
                .thenReturn(Mono.just(new SigningResult(SigningType.JADES, signedCredential)));

        StepVerifier.create(
                        credentialSignerWorkflow.signCredential(
                                token, enrichedDataSet, "learcredential.employee.w3c.4",
                                JWT_VC_JSON, Map.of(), issuanceId, email)
                )
                .assertNext(result -> assertEquals(signedCredential, result))
                .verifyComplete();

        verify(signingProvider).sign(any());
    }
}
