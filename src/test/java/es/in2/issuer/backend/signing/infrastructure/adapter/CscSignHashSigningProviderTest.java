package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CscSignHashSigningProviderTest {

    @Mock private CscPort cscPort;
    @Mock private IssuerCertificateService issuerCertificateService;
    @Mock private JwsSignHashService jwsSignHashService;
    @Mock private JadesHeaderBuilderService jadesHeaderBuilder;
    @Mock private CscSigningProperties cscSigningProperties;

    private CscSignHashSigningProvider provider;

    private static RemoteSignatureDto cfg() {
        return new RemoteSignatureDto(
                "provider",
                "1",
                "https://qtsp.test",
                "https://qtsp.test",
                "sign-hash",
                "cred-123", "pwd",
                "PT10M",
                "clientId", "clientSecret",
                "",
                "",
                "",
                "",
                ""
        );
    }

    private static SigningRequest requestWithCfg() {
        var context = new SigningContext("token", "issuanceId", "email@example.com");
        return SigningRequest.builder()
                .type(SigningType.JADES)
                .data("{\"vc\":\"unsigned\"}")
                .context(context)
                .remoteSignature(cfg())
                .build();
    }

    private static CertificateInfo validCertInfo() {
        return new CertificateInfo(
                List.of("MIIC...", "MIID..."),
                "CN=QTSP CA, O=QTSP, C=ES",
                "CN=Issuer Org, O=Organization, C=ES",
                "1234567890",
                "2024-01-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                List.of("1.2.840.10045.4.3.2"),
                256,
                false
        );
    }

    @BeforeEach
    void setUp() {
        provider = new CscSignHashSigningProvider(
                cscPort,
                issuerCertificateService,
                jwsSignHashService,
                jadesHeaderBuilder,
                cscSigningProperties
        );
    }

    @Test
    void sign_success_happyPath() {
        SigningRequest request = requestWithCfg();
        RemoteSignatureDto cfg = request.remoteSignature();
        CertificateInfo certInfo = validCertInfo();

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
                .thenReturn(Mono.just("access-token"));

        when(issuerCertificateService.requestCertificateInfo(cfg, "access-token", "cred-123"))
                .thenReturn(Mono.just(certInfo));

        when(jadesHeaderBuilder.buildHeader(certInfo, JadesProfile.JADES_B_T, request.typ()))
                .thenReturn("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");

        when(jwsSignHashService.signJwtWithSignHash(
                eq(cfg),
                eq("access-token"),
                eq("{\"alg\":\"ES256\",\"typ\":\"JWT\"}"),
                eq(request.data()),
                eq("1.2.840.10045.4.3.2")
        )).thenReturn(Mono.just("hdr.payload.sig"));

        StepVerifier.create(provider.sign(request))
                .assertNext(result -> {
                    assertEquals(SigningType.JADES, result.type());
                    assertEquals("hdr.payload.sig", result.data());
                })
                .verifyComplete();
    }

    @Test
    void sign_wraps_certInfoError_asSigningException() {
        SigningRequest request = requestWithCfg();
        RemoteSignatureDto cfg = request.remoteSignature();

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);
        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
                .thenReturn(Mono.just("access-token"));

        when(issuerCertificateService.requestCertificateInfo(cfg, "access-token", "cred-123"))
                .thenReturn(Mono.error(new RemoteSignatureException("cert revoked")));

        StepVerifier.create(provider.sign(request))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertTrue(ex.getMessage().contains("Signing failed via CSC signHash provider"));
                })
                .verify();

        verify(jwsSignHashService, never()).signJwtWithSignHash(any(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void sign_propagates_SigningException_without_doubleWrapping() {
        SigningRequest request = requestWithCfg();
        RemoteSignatureDto cfg = request.remoteSignature();

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);
        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
                .thenReturn(Mono.error(new SigningException("boom")));

        StepVerifier.create(provider.sign(request))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertEquals("boom", ex.getMessage());
                })
                .verify();
    }

    @Test
    void sign_errors_whenRemoteSignatureMissing() {
        var context = new SigningContext("token", "issuanceId", "email@example.com");
        SigningRequest request = SigningRequest.builder()
                .type(SigningType.JADES)
                .data("{\"vc\":\"unsigned\"}")
                .context(context)
                .build();

        StepVerifier.create(provider.sign(request))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertTrue(ex.getMessage().contains("tenant QTSP config missing"));
                })
                .verify();
    }
}
