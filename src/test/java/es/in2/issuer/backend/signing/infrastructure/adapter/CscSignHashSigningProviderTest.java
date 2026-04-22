package es.in2.issuer.backend.signing.infrastructure.adapter;


import org.mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@ExtendWith(MockitoExtension.class)
class CscSignHashSigningProviderTest {

    @Mock private QtspAuthClient qtspAuthClient;
    @Mock private QtspIssuerService qtspIssuerService;
    @Mock private JwsSignHashService jwsSignHashService;
    @Mock private JadesHeaderBuilderService jadesHeaderBuilder;
    @Mock private CscSigningProperties cscSigningProperties;

    private ObjectMapper objectMapper;

    private CscSignHashSigningProvider provider;

    private static RemoteSignatureDto cfg() {
        return new RemoteSignatureDto(
                "https://qtsp.example.com",
                "client", "secret", "cred-123", "password", "PT10M",
                "sign-hash"
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

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        provider = new CscSignHashSigningProvider(
                qtspAuthClient,
                qtspIssuerService,
                jwsSignHashService,
                jadesHeaderBuilder,
                cscSigningProperties,
                objectMapper
        );
    }

    @Test
    void sign_success_happyPath() {
        SigningRequest request = requestWithCfg();
        RemoteSignatureDto cfg = request.remoteSignature();

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);

        when(qtspAuthClient.requestAccessToken(request, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
                .thenReturn(Mono.just("access-token"));

        when(qtspIssuerService.requestCertificateInfo(cfg, "access-token", "cred-123"))
                .thenReturn(Mono.just(validCredentialInfoJson()));

        when(jadesHeaderBuilder.buildHeader(any(CertificateInfo.class), eq(JadesProfile.JADES_B_T), any()))
                .thenReturn("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");

        when(jwsSignHashService.signJwtWithSignHash(
                eq(cfg),
                eq("access-token"),
                eq("{\"alg\":\"ES256\",\"typ\":\"JWT\"}"),
                eq(request.data()),
                anyString()
        )).thenReturn(Mono.just("hdr.payload.sig"));

        StepVerifier.create(provider.sign(request))
                .assertNext(result -> {
                    assertEquals(SigningType.JADES, result.type());
                    assertEquals("hdr.payload.sig", result.data());
                })
                .verifyComplete();
    }

    @Test
    void sign_wraps_invalidCertInfo_statusNotValid() {
        SigningRequest request = requestWithCfg();
        RemoteSignatureDto cfg = request.remoteSignature();

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);
        when(qtspAuthClient.requestAccessToken(request, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
                .thenReturn(Mono.just("access-token"));

        when(qtspIssuerService.requestCertificateInfo(cfg, "access-token", "cred-123"))
                .thenReturn(Mono.just(invalidCertStatusJson()));

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

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);
        when(qtspAuthClient.requestAccessToken(request, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
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

    private static String validCredentialInfoJson() {
        return """
        {
          "key": {
            "status": "enabled",
            "algo": ["1.2.840.10045.4.3.2"],
            "len": 256
          },
          "cert": {
            "status": "valid",
            "certificates": ["MIIC...","MIID..."],
            "issuerDN": "CN=QTSP CA, O=QTSP, C=ES",
            "subjectDN": "CN=Issuer Org, O=Organization, C=ES",
            "serialNumber": "1234567890",
            "validFrom": "2024-01-01T00:00:00Z",
            "validTo": "2026-01-01T00:00:00Z"
          }
        }
        """;
    }

    private static String invalidCertStatusJson() {
        return """
        {
          "key": {
            "status": "enabled",
            "algo": ["1.2.840.10045.4.3.2"],
            "len": 256
          },
          "cert": {
            "status": "revoked",
            "certificates": ["MIIC..."]
          }
        }
        """;
    }
}
