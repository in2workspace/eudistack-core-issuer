package es.in2.issuer.backend.signing.infrastructure.adapter;


import org.mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
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
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@ExtendWith(MockitoExtension.class)
class CscSignHashSigningProviderTest {

    @Mock private QtspAuthClient qtspAuthClient;
    @Mock private QtspIssuerService qtspIssuerService;
    @Mock private JwsSignHashService jwsSignHashService;
    @Mock private JadesHeaderBuilderService jadesHeaderBuilder;
    @Mock private CscSigningProperties cscSigningProperties;

    private ObjectMapper objectMapper;

    private CscSignHashSigningProvider provider;

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
        // given
        var context = new SigningContext("token", "procedureId", "email@example.com");
        var request = new SigningRequest(SigningType.JADES, "{\"vc\":\"unsigned\"}", context);

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);

        when(qtspAuthClient.requestAccessToken(request, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
                .thenReturn(Mono.just("access-token"));

        when(qtspIssuerService.getCredentialId()).thenReturn("cred-123");
        when(qtspIssuerService.requestCertificateInfo("access-token", "cred-123"))
                .thenReturn(Mono.just(validCredentialInfoJson()));

        when(jadesHeaderBuilder.buildHeader(any(CertificateInfo.class), eq(JadesProfile.JADES_B_T)))
                .thenReturn("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");

        when(jwsSignHashService.signJwtWithSignHash(
                "access-token",
               "{\"alg\":\"ES256\",\"typ\":\"JWT\"}",
                request.data()
        )).thenReturn(Mono.just("hdr.payload.sig"));

        // when + then
        StepVerifier.create(provider.sign(request))
                .assertNext(result -> {
                    assertEquals(SigningType.JADES, result.type());
                    assertEquals("hdr.payload.sig", result.data());
                })
                .verifyComplete();
    }

    @Test
    void sign_wraps_invalidCertInfo_statusNotValid() {
        // given
        var context = new SigningContext("token", "procedureId", "email@example.com");
        var request = new SigningRequest(SigningType.JADES, "{\"vc\":\"unsigned\"}", context);

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);
        when(qtspAuthClient.requestAccessToken(request,
                SIGNATURE_REMOTE_SCOPE_CREDENTIAL,
                false))
                .thenReturn(Mono.just("access-token"));
        when(qtspIssuerService.getCredentialId()).thenReturn("cred-123");

        // cert.status != valid -> IllegalStateException -> onErrorMap => SigningException (wrap)
        when(qtspIssuerService.requestCertificateInfo("access-token", "cred-123"))
                .thenReturn(Mono.just(invalidCertStatusJson()));

        StepVerifier.create(provider.sign(request))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertTrue(ex.getMessage().contains("Signing failed via CSC signHash provider"));
                })
                .verify();

        verify(jwsSignHashService, never()).signJwtWithSignHash(anyString(), anyString(), anyString());
    }

    @Test
    void sign_propagates_SigningException_without_doubleWrapping() {
        // given: contexto NO nulo para pasar la validación
        var context = new SigningContext("token", "procedureId", "email@example.com");
        var request = new SigningRequest(SigningType.JADES, "{\"vc\":\"unsigned\"}", context);

        when(cscSigningProperties.signatureProfile()).thenReturn(JadesProfile.JADES_B_T);

        when(qtspAuthClient.requestAccessToken(request, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false))
                .thenReturn(Mono.error(new SigningException("boom")));

        // when + then
        StepVerifier.create(provider.sign(request))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof SigningException);
                    assertEquals("boom", ex.getMessage());
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