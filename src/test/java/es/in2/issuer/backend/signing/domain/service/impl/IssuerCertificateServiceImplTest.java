package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_SERVICE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuerCertificateServiceImplTest {

    @Mock private CscPort cscPort;

    @InjectMocks
    private IssuerCertificateServiceImpl issuerCertificateService;

    private static RemoteSignatureDto cfg() {
        return new RemoteSignatureDto(
                "provider",
                "1",
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

    private static CertificateInfo certInfo(String subjectDN, String serialNumber, List<String> certs) {
        return new CertificateInfo(certs, "CN=CA", subjectDN, serialNumber,
                "2024-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
                List.of("1.2.840.10045.4.3.2"), 256);
    }

    @Test
    void validateCredentials_returnsTrueWhenValid() {
        RemoteSignatureDto cfg = cfg();
        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_SERVICE, true))
                .thenReturn(Mono.just("token"));
        when(cscPort.validateCredentialId(cfg, "token", "cred-123"))
                .thenReturn(Mono.just(true));

        StepVerifier.create(issuerCertificateService.validateCredentials(cfg))
                .assertNext(valid -> assertThat(valid).isTrue())
                .verifyComplete();
    }

    @Test
    void validateCredentials_returnsFalseWhenInvalid() {
        RemoteSignatureDto cfg = cfg();
        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_SERVICE, true))
                .thenReturn(Mono.just("token"));
        when(cscPort.validateCredentialId(cfg, "token", "cred-123"))
                .thenReturn(Mono.just(false));

        StepVerifier.create(issuerCertificateService.validateCredentials(cfg))
                .assertNext(valid -> assertThat(valid).isFalse())
                .verifyComplete();
    }

    @Test
    void requestCertificateInfo_fetchesFromPort() {
        RemoteSignatureDto cfg = cfg();
        CertificateInfo expected = certInfo("CN=Test,O=Org,C=ES", "123", List.of("MIIC..."));

        when(cscPort.getCredentialInfo(cfg, "token", "cred-123"))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(issuerCertificateService.requestCertificateInfo(cfg, "token", "cred-123"))
                .assertNext(info -> assertThat(info).isEqualTo(expected))
                .verifyComplete();
    }

    @Test
    void requestCertificateInfo_returnsCachedResult_onSecondCall() {
        RemoteSignatureDto cfg = cfg();
        CertificateInfo expected = certInfo("CN=Test,O=Org,C=ES", "123", List.of("MIIC..."));

        when(cscPort.getCredentialInfo(cfg, "token", "cred-123"))
                .thenReturn(Mono.just(expected));

        issuerCertificateService.requestCertificateInfo(cfg, "token", "cred-123").block();
        issuerCertificateService.requestCertificateInfo(cfg, "token", "cred-123").block();

        verify(cscPort, times(1)).getCredentialInfo(any(), anyString(), anyString());
    }

    @Test
    void resolveRemoteDetailedIssuer_validCredentials_returnsIssuer() {
        RemoteSignatureDto cfg = cfg();

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_SERVICE, true))
                .thenReturn(Mono.just("token-1"));
        when(cscPort.validateCredentialId(cfg, "token-1", "cred-123"))
                .thenReturn(Mono.just(true));

        String orgId = "ORGID";
        String base64Cert = Base64.getEncoder()
                .encodeToString(("organizationIdentifier=" + orgId).getBytes(StandardCharsets.UTF_8));

        CertificateInfo certInfo = certInfo("CN=Test,O=Org,C=ES", "123", List.of(base64Cert));
        when(cscPort.getCredentialInfo(cfg, "token-1", "cred-123"))
                .thenReturn(Mono.just(certInfo));

        StepVerifier.create(issuerCertificateService.resolveRemoteDetailedIssuer(cfg))
                .assertNext(i -> {
                    assertThat(i.organizationIdentifier()).isEqualTo("ORGID");
                    assertThat(i.id()).isEqualTo("did:elsi:ORGID");
                    assertThat(i.organization()).isEqualTo("Org");
                    assertThat(i.country()).isEqualTo("ES");
                    assertThat(i.commonName()).isEqualTo("Test");
                    assertThat(i.serialNumber()).isEqualTo("123");
                })
                .verifyComplete();
    }

    @Test
    void resolveRemoteDetailedIssuer_invalidCredentials_returnsError() {
        RemoteSignatureDto cfg = cfg();

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_SERVICE, true))
                .thenReturn(Mono.just("access-token"));
        when(cscPort.validateCredentialId(cfg, "access-token", "cred-123"))
                .thenReturn(Mono.just(false));

        StepVerifier.create(issuerCertificateService.resolveRemoteDetailedIssuer(cfg))
                .expectErrorMatches(e -> e.getMessage().contains("Credentials mismatch"))
                .verify();
    }
}
