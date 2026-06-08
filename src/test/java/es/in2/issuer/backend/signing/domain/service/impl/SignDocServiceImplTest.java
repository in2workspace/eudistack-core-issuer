package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.signing.domain.exception.SignatureProcessingException;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.domain.util.JwtUtils;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SignDocServiceImplTest {

    @Mock private CscPort cscPort;
    @Mock private JwtUtils jwtUtils;

    @InjectMocks
    private SignDocServiceImpl signDocService;

    private static final String SIGN_ALGO_OID = "OID_sign_algorithm";

    private static RemoteSignatureDto cfg() {
        return new RemoteSignatureDto(
                "provider",
                "1",
                "https://api.external.com",
                "sign-doc",
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

    private static SigningRequest request(SigningType type, String data) {
        SigningContext context = new SigningContext("token", "proc", "email");
        return SigningRequest.builder()
                .type(type)
                .data(data)
                .context(context)
                .remoteSignature(cfg())
                .build();
    }

    @Test
    void signIssuedCredential_success() {
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        RemoteSignatureDto cfg = req.remoteSignature();

        String signedJwt = "signed-jwt";
        String signedB64 = Base64.getEncoder().encodeToString(signedJwt.getBytes(StandardCharsets.UTF_8));
        CertificateInfo certInfo = new CertificateInfo(List.of(), null, null, null, null, null, List.of(SIGN_ALGO_OID), null);

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, req.data()))
                .thenReturn(Mono.just("access-token"));
        when(cscPort.getCredentialInfo(cfg, "access-token", cfg.credentialId()))
                .thenReturn(Mono.just(certInfo));
        when(cscPort.authorizeForDoc(cfg, "access-token"))
                .thenReturn(Mono.just("sad-123"));
        when(cscPort.signDoc(eq(cfg), eq("access-token"), eq("sad-123"), anyString(), eq(SIGN_ALGO_OID)))
                .thenReturn(Mono.just(signedB64));
        when(jwtUtils.decodePayload(signedJwt)).thenReturn("{\"vc\":1}");
        when(jwtUtils.areJsonsEqual("{\"vc\":1}", req.data())).thenReturn(true);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .assertNext(result -> {
                    assertThat(result.type()).isEqualTo(SigningType.JADES);
                    assertThat(result.data()).isEqualTo(signedJwt);
                })
                .verifyComplete();
    }

    @Test
    void signSystemCredential_success() {
        SigningRequest req = request(SigningType.COSE, "{\"a\":1}");
        RemoteSignatureDto cfg = req.remoteSignature();

        String signedJwt = "signed-jwt";
        String signedB64 = Base64.getEncoder().encodeToString(signedJwt.getBytes(StandardCharsets.UTF_8));
        CertificateInfo certInfo = new CertificateInfo(List.of(), null, null, null, null, null, List.of(SIGN_ALGO_OID), null);

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, req.data()))
                .thenReturn(Mono.just("access-token"));
        when(cscPort.getCredentialInfo(cfg, "access-token", cfg.credentialId()))
                .thenReturn(Mono.just(certInfo));
        when(cscPort.authorizeForDoc(cfg, "access-token"))
                .thenReturn(Mono.just("sad-123"));
        when(cscPort.signDoc(eq(cfg), eq("access-token"), eq("sad-123"), anyString(), eq(SIGN_ALGO_OID)))
                .thenReturn(Mono.just(signedB64));
        when(jwtUtils.decodePayload(signedJwt)).thenReturn("{\"a\":1}");
        when(jwtUtils.areJsonsEqual("{\"a\":1}", req.data())).thenReturn(true);

        StepVerifier.create(signDocService.signSystemCredential(req))
                .assertNext(result -> {
                    assertThat(result.type()).isEqualTo(SigningType.COSE);
                    assertThat(result.data()).isEqualTo(signedJwt);
                })
                .verifyComplete();
    }

    @Test
    void signIssuedCredential_failsWhenPayloadMismatch() {
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        RemoteSignatureDto cfg = req.remoteSignature();

        String signedJwt = "signed-jwt";
        String signedB64 = Base64.getEncoder().encodeToString(signedJwt.getBytes(StandardCharsets.UTF_8));
        CertificateInfo certInfo = new CertificateInfo(List.of(), null, null, null, null, null, List.of(SIGN_ALGO_OID), null);

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, req.data()))
                .thenReturn(Mono.just("access-token"));
        when(cscPort.getCredentialInfo(cfg, "access-token", cfg.credentialId()))
                .thenReturn(Mono.just(certInfo));
        when(cscPort.authorizeForDoc(cfg, "access-token"))
                .thenReturn(Mono.just("sad-123"));
        when(cscPort.signDoc(eq(cfg), eq("access-token"), eq("sad-123"), anyString(), eq(SIGN_ALGO_OID)))
                .thenReturn(Mono.just(signedB64));
        when(jwtUtils.decodePayload(signedJwt)).thenReturn("{\"vc\":999}");
        when(jwtUtils.areJsonsEqual("{\"vc\":999}", req.data())).thenReturn(false);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SignatureProcessingException.class);
                    assertThat(ex.getMessage()).contains("does not match");
                })
                .verify();
    }

    @Test
    void signIssuedCredential_retries_thenSucceeds() {
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        RemoteSignatureDto cfg = req.remoteSignature();

        String signedJwt = "signed-jwt";
        String signedB64 = Base64.getEncoder().encodeToString(signedJwt.getBytes(StandardCharsets.UTF_8));
        CertificateInfo certInfo = new CertificateInfo(List.of(), null, null, null, null, null, List.of(SIGN_ALGO_OID), null);

        WebClientResponseException serverError = WebClientResponseException.create(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                HttpHeaders.EMPTY,
                null,
                null
        );

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, req.data()))
                .thenReturn(Mono.just("access-token"));
        when(cscPort.getCredentialInfo(cfg, "access-token", cfg.credentialId()))
                .thenReturn(Mono.just(certInfo));
        when(cscPort.authorizeForDoc(cfg, "access-token"))
                .thenReturn(Mono.just("sad-123"));
        when(cscPort.signDoc(eq(cfg), eq("access-token"), eq("sad-123"), anyString(), eq(SIGN_ALGO_OID)))
                .thenReturn(Mono.error(serverError))
                .thenReturn(Mono.error(serverError))
                .thenReturn(Mono.just(signedB64));
        when(jwtUtils.decodePayload(signedJwt)).thenReturn("{\"vc\":1}");
        when(jwtUtils.areJsonsEqual("{\"vc\":1}", req.data())).thenReturn(true);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .assertNext(result -> assertThat(result.data()).isEqualTo(signedJwt))
                .verifyComplete();

        verify(cscPort, times(3)).signDoc(any(), anyString(), anyString(), anyString(), anyString());
    }
}
