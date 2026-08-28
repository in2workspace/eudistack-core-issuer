package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import es.in2.issuer.backend.signing.infrastructure.model.CscSignType;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@Slf4j
@Service
@RequiredArgsConstructor
public class CscSignHashSigningProvider implements SigningProvider {

    private final CscPort cscPort;
    private final IssuerCertificateService issuerCertificateService;
    private final JwsSignHashService jwsSignHashService;
    private final JadesHeaderBuilderService jadesHeaderBuilder;
    private final CscSigningProperties cscSigningProperties;

    @Override
    public CscSignType supportedProvider() {
        return CscSignType.CSC_SIGN_HASH;
    }

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            SigningRequestValidator.validate(request, false);

            if (request.type() != SigningType.JADES) {
                return Mono.error(new SigningException("csc-sign-hash supports only JADES/JWT"));
            }

            JadesProfile profile = cscSigningProperties.signatureProfile();
            RemoteSignatureDto cfg = request.remoteSignature();

            if (cfg == null) {
                return Mono.error(new SigningException("SigningRequest.remoteSignature is null — tenant QTSP config missing"));
            }

            return cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false)
                    .flatMap(accessToken ->
                            issuerCertificateService.requestCertificateInfo(cfg, accessToken, cfg.credentialId())
                                    .flatMap(certInfo -> {
                                        String headerJson = jadesHeaderBuilder.buildHeader(certInfo, profile, request.typ());
                                        String signAlgoOid = certInfo.keyAlgorithms().getFirst();
                                        return jwsSignHashService.signJwtWithSignHash(cfg, accessToken, headerJson, request.data(), signAlgoOid);
                                    })
                    )
                    .map(jwt -> new SigningResult(SigningType.JADES, jwt))
                    .onErrorMap(ex -> (ex instanceof SigningException) ? ex
                            : new SigningException("Signing failed via CSC signHash provider: " + ex.getMessage(), ex));
        });
    }
}
