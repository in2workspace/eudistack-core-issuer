package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.SignDocService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import es.in2.issuer.backend.signing.infrastructure.model.CscSignType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class CscSignDocSigningProvider implements SigningProvider {

    private final SignDocService signDocService;

    @Override
    public CscSignType supportedProvider() {
        return CscSignType.CSC_SIGN_DOC;
    }

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            // Validate first: it guarantees request and context are non-null, so everything
            // below can read them directly.
            SigningRequestValidator.validate(request);

            // issuanceId is the only discriminator between a caller-triggered issuance and a
            // system artifact (status list). The caller token plays no part: AD-1/EUD-225 --
            // signDocService acquires its own QTSP credentials in both cases.
            String issuanceId = request.context().issuanceId();
            boolean isIssued = issuanceId != null && !issuanceId.isBlank();

            log.debug("Signing request received. type={}, issued={}, issuanceId={}", request.type(), isIssued, issuanceId);

            Mono<SigningResult> signingMono = isIssued
                    ? signDocService.signIssuedCredential(request, issuanceId)
                    : signDocService.signSystemCredential(request);

            return signingMono
                    .map(result -> new SigningResult(result.type(), result.data()))
                    .onErrorMap(ex -> new SigningException("Signing failed via CSC signDoc provider: " + ex.getMessage(), ex));
        });
    }
}
