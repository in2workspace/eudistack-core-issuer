package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
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
            // Computed defensively (null-safe) so that a null request/context still fails
            // through SigningRequestValidator.validate() as a SigningException, not an NPE:
            // isIssued must be known before validate() (it decides requireContextToken), but
            // validate() is also what asserts request/context are non-null in the first place.
            SigningContext ctx = request != null ? request.context() : null;
            String issuanceId = ctx != null ? ctx.issuanceId() : null;
            boolean isIssued = issuanceId != null && !issuanceId.isBlank();

            // Context token is only required when signing an issued credential (a caller
            // context exists). System artifacts (e.g. status lists, AD-1/EUD-225) are signed
            // without a caller token: signDocService acquires its own QTSP credentials.
            SigningRequestValidator.validate(request, isIssued);

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
