package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
public class CscSignDocSigningProvider implements SigningProvider {

    private final RemoteSignatureService remoteSignatureService;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            SigningRequestValidator.validate(request);

            SigningContext ctx = request.context();

            String token = ctx.token();
            String procedureId = ctx.procedureId();
            String email = ctx.email();

            boolean isIssued = procedureId != null && !procedureId.isBlank();

            log.debug("Signing request received. type={}, issued={}, procedureId={}",
                    request.type(), isIssued, procedureId);

            Mono<SigningResult> signingMono =
                    isIssued
                            ? remoteSignatureService.signIssuedCredential(request, token, procedureId, email)
                            : remoteSignatureService.signSystemCredential(request, token);

            Mono<SigningResult> resultMono = signingMono
                    .map(signingResult -> new SigningResult(signingResult.type(), signingResult.data()));

            resultMono = resultMono.onErrorMap(ex ->
                    new SigningException("Signing failed via CSC signDoc provider: " + ex.getMessage(), ex)
            );
            return resultMono;
        });
    }


}
