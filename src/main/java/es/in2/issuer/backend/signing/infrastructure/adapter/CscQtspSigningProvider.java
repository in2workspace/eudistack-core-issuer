package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.csc.CscSigningOperation;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;


/**
 * The only provider of the QTSP modality. It reads the CSC operation of the tenant's configuration
 * ({@code signingOperation}) and hands the request to {@link CscSignHashSigningProvider} or
 * {@link CscSignDocSigningProvider}, which keep their own retries and verification.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CscQtspSigningProvider implements SigningProvider {

    private final CscSignHashSigningProvider signHash;
    private final CscSignDocSigningProvider signDoc;

    @Override
    public SigningModality modality() {
        return SigningModality.QTSP;
    }

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            RemoteSignatureDto config = request.remoteSignature();
            if (config == null) {
                return Mono.error(new SigningException(
                        "SigningRequest.remoteSignature is null — tenant QTSP config missing"));
            }
            String operation = config.signingOperation();
            if (operation == null || operation.isBlank()) {
                return Mono.error(new SigningException(
                        """
                                signingOperation is required in the QTSP configuration.
                                Set it to 'sign-hash' or 'sign-doc'.
                                """
                ));
            }

            log.info(
                    "Signing via operation='{}' type='{}' url='{}'",
                    operation,
                    request.type(),
                    config.url()
            );

            return switch (CscSigningOperation.fromValue(operation)) {
                case SIGN_HASH -> signHash.sign(request);
                case SIGN_DOC -> signDoc.sign(request);
            };
        });
    }
}
