package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListCredentialSerializationException;
import es.in2.issuer.backend.statuslist.domain.spi.CredentialPayloadSigner;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@RequiredArgsConstructor
@Component
public class StatusListSigner implements CredentialPayloadSigner {

    private final SigningProvider signingProvider;
    private final ObjectMapper objectMapper;

    public Mono<String> sign(Map<String, Object> payload, String token, Long listId, String typ) {
        requireNonNullParam(payload, "payload");
        requireNonNullParam(token, "token");

        return toSignatureRequest(payload, token, typ)
                .flatMap(signingProvider::sign)
                .onErrorMap(ex -> new RemoteSignatureException("StatusList signing failed; list ID: " + listId, ex))
                .map(signingResult -> extractJwt(signingResult, listId));
    }

    private Mono<SigningRequest> toSignatureRequest(Map<String, Object> payload, String token, String typ) {
        return Mono.fromCallable(() -> {
            String json = objectMapper.writeValueAsString(payload);

            SigningContext context = SigningContext.builder()
                    .token(token)
                    .issuanceId(null)
                    .email(null)
                    .build();

            return SigningRequest.builder()
                    .type(SigningType.JADES)
                    .data(json)
                    .context(context)
                    .typ(typ)
                    .build();
        }).onErrorMap(JsonProcessingException.class, StatusListCredentialSerializationException::new);
    }

    private String extractJwt(SigningResult signingResult, Long listId) {
        if (signingResult == null || signingResult.data() == null || signingResult.data().isBlank()) {
            throw new RemoteSignatureException("Signer returned empty signingResult; list ID: " + listId);
        }
        return signingResult.data();
    }

}
