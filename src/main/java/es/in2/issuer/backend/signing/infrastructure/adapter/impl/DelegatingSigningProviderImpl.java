package es.in2.issuer.backend.signing.infrastructure.adapter.impl;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningProviderResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Routes signing requests to the CSC operation configured for the active
 * tenant's QTSP. Reads signing config per-tenant from the database (via
 * {@link TenantSigningConfigService}) and injects it into the {@link
 * SigningRequest} before delegating.
 *
 * <p>There is no global fallback: if {@code tenant_signing_config} has no
 * row for the active tenant, a {@link SigningException} is thrown. Seed
 * the row via {@code seed-tenants[.stg].sql} or via the per-tenant config
 * management service (future EUDI-090).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DelegatingSigningProviderImpl implements DelegatingSigningProvider {

    private final TenantSigningConfigService tenantSigningConfigService;
    private final SigningProviderResolver signingProviderResolver;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {

        return Mono.justOrEmpty(request.remoteSignature())
                .switchIfEmpty(loadTenantRemoteSignature())
                .flatMap(remoteSignatureDto ->
                        sign(request, remoteSignatureDto));
    }

    private Mono<RemoteSignatureDto> loadTenantRemoteSignature() {

        return tenantSigningConfigService.getRemoteSignature()
                .switchIfEmpty(Mono.error(
                        new SigningException(
                                """
                                        No remote signature configuration available for this tenant.
                                        Seed tenant_signing_config for the active tenant.
                                        """
                        )
                ));
    }

    private Mono<SigningResult> sign(
            SigningRequest signingRequest,
            RemoteSignatureDto remoteSignatureDto
    ) {

        validateSigningOperation(remoteSignatureDto.signingOperation());

        SigningProvider signingProvider =
                signingProviderResolver.resolveFromValue(
                        remoteSignatureDto.signingOperation()
                );

        log.info(
                "Signing via operation='{}' type='{}' url='{}'",
                remoteSignatureDto.signingOperation(),
                signingRequest.type(),
                remoteSignatureDto.url()
        );

        return signingProvider.sign(
                enrich(signingRequest, remoteSignatureDto)
        );
    }

    private void validateSigningOperation(String operation) {

        if (operation == null || operation.isBlank()) {

            throw new SigningException(
                    """
                            signingOperation is required in the QTSP configuration.
                            Set it to 'sign-hash' or 'sign-doc'.
                            """
            );
        }
    }

    private static SigningRequest enrich(
            SigningRequest original,
            RemoteSignatureDto cfg
    ) {

        if (original.remoteSignature() != null) {
            return original;
        }

        return SigningRequest.builder()
                .type(original.type())
                .data(original.data())
                .context(original.context())
                .typ(original.typ())
                .remoteSignature(cfg)
                .build();
    }
}