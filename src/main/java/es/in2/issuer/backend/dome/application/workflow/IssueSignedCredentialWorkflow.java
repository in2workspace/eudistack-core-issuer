package es.in2.issuer.backend.dome.application.workflow;

import es.in2.issuer.backend.dome.domain.model.keymigration.ReissuanceContext;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Re-signs an existing credential using the new KMS v2 key (Plan B / DOME key migration).
 * <p>
 * Intentionally bypasses the holder-consent and PDP authorization flows — the original
 * holder binding ({@code holderCnfJwk}) is preserved from {@link ReissuanceContext}.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IssueSignedCredentialWorkflow {

    private final IssuanceService issuanceService;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final KeyMigrationProperties keyMigrationProperties;

    /**
     * Re-issues the credential identified by {@code context.sourceIssuanceId()} signed
     * with the v2 KMS alias ({@code issuer.dome.key-migration.kms-alias-v2}).
     *
     * @param context re-issuance context carrying holder binding and original validity dates.
     * @return the signed credential string (JWT or SD-JWT).
     */
    public Mono<String> reissue(ReissuanceContext context) {
        log.debug("reissue: sourceIssuanceId={}", context.sourceIssuanceId());
        return issuanceService.getIssuanceById(context.sourceIssuanceId().toString())
                .flatMap(issuance -> {
                    Map<String, Object> cnfMap = context.holderCnfJwk().isBlank()
                            ? Map.of()
                            : Map.of("jwk", context.holderCnfJwk());
                    return credentialSignerWorkflow.signCredential(
                            keyMigrationProperties.kmsAliasV2(),
                            issuance.getCredentialDataSet(),
                            issuance.getCredentialType(),
                            issuance.getCredentialFormat(),
                            cnfMap,
                            issuance.getIssuanceId().toString(),
                            issuance.getEmail());
                });
    }
}

