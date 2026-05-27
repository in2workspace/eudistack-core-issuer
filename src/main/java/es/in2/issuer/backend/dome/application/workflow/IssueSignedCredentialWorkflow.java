package es.in2.issuer.backend.dome.application.workflow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.dome.domain.model.keymigration.ReissuanceContext;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssueSignedCredentialWorkflow {

    private final IssuanceService issuanceService;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final KeyMigrationProperties keyMigrationProperties;
    private final ObjectMapper objectMapper;

    public Mono<String> reissue(ReissuanceContext context) {
        log.debug("reissue: sourceIssuanceId={}", context.sourceIssuanceId());
        return issuanceService.getIssuanceById(context.sourceIssuanceId().toString())
                .flatMap(issuance -> {
                    Map<String, Object> cnfMap;
                    if (context.holderCnfJwk().isBlank()) {
                        cnfMap = Map.of();
                    } else {
                        try {
                            Map<String, Object> jwkMap = objectMapper.readValue(
                                    context.holderCnfJwk(), new TypeReference<>() {});
                            cnfMap = Map.of("jwk", jwkMap);
                        } catch (JsonProcessingException e) {
                            throw new IllegalArgumentException(
                                    "holderCnfJwk is not valid JSON: " + e.getMessage(), e);
                        }
                    }
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
