package es.in2.issuer.backend.shared.application.workflow;

import reactor.core.publisher.Mono;

import java.util.Map;

public interface CredentialSignerWorkflow {
    Mono<String> signCredential(String token, String enrichedDataSet, String credentialType,
                                String format, Map<String, Object> cnf, String procedureId, String email);
}
