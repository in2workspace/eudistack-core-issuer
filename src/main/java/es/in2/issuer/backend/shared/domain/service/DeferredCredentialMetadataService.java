package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.DeferredCredentialMetadataDeferredResponse;
import es.in2.issuer.backend.shared.domain.model.entities.DeferredCredentialMetadata;
import reactor.core.publisher.Mono;

import java.util.Map;

public interface DeferredCredentialMetadataService {
    Mono<String> createDeferredCredentialMetadata(String procedureId);
    Mono<Map<String, Object>> updateCacheStoreForCTransactionCode(String transactionCode);
    Mono<String> validateCTransactionCode(String cTransactionCode);
    Mono<String> updateTransactionCodeInDeferredCredentialMetadata(String procedureId);
    Mono<String> getProcedureIdByTransactionCode(String transactionCode);
    Mono<DeferredCredentialMetadata> getDeferredCredentialMetadataByAuthServerNonce(String authServerNonce);
    Mono<Void> updateAuthServerNonceByTransactionCode(String transactionCode, String authServerNonce);
    Mono<String> updateDeferredCredentialMetadataByAuthServerNonce(String authServerNonce);
    Mono<Void> updateDeferredCredentialByAuthServerNonce(String authServerNonce, String format);
    Mono<Void> validateTransactionCode(String transactionCode);
    Mono<Void> validateTransactionCodeNonDestructive(String transactionCode);
    Mono<Void> updateAuthServerNonceByAuthServerNonce(String accessToken, String preAuthCode);
    Mono<Void> updateVcByProcedureId(String vc, String procedureId);
    Mono<DeferredCredentialMetadataDeferredResponse> getVcByTransactionId(String transactionId);
    Mono<Void> deleteDeferredCredentialMetadataById(String id);
    Mono<Void> deleteDeferredCredentialMetadataByAuthServerNonce(String authServerNonce);
    Mono<Void> updateFormatByProcedureId(String procedureId, String format);
    Mono<String> getFormatByProcedureId(String procedureId);
    Mono<Void> updateCnfByProcedureId(String procedureId, String cnfJson);
    Mono<String> getCnfByProcedureId(String procedureId);
}
