package es.in2.issuer.backend.signing.domain.onboarding;

import java.time.Instant;
import java.util.List;

/**
 * The non-secret state {@code prepare} leaves for {@code import}. It may be stale when {@code import}
 * runs (the key may have been reserved meanwhile, the certificate may have expired), so {@code import}
 * validates again and uses this only to know which KMS key and which chain the onboarding is about.
 *
 * @param operationId         the id of the onboarding, also a tag of the KMS key
 * @param tenant              tenant id, as {@code tenant_registry.schema_name}
 * @param keyArn              ARN of the KMS key created by {@code prepare}
 * @param alias               alias of the key
 * @param certificateChain    base64 DER certificates, leaf first and root excluded
 * @param spkiSha256          SHA-256 of the SPKI of the leaf, lowercase hexadecimal
 * @param createdAt           when {@code prepare} ran
 * @param importTokenExpiresAt when the import token and the wrapping key expire
 */
public record PreparedOnboarding(
        String operationId,
        String tenant,
        String keyArn,
        String alias,
        List<String> certificateChain,
        String spkiSha256,
        Instant createdAt,
        Instant importTokenExpiresAt
) {

    public PreparedOnboarding {
        certificateChain = List.copyOf(certificateChain);
    }
}
