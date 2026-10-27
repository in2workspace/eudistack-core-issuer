package es.in2.issuer.backend.signing.domain.spi;

import java.time.Instant;
import java.util.Map;

/**
 * Creates, imports into and retires the KMS keys of the own-key onboarding tool. It is the
 * administration side of KMS, run with the operation role: there is no {@code Sign} here (the role
 * cannot sign; the key is checked by comparing its public key with the certificate). Failures surface
 * as {@code OnboardingFailedException}; KMS refusing the imported material is an
 * {@code OnboardingRejectedException}.
 *
 * <p>Keys are referenced by their ARN.
 */
public interface KmsKeyAdministrationPort {

    /** Lifecycle state of a key as far as the tool cares. */
    enum KeyState {
        ENABLED,
        DISABLED,
        PENDING_DELETION,
        /** The key was created and waits for its key material: it has never held a private key. */
        PENDING_IMPORT,
        /** The key does not exist (any more). */
        NOT_FOUND,
        /** Any other state (for example Unavailable): the tool does not act on it. */
        OTHER
    }

    /**
     * What KMS answers to {@code GetParametersForImport}.
     *
     * @param wrappingPublicKeyDer DER SubjectPublicKeyInfo of the RSA-4096 key the key material must be wrapped with
     * @param importToken          opaque token that goes with the wrapped key material
     * @param validTo              when the token and the wrapping key stop being valid
     */
    record ImportParameters(byte[] wrappingPublicKeyDer, byte[] importToken, Instant validTo) {}

    /**
     * Creates an external-origin ECC_NIST_P256 SIGN_VERIFY key tagged {@code Tenant=<tenant>} (the tag the Issuer
     * checks before signing) and {@code operationId=<operationId>}. The key policy is the KMS default; Infra
     * will define a fixed policy and it will be injected into the adapter, not decided here.
     *
     * @return the key ARN
     */
    String createKey(String tenant, String operationId);

    /** @param alias the full alias name, starting with {@code alias/} */
    void createAlias(String alias, String keyArn);

    /** Wrapping algorithm RSA_AES_KEY_WRAP_SHA_256 with an RSA_4096 wrapping key. */
    ImportParameters getParametersForImport(String keyArn);

    /** Imports the wrapped key material with {@code KEY_MATERIAL_DOES_NOT_EXPIRE}. */
    void importKeyMaterial(String keyArn, byte[] importToken, byte[] encryptedKeyMaterial);

    /** @return the DER SubjectPublicKeyInfo of the key */
    byte[] getPublicKey(String keyArn);

    KeyState describeKeyState(String keyArn);

    /** All the tags of the key, through every page. */
    Map<String, String> listTags(String keyArn);

    /** @param alias the full alias name, starting with {@code alias/} */
    void deleteAlias(String alias);

    void disableKey(String keyArn);

    void scheduleKeyDeletion(String keyArn, int pendingWindowDays);
}
