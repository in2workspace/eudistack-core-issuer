package es.in2.issuer.backend.signing.domain.model;

import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;

import java.util.Objects;

/**
 * The active signing configuration of a tenant: its modality plus the data of that modality
 * ({@code qtsp} for {@link SigningModality#QTSP}, {@code ownKey} for {@link SigningModality#OWN_KEY}).
 *
 * <p>{@link RemoteSignatureDto} is an infrastructure type; it is reused here because
 * {@code TenantSigningConfigService} already exposed it.
 */
public record ActiveSigningConfig(
        SigningModality modality,
        RemoteSignatureDto qtsp,
        OwnKeySigningConfig ownKey
) {
    public ActiveSigningConfig {
        Objects.requireNonNull(modality, "modality");
        boolean consistent = switch (modality) {
            case QTSP -> qtsp != null && ownKey == null;
            case OWN_KEY -> ownKey != null && qtsp == null;
        };
        if (!consistent) {
            throw new IllegalArgumentException("signing configuration data does not match modality " + modality);
        }
    }

    public static ActiveSigningConfig qtsp(RemoteSignatureDto remoteSignature) {
        return new ActiveSigningConfig(SigningModality.QTSP, remoteSignature, null);
    }

    public static ActiveSigningConfig ownKey(OwnKeySigningConfig ownKey) {
        return new ActiveSigningConfig(SigningModality.OWN_KEY, null, ownKey);
    }
}
