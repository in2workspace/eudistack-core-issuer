package es.in2.issuer.backend.dome.domain.model.sync;

import es.in2.issuer.backend.dome.infrastructure.validation.HexString;

/**
 * Value object representing the cryptographic thumbprint of the holder's key.
 * Used to uniquely and securely identify the wallet requesting the synchronization.
 *
 * @param value The 64-character hexadecimal string representing the hash of the user's
 *              public key.
 */
public record HolderKeyThumbprint (
        @HexString(length = 64)
        String value
) {}

