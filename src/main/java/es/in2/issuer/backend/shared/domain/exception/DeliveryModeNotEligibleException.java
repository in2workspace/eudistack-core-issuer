package es.in2.issuer.backend.shared.domain.exception;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;

import java.util.Set;

public class DeliveryModeNotEligibleException extends RuntimeException {

    public DeliveryModeNotEligibleException(String credentialConfigurationId, Set<DeliveryMode> requestedModes) {
        super("Requested delivery mode(s) " + DeliveryMode.toCanonicalCsv(requestedModes)
                + " are not eligible for credential_configuration_id: " + credentialConfigurationId);
    }

}
