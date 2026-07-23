package es.in2.issuer.backend.apiclient.domain.model;

public record ApiClient(
        String clientId,
        AuthorizationStatus authorizationStatus,
        boolean canTriggerIssuance,
        String secretHash
) {
    public boolean isActive() {
        return authorizationStatus == AuthorizationStatus.ACTIVE;
    }
}
