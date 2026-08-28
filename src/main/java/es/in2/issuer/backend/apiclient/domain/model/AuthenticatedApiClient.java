package es.in2.issuer.backend.apiclient.domain.model;

public record AuthenticatedApiClient(
        String clientId,
        boolean canTriggerIssuance
) {
}
