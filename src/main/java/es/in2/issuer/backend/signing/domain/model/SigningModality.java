package es.in2.issuer.backend.signing.domain.model;

/** How a tenant signs: through a remote QTSP, or with its own key held in a KMS. */
public enum SigningModality {
    QTSP,
    OWN_KEY
}
