package es.in2.issuer.backend.shared.domain.model.requestcontrol;

/**
 * A person (a LEAR employee attestation) or a system (a LEAR machine attestation, or a client of
 * the M2M intake). They have different volume limits (EUD-269).
 */
public enum RequesterKind {
    PERSON,
    SYSTEM
}
