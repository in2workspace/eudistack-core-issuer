package es.in2.issuer.backend.shared.domain.model.enums;

import java.util.EnumSet;
import java.util.Set;

public enum CredentialStatusEnum {
    ARCHIVED,
    WITHDRAWN,
    DRAFT,
    ISSUED,
    VALID,
    REVOKED,
    EXPIRED;

    private Set<CredentialStatusEnum> allowedTransitions;

    static {
        ARCHIVED.allowedTransitions = EnumSet.noneOf(CredentialStatusEnum.class);
        WITHDRAWN.allowedTransitions = EnumSet.of(ARCHIVED);
        DRAFT.allowedTransitions = EnumSet.of(WITHDRAWN, ISSUED);
        ISSUED.allowedTransitions = EnumSet.of(VALID);
        VALID.allowedTransitions = EnumSet.of(REVOKED, EXPIRED);
        REVOKED.allowedTransitions = EnumSet.of(ARCHIVED);
        EXPIRED.allowedTransitions = EnumSet.of(ARCHIVED);
    }

    public boolean canTransitionTo(CredentialStatusEnum target) {
        return allowedTransitions.contains(target);
    }
}
