package es.in2.issuer.backend.shared.domain.model.enums;

import java.util.EnumSet;
import java.util.Set;

public enum CredentialStatusEnum {
    WITHDRAWN,
    DRAFT,
    ISSUED,
    VALID,
    REVOKED,
    EXPIRED;

    private Set<CredentialStatusEnum> allowedTransitions;

    static {
        WITHDRAWN.allowedTransitions = EnumSet.noneOf(CredentialStatusEnum.class);
        DRAFT.allowedTransitions = EnumSet.of(WITHDRAWN, ISSUED);
        ISSUED.allowedTransitions = EnumSet.of(VALID);
        VALID.allowedTransitions = EnumSet.of(REVOKED, EXPIRED);
        REVOKED.allowedTransitions = EnumSet.noneOf(CredentialStatusEnum.class);
        EXPIRED.allowedTransitions = EnumSet.noneOf(CredentialStatusEnum.class);
    }

    public boolean canTransitionTo(CredentialStatusEnum target) {
        return allowedTransitions.contains(target);
    }
}
