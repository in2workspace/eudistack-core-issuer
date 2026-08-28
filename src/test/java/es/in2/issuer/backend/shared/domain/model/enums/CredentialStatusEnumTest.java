package es.in2.issuer.backend.shared.domain.model.enums;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialStatusEnumTest {

    @Test
    void testTransitionFromArchivedToArchivedIsRejected() {
        assertFalse(CredentialStatusEnum.ARCHIVED.canTransitionTo(CredentialStatusEnum.ARCHIVED),
                "Transition from ARCHIVED to ARCHIVED should be rejected");
    }

    @Test
    void testTransitionsFromTerminalStatesToArchivedAreAllowed() {
        assertTrue(CredentialStatusEnum.WITHDRAWN.canTransitionTo(CredentialStatusEnum.ARCHIVED),
                "Transition from WITHDRAWN to ARCHIVED should be allowed");
        assertTrue(CredentialStatusEnum.REVOKED.canTransitionTo(CredentialStatusEnum.ARCHIVED),
                "Transition from REVOKED to ARCHIVED should be allowed");
        assertTrue(CredentialStatusEnum.EXPIRED.canTransitionTo(CredentialStatusEnum.ARCHIVED),
                "Transition from EXPIRED to ARCHIVED should be allowed");
    }

    @Test
    void testArchivedHasNoOutgoingTransitions() {
        for (CredentialStatusEnum status : CredentialStatusEnum.values()) {
            assertFalse(CredentialStatusEnum.ARCHIVED.canTransitionTo(status),
                    "ARCHIVED should not have any outgoing transitions to " + status);
        }
    }
}
