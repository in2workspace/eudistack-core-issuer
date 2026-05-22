package es.in2.issuer.backend.dome.domain.model.keymigration;

import java.util.EnumSet;
import java.util.Set;

public enum MigrationStatus {

    PENDING {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return VALID_FROM_PENDING.contains(target);
        }
    },
    POC_OK {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return VALID_FROM_POC_OK.contains(target);
        }
    },
    POC_FAILED {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return VALID_FROM_POC_FAILED.contains(target);
        }
    },
    PLAN_A_OK {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return VALID_FROM_PLAN_A_OK.contains(target);
        }
    },
    PLAN_B_REISSUE {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return VALID_FROM_PLAN_B_REISSUE.contains(target);
        }
    },
    PLAN_B_PARTIAL {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return false;
        }
    },
    ROLLED_BACK {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return false;
        }
    },
    FAILED {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return VALID_FROM_FAILED.contains(target);
        }
    };

    private static final Set<MigrationStatus> VALID_FROM_PENDING =
            EnumSet.of(POC_OK, POC_FAILED, FAILED, PLAN_A_OK);
    private static final Set<MigrationStatus> VALID_FROM_POC_OK =
            EnumSet.of(PLAN_A_OK, PLAN_B_REISSUE, FAILED);
    private static final Set<MigrationStatus> VALID_FROM_POC_FAILED =
            EnumSet.of(PLAN_B_REISSUE, FAILED);
    private static final Set<MigrationStatus> VALID_FROM_PLAN_A_OK =
            EnumSet.of(ROLLED_BACK);
    private static final Set<MigrationStatus> VALID_FROM_PLAN_B_REISSUE =
            EnumSet.of(PLAN_B_PARTIAL, FAILED);
    private static final Set<MigrationStatus> VALID_FROM_FAILED =
            EnumSet.of(PENDING);

    public abstract boolean canTransitionTo(MigrationStatus target);
}

