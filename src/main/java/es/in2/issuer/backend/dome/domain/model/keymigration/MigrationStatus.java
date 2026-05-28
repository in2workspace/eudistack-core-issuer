package es.in2.issuer.backend.dome.domain.model.keymigration;

import java.util.EnumSet;
import java.util.Set;

public enum MigrationStatus {

    PENDING {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return ALLOWED_FROM_PENDING.contains(target);
        }
    },
    POC_OK {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return ALLOWED_FROM_POC_OK.contains(target);
        }
    },
    FAILED {
        @Override
        public boolean canTransitionTo(MigrationStatus target) {
            return ALLOWED_FROM_FAILED.contains(target);
        }
    },
    MIGRATED {
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
    };

    private static final Set<MigrationStatus> ALLOWED_FROM_PENDING =
            EnumSet.of(POC_OK, FAILED);

    private static final Set<MigrationStatus> ALLOWED_FROM_POC_OK =
            EnumSet.of(MIGRATED, ROLLED_BACK, FAILED);

    private static final Set<MigrationStatus> ALLOWED_FROM_FAILED =
            EnumSet.of(PENDING);

    public abstract boolean canTransitionTo(MigrationStatus target);
}

