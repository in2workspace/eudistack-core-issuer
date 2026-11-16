package es.in2.issuer.backend.shared.infrastructure.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Idempotency and volume limits of the management APIs (EUD-269). The defaults are the values of the
 * PRDs; the limit of the systems of one organization is raised from the tenant configuration, without
 * a redeploy, not here.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "issuer.api")
public class ApiRequestControlProperties {

    private VolumeLimit volumeLimit = new VolumeLimit();
    private Idempotency idempotency = new Idempotency();

    @Getter
    @Setter
    public static class VolumeLimit {
        private Duration window = Duration.ofMinutes(1);
        /** FR-09 of EUD-254. */
        private Limits issuance = new Limits(300, 30);
        /** FR-07 of EUD-247. */
        private Limits revocation = new Limits(300, 30);
        /** Search by identifier, §5 of EUD-255. */
        private Limits search = new Limits(60, 10);
        /** List and detail, §5 of EUD-255. */
        private Limits read = new Limits(300, 30);
    }

    @Getter
    @Setter
    public static class Limits {
        private int systemsPerOrganization;
        private int perPerson;

        public Limits() {
        }

        public Limits(int systemsPerOrganization, int perPerson) {
            this.systemsPerOrganization = systemsPerOrganization;
            this.perPerson = perPerson;
        }
    }

    @Getter
    @Setter
    public static class Idempotency {
        /** FR-08 of EUD-254. */
        private Duration retention = Duration.ofHours(24);
        /** How long a request in progress holds its key before a retry may take it over. */
        private Duration lease = Duration.ofMinutes(2);
        /**
         * Secret of the idempotency and the volume counters ({@code ISSUER_IDEMPOTENCY_SECRET}), at least 32
         * bytes, the same on every instance. Required: the issuer does not start without it.
         */
        private String secret;
        /** Id of {@link #secret}, 1 to 255, kept with every response sealed with it. */
        private int secretId = 1;
        /** The secret before the last rotation, kept configured for the retention (24 hours); optional. */
        private String previousSecret;
        /** Id of {@link #previousSecret}; different from {@link #secretId}. */
        private int previousSecretId;

        /** The secrets are never printed. */
        @Override
        public String toString() {
            return "Idempotency[retention=" + retention + ", lease=" + lease + ", secretId=" + secretId
                    + ", previousSecretId=" + previousSecretId + "]";
        }
    }
}
