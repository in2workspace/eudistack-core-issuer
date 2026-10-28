package es.in2.issuer.backend.signing.infrastructure.onboarding;

/** A {@link SigningConfigurationAuditSink} and whatever it has to release when the run ends. */
public interface AuditSinkHandle extends AutoCloseable {

    SigningConfigurationAuditSink sink();

    @Override
    void close();

    /** A sink that holds nothing to release. */
    static AuditSinkHandle of(SigningConfigurationAuditSink sink) {
        return new AuditSinkHandle() {
            @Override
            public SigningConfigurationAuditSink sink() {
                return sink;
            }

            @Override
            public void close() {
                // Nothing to release.
            }
        };
    }
}
