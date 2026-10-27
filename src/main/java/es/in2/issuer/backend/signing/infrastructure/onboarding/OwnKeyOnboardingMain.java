package es.in2.issuer.backend.signing.infrastructure.onboarding;

/**
 * Entry point of the own-key onboarding tool. It is not the Issuer: no Spring context is started, and it
 * lives in the Issuer jar only to reuse its checks. See {@link OnboardingCli} for the commands and exit codes.
 *
 * <p>Launch it from the Issuer's Spring Boot jar with the {@code PropertiesLauncher}:
 * <pre>
 * java -cp issuer.jar -Dloader.main=es.in2.issuer.backend.signing.infrastructure.onboarding.OwnKeyOnboardingMain \
 *      org.springframework.boot.loader.launch.PropertiesLauncher prepare --tenant cgcom ...
 * </pre>
 */
public final class OwnKeyOnboardingMain {

    /** Logs go to stderr and the result to stdout; this file replaces the default (DEBUG) configuration. */
    private static final String LOGGING_CONFIGURATION = "logback-onboarding.xml";

    private OwnKeyOnboardingMain() {}

    public static void main(String[] args) {
        System.setProperty("logback.configurationFile", LOGGING_CONFIGURATION);
        int exitCode = new OnboardingCli(new OnboardingWiring(), System.out, System.err).run(args, System.getenv());
        System.exit(exitCode);
    }
}
