package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingPolicy;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyCertificateValidator;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.PrepareCommand;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler.ReconcileReport;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Command line of the own-key onboarding tool: {@code prepare}, {@code import} and {@code reconcile}. It is
 * independent of how it is launched (laptop, a one-off ECS task, a scheduled job): commands and parameters
 * come from arguments or environment variables, the result is the exit code.
 *
 * <p>Exit codes: {@value #EXIT_OK} ok; {@value #EXIT_ERROR} any other error; {@value #EXIT_REJECTED} the
 * onboarding was rejected by a validation (the reason is on stderr; nothing was put into service);
 * {@value #EXIT_USAGE} usage error.
 *
 * <p>There is no withdrawal command: a configuration is withdrawn by its replacement ({@code import}), and
 * {@code reconcile} retires the KMS key of a replaced configuration once the grace period has passed.
 */
public final class OnboardingCli {

    public static final int EXIT_OK = 0;
    public static final int EXIT_ERROR = 1;
    public static final int EXIT_REJECTED = 2;
    public static final int EXIT_USAGE = 64;

    private static final long DEFAULT_GRACE_SECONDS = 160;
    private static final int DEFAULT_DELETION_WINDOW_DAYS = 7;

    /** Opens the collaborators of one run. */
    @FunctionalInterface
    public interface Wiring {
        Services open(OnboardingSettings settings);
    }

    /** The use cases of one run, and the clients behind them, which {@link #close()} releases. */
    public interface Services extends AutoCloseable {
        OwnKeyOnboarding onboarding();

        OwnKeyReconciler reconciler();

        @Override
        void close();
    }

    private enum Command {
        PREPARE("prepare"),
        IMPORT("import"),
        RECONCILE("reconcile");

        private final String word;

        Command(String word) {
            this.word = word;
        }
    }

    private enum Opt {
        DB_URL("db-url", "SPRING_FLYWAY_URL", false),
        DB_USER("db-user", "SPRING_R2DBC_USERNAME", false),
        KMS_REGION("kms-region", "ISSUER_SIGNING_KMS_REGION", false),
        KMS_ENDPOINT("kms-endpoint", "ISSUER_SIGNING_KMS_ENDPOINT", false),
        DELETION_WINDOW_DAYS("deletion-window-days", "OWN_KEY_DELETION_WINDOW_DAYS", false),
        DRY_RUN("dry-run", "OWN_KEY_DRY_RUN", true),
        TENANT("tenant", "OWN_KEY_TENANT", false),
        CERT_CHAIN("cert-chain", "OWN_KEY_CERT_CHAIN", false),
        OUT_DIR("out-dir", "OWN_KEY_OUT_DIR", false),
        ALIAS("alias", "OWN_KEY_ALIAS", false),
        PRODUCTION("production", "OWN_KEY_PRODUCTION", true),
        TRUST_ANCHOR("trust-anchor", "OWN_KEY_TRUST_ANCHOR", false),
        EXPECTED_ORG_ID("expected-org-id", "OWN_KEY_EXPECTED_ORG_ID", false),
        STATE("state", "OWN_KEY_STATE", false),
        KEY_MATERIAL("key-material", "OWN_KEY_KEY_MATERIAL", false),
        IMPORT_TOKEN("import-token", "OWN_KEY_IMPORT_TOKEN", false),
        GRACE_SECONDS("grace-seconds", "OWN_KEY_GRACE_SECONDS", false);

        private final String flag;
        private final String env;
        private final boolean isSwitch;

        Opt(String flag, String env, boolean isSwitch) {
            this.flag = flag;
            this.env = env;
            this.isSwitch = isSwitch;
        }
    }

    private static final String ENV_DB_PASSWORD = "SPRING_R2DBC_PASSWORD";
    private static final String ENV_AWS_REGION = "AWS_REGION";

    private static final Set<Opt> COMMON = EnumSet.of(Opt.DB_URL, Opt.DB_USER, Opt.KMS_REGION, Opt.KMS_ENDPOINT,
            Opt.DELETION_WINDOW_DAYS, Opt.DRY_RUN);

    private static final String HELP = """
            Own-key onboarding tool (EUD-289): puts a tenant's own signing key, held in AWS KMS, into service.

            Usage: <launcher> <command> [options]

            Commands
              prepare    Validate the certificate chain, create the KMS key (tagged Tenant=<tenant>) and leave
                         the wrapping public key, the import token and a state file in --out-dir. The customer
                         wraps its private key with the public key.
              import     Validate again, import the wrapped key material, check that the key is the certificate's
                         and, in one transaction, replace the tenant's active configuration with the new one.
              reconcile  Disable and schedule the deletion of the KMS key of every replaced configuration
                         withdrawn for longer than the grace period. Safe to repeat.

            Every command accepts --dry-run: validations only, nothing is written to KMS, files or the database.
            An option can also be given as an environment variable (name in brackets).

            Common options
              --db-url <jdbc url>            [SPRING_FLYWAY_URL]
              --db-user <user>               [SPRING_R2DBC_USERNAME]
              (database password)            [SPRING_R2DBC_PASSWORD], environment only
              --kms-region <region>          [ISSUER_SIGNING_KMS_REGION, then AWS_REGION]
              --kms-endpoint <url>           [ISSUER_SIGNING_KMS_ENDPOINT] emulators only; applies to KMS and STS
              --deletion-window-days <7-30>  [OWN_KEY_DELETION_WINDOW_DAYS] default 7
              --dry-run                      [OWN_KEY_DRY_RUN]

            prepare
              --tenant <id>                  [OWN_KEY_TENANT] tenant id, e.g. cgcom
              --cert-chain <pem file>        [OWN_KEY_CERT_CHAIN] leaf first, root excluded
              --out-dir <dir>                [OWN_KEY_OUT_DIR]
              --alias <alias/name>           [OWN_KEY_ALIAS] default alias/own-key-<tenant>-<operation id>
            import
              --state <file>                 [OWN_KEY_STATE] the state file written by prepare
              --key-material <file>          [OWN_KEY_KEY_MATERIAL] the private key wrapped by the customer
              --import-token <file>          [OWN_KEY_IMPORT_TOKEN] default: the one next to the state file
            prepare and import
              --production                   [OWN_KEY_PRODUCTION] adds the production checks; requires the next two
              --trust-anchor <pem file>      [OWN_KEY_TRUST_ANCHOR] the CA agreed with the tenant (root or intermediate)
              --expected-org-id <id>         [OWN_KEY_EXPECTED_ORG_ID] organizationIdentifier of the tenant
            reconcile
              --grace-seconds <n>            [OWN_KEY_GRACE_SECONDS] default 160

            Exit codes: 0 ok; 1 any other error; 2 onboarding rejected by a validation (reason on stderr);
            64 usage error.
            """;

    private final Wiring wiring;
    private final PrintStream out;
    private final PrintStream err;

    public OnboardingCli(Wiring wiring, PrintStream out, PrintStream err) {
        this.wiring = wiring;
        this.out = out;
        this.err = err;
    }

    /** A bad command line: the message says what to correct. */
    private static final class UsageException extends RuntimeException {
        private UsageException(String message) {
            super(message);
        }
    }

    /** The command line, resolved against the environment. */
    private record Invocation(Command command, Map<Opt, String> values, Map<String, String> env) {

        private String get(Opt option) {
            return values.get(option);
        }

        private boolean has(Opt option) {
            return values.containsKey(option);
        }

        private String require(Opt option) {
            String value = values.get(option);
            if (value == null || value.isBlank()) {
                throw new UsageException("--" + option.flag + " (or " + option.env + ") is required");
            }
            return value;
        }

        private boolean dryRun() {
            return has(Opt.DRY_RUN);
        }
    }

    /** @return the exit code */
    public int run(String[] args, Map<String, String> env) {
        try {
            if (args.length == 0) {
                throw new UsageException("a command is required: prepare, import or reconcile");
            }
            if (List.of("--help", "-h", "help").contains(args[0])) {
                out.print(HELP);
                return EXIT_OK;
            }
            Invocation invocation = parse(args, env);
            if (invocation == null) {
                out.print(HELP);
                return EXIT_OK;
            }
            return execute(invocation);
        } catch (UsageException | IllegalArgumentException e) {
            err.println("USAGE: " + e.getMessage() + " (run with --help)");
            return EXIT_USAGE;
        } catch (OnboardingRejectedException e) {
            err.println("REJECTED: " + e.getMessage());
            return EXIT_REJECTED;
        } catch (OnboardingFailedException e) {
            err.println("ERROR: " + e.getMessage());
            return EXIT_ERROR;
        } catch (RuntimeException e) {
            err.println("ERROR: unexpected " + e.getClass().getSimpleName() + ": " + e.getMessage());
            return EXIT_ERROR;
        }
    }

    private int execute(Invocation invocation) {
        OnboardingSettings settings = settings(invocation);
        try (Services services = wiring.open(settings)) {
            return switch (invocation.command()) {
                case PREPARE -> prepare(invocation, services.onboarding());
                case IMPORT -> importKey(invocation, services.onboarding());
                case RECONCILE -> reconcile(invocation, services.reconciler());
            };
        }
    }

    private int prepare(Invocation invocation, OwnKeyOnboarding onboarding) {
        String tenant = invocation.require(Opt.TENANT);
        String chainPem = readString(Path.of(invocation.require(Opt.CERT_CHAIN)));
        Path outDir = invocation.dryRun() ? null : Path.of(invocation.require(Opt.OUT_DIR));
        OnboardingPolicy policy = policy(invocation);
        var result = onboarding.prepare(new PrepareCommand(tenant, chainPem, policy, invocation.get(Opt.ALIAS),
                invocation.dryRun(), outDir == null ? null : new PreparedOnboardingFiles(outDir)));
        if (result.prepared() == null) {
            out.println("dry run: the certificate chain and the tenant pass the validations (operation "
                    + result.operation().catalogName() + "); nothing was created");
            return EXIT_OK;
        }
        var prepared = result.prepared();
        String prefix = "own-key-" + prepared.tenant() + "-" + prepared.operationId();
        out.println("prepared onboarding " + prepared.operationId() + " for tenant " + prepared.tenant()
                + " (operation " + result.operation().catalogName() + ")");
        out.println("key        : " + prepared.keyArn());
        out.println("alias      : " + prepared.alias());
        out.println("SPKI sha256: " + prepared.spkiSha256());
        out.println("valid until: " + prepared.importTokenExpiresAt() + " (import token and wrapping key)");
        out.println("files      : " + outDir.resolve(prefix + ".{wrapping-public-key.der,wrapping-public-key.pem,"
                + "import-token.bin,state.json}"));
        out.println("next       : the customer wraps its private key with the wrapping public key; then run import "
                + "with --state " + outDir.resolve(prefix + ".state.json") + " and --key-material <wrapped key>");
        return EXIT_OK;
    }

    private int importKey(Invocation invocation, OwnKeyOnboarding onboarding) {
        Path stateFile = Path.of(invocation.require(Opt.STATE));
        byte[] keyMaterial = invocation.dryRun() && !invocation.has(Opt.KEY_MATERIAL)
                ? new byte[0] : readBytes(Path.of(invocation.require(Opt.KEY_MATERIAL)));
        Path tokenFile = invocation.has(Opt.IMPORT_TOKEN) ? Path.of(invocation.get(Opt.IMPORT_TOKEN)) : null;
        var loaded = PreparedOnboardingFiles.read(stateFile, tokenFile);
        var result = onboarding.importKey(new ImportCommand(loaded.prepared(), loaded.importToken(), keyMaterial,
                policy(invocation), invocation.dryRun()));
        if (result.configurationId() == null) {
            out.println("dry run: the onboarding of tenant " + loaded.prepared().tenant()
                    + " passes the validations (operation " + result.operation().catalogName() + "); nothing was imported");
            return EXIT_OK;
        }
        out.println("tenant " + loaded.prepared().tenant() + " now signs with its own key (operation "
                + result.operation().catalogName() + ")");
        out.println("key           : " + result.keyArn());
        out.println("configuration : " + result.configurationId());
        out.println("SPKI sha256   : " + result.spkiSha256());
        return EXIT_OK;
    }

    private int reconcile(Invocation invocation, OwnKeyReconciler reconciler) {
        long seconds = invocation.has(Opt.GRACE_SECONDS) ? parseLong(Opt.GRACE_SECONDS, invocation.get(Opt.GRACE_SECONDS))
                : DEFAULT_GRACE_SECONDS;
        if (seconds < 0) {
            throw new UsageException("--grace-seconds must not be negative");
        }
        ReconcileReport report = reconciler.reconcile(Duration.ofSeconds(seconds), invocation.dryRun());
        out.println((invocation.dryRun() ? "dry run: keys that would be retired: " : "keys retired: ") + report.retired());
        if (!report.succeeded()) {
            report.failures().forEach(failure -> err.println("ERROR: " + failure));
            return EXIT_ERROR;
        }
        return EXIT_OK;
    }

    private OnboardingPolicy policy(Invocation invocation) {
        X509Certificate anchor = null;
        if (invocation.has(Opt.TRUST_ANCHOR)) {
            List<X509Certificate> anchors = OwnKeyCertificateValidator.parsePemChain(
                    readString(Path.of(invocation.get(Opt.TRUST_ANCHOR))));
            anchor = anchors.getFirst();
        }
        return new OnboardingPolicy(invocation.has(Opt.PRODUCTION), anchor, invocation.get(Opt.EXPECTED_ORG_ID));
    }

    private OnboardingSettings settings(Invocation invocation) {
        String password = invocation.env().get(ENV_DB_PASSWORD);
        if (password == null) {
            throw new UsageException(ENV_DB_PASSWORD + " is required (the database password is never an argument)");
        }
        String region = invocation.get(Opt.KMS_REGION);
        if (region == null || region.isBlank()) {
            region = invocation.env().get(ENV_AWS_REGION);
        }
        URI endpoint = invocation.has(Opt.KMS_ENDPOINT) ? URI.create(invocation.get(Opt.KMS_ENDPOINT)) : null;
        int days = invocation.has(Opt.DELETION_WINDOW_DAYS)
                ? (int) parseLong(Opt.DELETION_WINDOW_DAYS, invocation.get(Opt.DELETION_WINDOW_DAYS))
                : DEFAULT_DELETION_WINDOW_DAYS;
        return new OnboardingSettings(invocation.require(Opt.DB_URL), invocation.require(Opt.DB_USER), password,
                region == null || region.isBlank() ? null : region, endpoint, days);
    }

    /** @return the invocation, or {@code null} if help was asked for */
    private static Invocation parse(String[] args, Map<String, String> env) {
        Command command = null;
        for (Command candidate : Command.values()) {
            if (candidate.word.equals(args[0])) {
                command = candidate;
            }
        }
        if (command == null) {
            throw new UsageException("unknown command '" + args[0] + "': prepare, import or reconcile");
        }
        Set<Opt> allowed = allowedOptions(command);
        Map<Opt, String> values = new EnumMap<>(Opt.class);
        for (int i = 1; i < args.length; i++) {
            String token = args[i];
            if ("--help".equals(token) || "-h".equals(token)) {
                return null;
            }
            if (!token.startsWith("--")) {
                throw new UsageException("unexpected argument '" + token + "'");
            }
            int equals = token.indexOf('=');
            String name = equals < 0 ? token.substring(2) : token.substring(2, equals);
            Opt option = allowed.stream().filter(o -> o.flag.equals(name)).findFirst()
                    .orElseThrow(() -> new UsageException("unknown option --" + name + " for " + args[0]));
            if (values.containsKey(option)) {
                throw new UsageException("--" + name + " is given twice");
            }
            if (option.isSwitch) {
                if (equals < 0 || isTrue(token.substring(equals + 1))) {
                    values.put(option, "true");
                }
            } else if (equals >= 0) {
                values.put(option, token.substring(equals + 1));
            } else if (i + 1 < args.length) {
                values.put(option, args[++i]);
            } else {
                throw new UsageException("--" + name + " needs a value");
            }
        }
        for (Opt option : allowed) {
            if (!values.containsKey(option) && env.get(option.env) != null && !env.get(option.env).isBlank()) {
                if (!option.isSwitch) {
                    values.put(option, env.get(option.env));
                } else if (isTrue(env.get(option.env))) {
                    values.put(option, "true");
                }
            }
        }
        return new Invocation(command, values, env);
    }

    private static Set<Opt> allowedOptions(Command command) {
        Set<Opt> allowed = EnumSet.copyOf(COMMON);
        switch (command) {
            case PREPARE -> allowed.addAll(List.of(Opt.TENANT, Opt.CERT_CHAIN, Opt.OUT_DIR, Opt.ALIAS, Opt.PRODUCTION,
                    Opt.TRUST_ANCHOR, Opt.EXPECTED_ORG_ID));
            case IMPORT -> allowed.addAll(List.of(Opt.STATE, Opt.KEY_MATERIAL, Opt.IMPORT_TOKEN, Opt.PRODUCTION,
                    Opt.TRUST_ANCHOR, Opt.EXPECTED_ORG_ID));
            case RECONCILE -> allowed.add(Opt.GRACE_SECONDS);
        }
        return allowed;
    }

    private static boolean isTrue(String value) {
        return List.of("true", "1", "yes").contains(value.toLowerCase(Locale.ROOT));
    }

    private static long parseLong(Opt option, String value) {
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            throw new UsageException("--" + option.flag + " must be a whole number");
        }
    }

    private static String readString(Path file) {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new OnboardingFailedException("could not read " + file, e);
        }
    }

    private static byte[] readBytes(Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new OnboardingFailedException("could not read " + file, e);
        }
    }
}
