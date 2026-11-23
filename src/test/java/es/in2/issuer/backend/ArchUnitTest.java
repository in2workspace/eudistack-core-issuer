package es.in2.issuer.backend;


import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.GeneralCodingRules;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;

@AnalyzeClasses(packages = "es.in2.issuer.backend")
class ArchUnitTest {
    private static final String BASE_PACKAGE = "es.in2.issuer.backend";
    private static final Set<String> CONSTANTS_CLASSES =
            Set.of(
                    BASE_PACKAGE + ".shared.domain.util.Constants",
                    BASE_PACKAGE + ".shared.infrastructure.config.SwaggerConfig",
                    BASE_PACKAGE + ".shared.infrastructure.config.TenantDomainWebFilter",
                    BASE_PACKAGE + ".shared.infrastructure.config.IssuerBaseUrlWebFilter",
                    // String constants are inlined by the compiler, so no class shows a dependency on them
                    BASE_PACKAGE + ".shared.domain.model.audit.AuditSource",
                    BASE_PACKAGE + ".shared.domain.model.audit.AuditVocabulary",
                    // Spring-managed beans discovered via component scanning (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.service.AuditServiceImpl",
                    BASE_PACKAGE + ".shared.infrastructure.service.NoOpAuditTrailAdapter",
                    BASE_PACKAGE + ".shared.infrastructure.service.StarterAuditTrailAdapter",
                    BASE_PACKAGE + ".shared.infrastructure.audit.IssuerAuditContextResolver",
                    BASE_PACKAGE + ".shared.infrastructure.audit.MachineAuditAccessTokenProvider",
                    BASE_PACKAGE + ".shared.infrastructure.config.health.SigningServiceHealthIndicator",
                    BASE_PACKAGE + ".shared.infrastructure.config.health.SmtpHealthIndicator",
                    BASE_PACKAGE + ".shared.infrastructure.config.health.VerifierHealthIndicator",
                    // Spring-managed beans discovered via interface or component scanning (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.service.PayloadSchemaValidatorImpl",
                    BASE_PACKAGE + ".shared.infrastructure.service.IssuancePayloadNormalizerImpl",
                    BASE_PACKAGE + ".shared.infrastructure.config.ObservationConfig",
                    BASE_PACKAGE + ".shared.infrastructure.config.RateLimitFilter",
                    BASE_PACKAGE + ".shared.infrastructure.config.FlywayConfig",
                    // EUD-272: wires the domain decision point as a bean (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.config.PowerAuthorizationConfig",
                    // EUD-269: wires the idempotency and volume-limit policies and web filters as beans
                    BASE_PACKAGE + ".shared.infrastructure.config.ApiRequestControlConfig",
                    BASE_PACKAGE + ".shared.infrastructure.config.IdempotencyFilter",
                    // Environment label (email-ui-refactor): WebFilter discovered via component scanning
                    BASE_PACKAGE + ".shared.infrastructure.config.EnvironmentLabelWebFilter",
                    BASE_PACKAGE + ".shared.infrastructure.config.PayloadSizeLimitFilter",
                    // Domain classes used only within a single bounded context (pending refactoring)
                    BASE_PACKAGE + ".shared.domain.exception.MissingEmailOwnerException",
                    BASE_PACKAGE + ".shared.domain.exception.CredentialIssuanceException",
                    BASE_PACKAGE + ".shared.domain.exception.InvalidOrMissingProofException",
                    BASE_PACKAGE + ".shared.domain.service.ClientAttestationValidationService",
                    BASE_PACKAGE + ".shared.domain.model.entities.BindingInfo",
                    // Test object mothers
                    BASE_PACKAGE + ".shared.objectmother.PreAuthorizedCodeResponseMother",
                    // Spring-managed bean discovered via component scanning (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.config.SecureRandomConfig",
                    // Utility class whose static final String constants are inlined by javac (invisible to ArchUnit)
                    BASE_PACKAGE + ".shared.domain.util.EndpointsConstants",
                    // Tenant-related services (EUDI-063/EUDI-065): Spring-managed beans that legitimately
                    // live only in shared, wired via dependency injection into multiple bounded contexts
                    BASE_PACKAGE + ".shared.domain.service.impl.TenantCredentialProfileServiceImpl",
                    BASE_PACKAGE + ".shared.domain.service.impl.TenantConfigServiceImpl",
                    BASE_PACKAGE + ".shared.domain.service.impl.TenantSigningConfigServiceImpl",
                    BASE_PACKAGE + ".shared.domain.service.impl.TenantRegistryServiceImpl",
                    BASE_PACKAGE + ".shared.infrastructure.config.TenantSchemaFlywayMigrator",
                    // Reactive transactions (EUD-72): @Configuration whose beans (ReactiveTransactionManager,
                    // TransactionalOperator) are consumed by injection, never by a direct class reference
                    BASE_PACKAGE + ".shared.infrastructure.config.R2dbcTransactionConfiguration",
                    // Observability: gRPC metrics export and reactive context propagation, Spring-managed
                    // beans discovered via component scanning / @ConditionalOnProperty (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.config.ReactorContextPropagationConfig",
                    BASE_PACKAGE + ".shared.infrastructure.observability.CustomObservationHandler",
                    BASE_PACKAGE + ".shared.infrastructure.config.OtlpGrpcMetricsConfig",
                    BASE_PACKAGE + ".shared.infrastructure.config.OtlpGrpcMetricsSender",
                    BASE_PACKAGE + ".shared.infrastructure.config.MicrometerMetricsConfig",
                    // Spring-managed bean discovered via ObjectProvider<ServerRequestObservationConvention>
                    // in Boot's WebFluxObservationAutoConfiguration (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.config.TenantServerRequestObservationConvention",
                    // OTLP log export: referenced only by class name from logback-spring.xml
                    // (Logback instantiates it via reflection, not a Java reference) ...
                    BASE_PACKAGE + ".shared.infrastructure.config.logging.MaskingOpenTelemetryAppender",
                    // ... and this one is a Spring-managed bean discovered via component
                    // scanning (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.config.OpenTelemetryAppenderInitializer",
                    // EUDISTACK-650 (H-05): IssuanceR2dbcAdapter implements IssuancePort and is
                    // wired by Spring DI through that interface — no direct class reference to
                    // the concrete adapter exists in source, same situation as the other
                    // component-scanning-discovered beans above.
                    BASE_PACKAGE + ".shared.infrastructure.repository.IssuanceR2dbcAdapter",
                    // EUD-266: CatalogEntryR2dbcAdapter implements CatalogEntryPort and is wired by
                    // Spring DI through that interface, like IssuanceR2dbcAdapter above.
                    BASE_PACKAGE + ".shared.infrastructure.repository.CatalogEntryR2dbcAdapter",
                    // EUD-266: ApplicationRunner discovered by component scanning (no direct class
                    // references), like TenantSchemaFlywayMigrator above.
                    BASE_PACKAGE + ".shared.infrastructure.config.TenantCatalogConfigBackfill");

    // EUDISTACK-650 (H-05) scopes the hexagonal fix to Issuance only. These domain entities
    // have the exact same Spring Data leakage (@Table/@Id/@Column, or a direct
    // R2dbcEntityTemplate dependency in a domain service) but are out of scope for this
    // ticket — carried forward as pre-existing, undocumented debt rather than silently
    // widening this PR. Do not add new entries here; fix the offending class instead.
    private static final Set<String> DOMAIN_SPRING_DATA_LEGACY_EXCEPTIONS =
            Set.of(
                    BASE_PACKAGE + ".shared.domain.model.entities.TenantConfig",
                    BASE_PACKAGE + ".shared.domain.model.entities.TenantRegistry",
                    BASE_PACKAGE + ".shared.domain.model.entities.TenantSigningConfig",
                    BASE_PACKAGE + ".shared.domain.model.entities.TenantCredentialProfile",
                    BASE_PACKAGE + ".shared.domain.service.impl.TenantCredentialProfileServiceImpl");

//todo foo
//    @ArchTest
//    static final ArchRule packageDependenciesAreRespected = layeredArchitecture()
//            .consideringOnlyDependenciesInLayers()
//            // Define layers
//            .layer("Issuance").definedBy(BASE_PACKAGE + ".issuance..")
//            .layer("OIDC4VCI").definedBy(BASE_PACKAGE + ".oidc4vci..")
//            .layer("OIDC4VCI-Workflow").definedBy(BASE_PACKAGE + ".oidc4vci.application.workflow..")
//            .layer("Shared").definedBy(BASE_PACKAGE + ".shared..")
//            // Add constraints
//            .whereLayer("Issuance").mayOnlyAccessLayers("OIDC4VCI-Workflow", "Shared")
//            .whereLayer("OIDC4VCI").mayOnlyAccessLayers("Shared")
//            .whereLayer("Shared").mayNotAccessAnyLayer();

    @ArchTest
    static final ArchRule noProductionClassShouldDependOnGplBase58 =
            noClasses()
                    .that().resideInAPackage(BASE_PACKAGE + "..")
                    .should().dependOnClassesThat().resideInAPackage("io.github.novacrypto..");

    @ArchTest
    static final ArchRule signingDomainShouldNotDependOnBouncyCastle =
            noClasses()
                    .that().resideInAPackage(BASE_PACKAGE + ".signing.domain..")
                    // Test fixtures (OwnKeyTestPki and the like) build test certificates with BouncyCastle.
                    .and(DescribedPredicate.describe("are production classes",
                            (JavaClass javaClass) -> javaClass.getSource()
                                    .map(source -> !source.getUri().toString().contains("/test/"))
                                    .orElse(true)))
                    .should().dependOnClassesThat().resideInAPackage("org.bouncycastle..")
                    .because("hexagonal boundary: BouncyCastle is an infrastructure library");

    @ArchTest
    static final ArchRule domainShouldNotDependOnSpringData =
            noClasses()
                    .that().resideInAPackage(BASE_PACKAGE + "..domain..")
                    // *Test/*IT classes are exempt: Testcontainers IT fixtures legitimately seed
                    // rows via R2dbcEntityTemplate directly (hexagonal-discipline.md testing
                    // section already treats *IT as infrastructure-touching by design). This
                    // rule targets production domain code, not test setup.
                    .and(DescribedPredicate.describe(
                            "are not test classes and not pre-existing Tenant* domain entities "
                                    + "(out of EUDISTACK-650 scope, see DOMAIN_SPRING_DATA_LEGACY_EXCEPTIONS)",
                            (JavaClass javaClass) -> !javaClass.getSimpleName().endsWith("Test")
                                    && !javaClass.getSimpleName().endsWith("IT")
                                    && !javaClass.getName().contains("Test$")
                                    && !DOMAIN_SPRING_DATA_LEGACY_EXCEPTIONS.contains(javaClass.getName())))
                    .should().dependOnClassesThat().resideInAnyPackage("org.springframework.data..", "org.springframework.dao..")
                    .because("hexagonal boundary (H-05): domain must not depend on the persistence framework — "
                            + "persistence annotations, R2dbcEntityTemplate/repository access, and Spring's data-access "
                            + "exception hierarchy (org.springframework.dao..) belong in infrastructure");

    @ArchTest
    static final ArchRule implementationsShouldBeInSameLayerAsInterfaces =
            classes()
                    .that().areNotInterfaces()
                    .and().resideInAPackage(BASE_PACKAGE + "..")
                    .and().haveNameMatching(".*(?i)(service|workflow).*")
                    .should(new ArchCondition<>("reside in the same layer as the interfaces they implement") {
                        @Override
                        public void check(JavaClass clazz, ConditionEvents events) {
                            String implLayer = getLayerForPackage(clazz.getPackageName());

                            for (JavaType javaType : clazz.getInterfaces()) {
                                JavaClass implementedInterface = javaType.toErasure();
                                String interfaceLayer = getLayerForPackage(implementedInterface.getPackageName());

                                if (implLayer != null && interfaceLayer != null && !implLayer.equals(interfaceLayer)) {
                                    String message = String.format(
                                            "Class %s (layer: %s) implements %s (layer: %s)",
                                            clazz.getName(), implLayer, implementedInterface.getName(), interfaceLayer
                                    );
                                    events.add(SimpleConditionEvent.violated(clazz, message));
                                }
                            }
                        }
                    });

    private static String getLayerForPackage(String packageName) {
        if (packageName.startsWith(BASE_PACKAGE + ".issuance")) return "Issuance";
        if (packageName.startsWith(BASE_PACKAGE + ".oidc4vci.application.workflow")) return "OIDC4VCI-Workflow";
        if (packageName.startsWith(BASE_PACKAGE + ".oidc4vci")) return "OIDC4VCI";
        if (packageName.startsWith(BASE_PACKAGE + ".shared")) return "Shared";
        return null;
    }

    @ArchTest
    static final ArchRule testClassesShouldResideInTheSamePackageAsImplementation =
            GeneralCodingRules.testClassesShouldResideInTheSamePackageAsImplementation();

    /**
     * Receives the classes ArchUnit already imported for this class (cached), instead of importing the package again:
     * two full imports of the issuer did not fit in the default heap of the test JVM. The users of each class are
     * indexed once, so the rule is linear in the dependencies instead of shared classes times all classes.
     */
    @ArchTest
    static void classesInSharedMustBeUsedBySharedOrByBothIssuanceAndOidc4vci(JavaClasses classes) {
        Map<JavaClass, Set<String>> userAreas = new HashMap<>();
        for (JavaClass user : classes) {
            Set<String> areas = areasOf(user);
            if (areas.isEmpty()) {
                continue;
            }
            user.getDirectDependenciesFromSelf().forEach(dependency ->
                    userAreas.computeIfAbsent(dependency.getTargetClass(), target -> new HashSet<>()).addAll(areas));
        }

        java.util.List<String> violations = new java.util.ArrayList<>();
        for (JavaClass sharedClass : classes) {
            if (!sharedClass.getPackageName().contains(SHARED)
                    || CONSTANTS_CLASSES.contains(sharedClass.getName())
                    || !isNotTestClass(sharedClass)
                    || !isNotAnonymousClass(sharedClass)) {
                continue;
            }
            Set<String> areas = userAreas.getOrDefault(sharedClass, Set.of());
            boolean isShared = (areas.contains(ISSUANCE) && areas.contains(OIDC4VCI)) || areas.contains(SHARED);
            if (!isShared) {
                violations.add(sharedClass.getName());
            }
        }
        assertThat(violations)
                .withFailMessage("The following classes are not used by both packages nor shared: " + violations)
                .isEmpty();
    }

    private static final String SHARED = ".shared";
    private static final String ISSUANCE = ".issuance";
    private static final String OIDC4VCI = ".oidc4vci";

    /** The areas a user class counts for, as the rule always matched them: by a substring of its package. */
    private static Set<String> areasOf(JavaClass javaClass) {
        String packageName = javaClass.getPackageName();
        Set<String> areas = new HashSet<>();
        for (String area : new String[]{SHARED, ISSUANCE, OIDC4VCI}) {
            if (packageName.contains(area)) {
                areas.add(area);
            }
        }
        return areas;
    }

    private static boolean isNotTestClass(JavaClass javaClass) {
        String fullName = javaClass.getName();
        return !javaClass.getSimpleName().endsWith("Test")
                && !javaClass.getSimpleName().endsWith("IT")
                && !fullName.contains("Test$");
    }

    private static boolean isNotAnonymousClass(JavaClass javaClass) {
        String simpleName = javaClass.getSimpleName();
        return !simpleName.isEmpty() && !Character.isDigit(simpleName.charAt(0));
    }
}
