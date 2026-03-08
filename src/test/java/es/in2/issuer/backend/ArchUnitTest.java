package es.in2.issuer.backend;


import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.GeneralCodingRules;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static org.assertj.core.api.Assertions.assertThat;

@AnalyzeClasses(packages = "es.in2.issuer.backend")
class ArchUnitTest {
    private static final String BASE_PACKAGE = "es.in2.issuer.backend";
    private static final Set<String> CONSTANTS_CLASSES =
            Set.of(
                    BASE_PACKAGE + ".shared.domain.util.Constants",
                    BASE_PACKAGE + ".shared.infrastructure.config.SwaggerConfig",
                    BASE_PACKAGE + ".shared.infrastructure.config.TenantDomainWebFilter",
                    // Spring-managed beans discovered via component scanning (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.service.AuditServiceImpl",
                    BASE_PACKAGE + ".shared.infrastructure.config.health.SigningServiceHealthIndicator",
                    BASE_PACKAGE + ".shared.infrastructure.config.health.SmtpHealthIndicator",
                    BASE_PACKAGE + ".shared.infrastructure.config.health.VerifierHealthIndicator",
                    // Spring-managed beans discovered via interface or component scanning (no direct class references)
                    BASE_PACKAGE + ".shared.infrastructure.service.PayloadSchemaValidatorImpl",
                    BASE_PACKAGE + ".shared.infrastructure.config.ObservationConfig",
                    BASE_PACKAGE + ".shared.infrastructure.config.RateLimitFilter",
                    BASE_PACKAGE + ".shared.infrastructure.config.FlywayConfig",
                    BASE_PACKAGE + ".shared.infrastructure.config.IdempotencyFilter",
                    BASE_PACKAGE + ".shared.infrastructure.config.PayloadSizeLimitFilter",
                    // Domain classes used only within a single bounded context (pending refactoring)
                    BASE_PACKAGE + ".shared.domain.exception.MissingEmailOwnerException",
                    BASE_PACKAGE + ".shared.domain.exception.CredentialIssuanceException",
                    BASE_PACKAGE + ".shared.domain.exception.InvalidOrMissingProofException",
                    BASE_PACKAGE + ".shared.domain.service.ClientAttestationValidationService",
                    BASE_PACKAGE + ".shared.domain.model.entities.BindingInfo",
                    // Test object mothers
                    BASE_PACKAGE + ".shared.objectmother.PreAuthorizedCodeResponseMother");

//todo
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

    @Test
    void classesInSharedMustBeUsedBySharedOrByBothIssuanceAndOidc4vci() {
        var classes = new ClassFileImporter().importPackages(BASE_PACKAGE);

        Set<JavaClass> sharedClasses = classes.stream()
                .filter(javaClass -> javaClass.getPackageName().contains(".shared"))
                .collect(Collectors.toSet());

        Set<JavaClass> sharedClassesToCheck = sharedClasses
                .stream()
                .filter(javaClass -> !CONSTANTS_CLASSES.contains(javaClass.getName()))
                .filter(this::isNotTestClass)
                .filter(this::isNotAnonymousClass)
                .collect(Collectors.toSet());

        Set<JavaClass> issuanceClasses = filterClassesByPackage(classes, ".issuance");
        Set<JavaClass> oidcClasses = filterClassesByPackage(classes, ".oidc4vci");


        java.util.List<String> violations = new java.util.ArrayList<>();
        for (JavaClass sharedClass : sharedClassesToCheck) {
            boolean usedByIssuance = issuanceClasses.stream().anyMatch(user -> usesClass(user, sharedClass));
            boolean usedByOidc4vci = oidcClasses.stream().anyMatch(user -> usesClass(user, sharedClass));
            boolean usedByShared = sharedClasses.stream().anyMatch(user -> usesClass(user, sharedClass));

            boolean isShared = ((usedByIssuance && usedByOidc4vci) || usedByShared);
            if (!isShared) {
                violations.add(sharedClass.getName());
            }
        }
        assertThat(violations)
                .withFailMessage("The following classes are not used by both packages nor shared: " + violations)
                .isEmpty();
    }

    private Set<JavaClass> filterClassesByPackage(JavaClasses classes, String packageName) {
        return classes.stream()
                .filter(javaClass -> javaClass.getPackageName().contains(packageName))
                .collect(Collectors.toSet());
    }

    private boolean usesClass(JavaClass javaClass, JavaClass sharedClass) {
        return javaClass.getDirectDependenciesFromSelf().stream()
                .anyMatch(dependency -> dependency.getTargetClass().equals(sharedClass));
    }

    private boolean isNotTestClass(JavaClass javaClass) {
        String fullName = javaClass.getName();
        return !javaClass.getSimpleName().endsWith("Test")
                && !javaClass.getSimpleName().endsWith("IT")
                && !fullName.contains("Test$");
    }

    private boolean isNotAnonymousClass(JavaClass javaClass) {
        String simpleName = javaClass.getSimpleName();
        return !simpleName.isEmpty() && !Character.isDigit(simpleName.charAt(0));
    }
}