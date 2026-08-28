package es.in2.issuer.backend.shared.domain.model.dto.credential.profile;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialProfileBindingInvariantTest {

    private static final Map<String, CredentialProfile.ProofTypeConfig> JWT_PROOF =
            Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                    .proofSigningAlgValuesSupported(Set.of("ES256"))
                    .build());

    private static CredentialProfile.CredentialProfileBuilder profile(String configId) {
        return CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .format("jwt_vc_json");
    }

    @Nested
    class Invariant1_TheTwoOid4vciFieldsTravelTogether {

        @Test
        void validate_bothPresent_passes() {
            assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                    profile("learcredential.employee.w3c.4")
                            .cryptographicBindingMethodsSupported(Set.of("did:key"))
                            .proofTypesSupported(JWT_PROOF)
                            .build()))
                    .doesNotThrowAnyException();
        }

        @Test
        void validate_bothAbsent_passes() {
            assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                    profile("gx.labelcredential.w3c.2").build()))
                    .doesNotThrowAnyException();
        }

        @Test
        void validate_bindingMethodsWithoutProofTypes_failsNamingProfileAndField() {
            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(
                    profile("some.profile.1")
                            .cryptographicBindingMethodsSupported(Set.of("did:key"))
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("some.profile.1")
                    .hasMessageContaining("cryptographic_binding_methods_supported");
        }

        @Test
        void validate_proofTypesWithoutBindingMethods_failsNamingProfileAndField() {
            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(
                    profile("some.profile.2")
                            .proofTypesSupported(JWT_PROOF)
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("some.profile.2")
                    .hasMessageContaining("proof_types_supported");
        }

        /**
         * ADR-110 requires absence to be declared by removing the key, never by emptying it. The message
         * must say so, because "empty" and "absent" look identical to whoever is reading the failure and
         * only one of them is the fix.
         */
        @Test
        void validate_emptyCollectionsAreTreatedAsAbsent_andTheMessageSaysHowToDeclareAbsence() {
            assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                    profile("some.profile.3")
                            .cryptographicBindingMethodsSupported(Set.of())
                            .proofTypesSupported(Map.of())
                            .build()))
                    .doesNotThrowAnyException();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(
                    profile("some.profile.4")
                            .cryptographicBindingMethodsSupported(Set.of("did:key"))
                            .proofTypesSupported(Map.of())
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("removing the key");
        }
    }

    @Nested
    class Invariant2_CnfRequiredNeedsAProofSource {

        @Test
        void validate_cnfRequiredWithProofTypes_passes() {
            assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                    profile("learcredential.employee.w3c.4")
                            .cryptographicBindingMethodsSupported(Set.of("did:key"))
                            .proofTypesSupported(JWT_PROOF)
                            .cnfRequired(true)
                            .build()))
                    .doesNotThrowAnyException();
        }

        @Test
        void validate_cnfRequiredWithoutProofTypesOnAnOrdinaryType_failsAtStartup() {
            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(
                    profile("gx.labelcredential.w3c.2")
                            .cnfRequired(true)
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("gx.labelcredential.w3c.2")
                    .hasMessageContaining("cnf_required");
        }
    }

    /**
     * AD-8. The exemption is what lets the machine types keep a cnf sourced from the issuance request
     * while staying eligible for direct delivery. It must apply to those two ids and to nothing else --
     * an exemption that leaks is indistinguishable from having dropped the invariant.
     */
    @Nested
    class Ad8Exemption {

        @Test
        void validate_exemptTypesKeepCnfRequiredWithoutProofTypes_passes() {
            for (String configId : new String[]{"learcredential.machine.sd.1", "learcredential.machine.w3c.3"}) {
                assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                        profile(configId).cnfRequired(true).build()))
                        .as("exempt type %s must load", configId)
                        .doesNotThrowAnyException();
            }
        }

        /** The prefix match exists so a version bump does not need a code change to keep issuing. */
        @Test
        void validate_futureVersionsOfTheSameMachineFamilies_areCoveredWithoutACodeChange() {
            for (String configId : new String[]{"learcredential.machine.w3c.4", "learcredential.machine.sd.2"}) {
                assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                        profile(configId).cnfRequired(true).build()))
                        .as("future machine version %s must load", configId)
                        .doesNotThrowAnyException();
            }
        }

        @Test
        void validate_aTypeOutsideTheMachineFamilies_stillFails() {
            // The exemption is scoped to the machine credential families and nothing else: any other
            // type in that same shape is the incoherence the invariant exists to catch.
            for (String configId : new String[]{
                    "learcredential.employee.w3c.4", "gx.labelcredential.w3c.2", "learcredential.machinery.w3c.1"}) {
                assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(
                        profile(configId).cnfRequired(true).build()))
                        .as("non-exempt type %s must fail", configId)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining(configId);
            }
        }

        @Test
        void validate_exemptTypeStillSubjectToInvariant1() {
            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(
                    profile("learcredential.machine.sd.1")
                            .cryptographicBindingMethodsSupported(Set.of("did:key"))
                            .cnfRequired(true)
                            .build()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("cryptographic_binding_methods_supported");
        }
    }
}
