package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SubjectPathConverterTest {

    private static final String SD_JWT = "dc+sd-jwt";
    private static final String W3C = "jwt_vc_json";

    @Test
    void toClaimPaths_withConcat_convertsEachFieldAndKeepsTheirOrder() {
        CredentialProfile profile = profile(SD_JWT, "direct",
                new CredentialProfile.SubjectExtraction("concat", List.of("givenName", "familyName"), " ", null));

        assertThat(SubjectPathConverter.toClaimPaths(profile))
                .containsExactly(ClaimPath.of("givenName"), ClaimPath.of("familyName"));
    }

    @Test
    void toClaimPaths_withFieldStrategy_convertsTheSingleField() {
        CredentialProfile profile = profile(SD_JWT, "mandate",
                new CredentialProfile.SubjectExtraction("field", List.of("mandatee.domain"), null, null));

        assertThat(SubjectPathConverter.toClaimPaths(profile))
                .containsExactly(ClaimPath.of("mandate", "mandatee", "domain"));
    }

    @Test
    void toClaimPaths_withFieldsStrategyAndDelimiter_convertsTheFieldWithoutTheDelimiter() {
        CredentialProfile profile = profile(W3C, "direct",
                new CredentialProfile.SubjectExtraction("fields", List.of("credentialSubject.id"), null, ":"));

        assertThat(SubjectPathConverter.toClaimPaths(profile))
                .containsExactly(ClaimPath.of("credentialSubject", "id"));
    }

    @Test
    void toClaimPaths_ofMandateSdJwt_prefixesMandate() {
        CredentialProfile profile = profile(SD_JWT, "mandate",
                new CredentialProfile.SubjectExtraction("concat",
                        List.of("mandatee.firstName", "mandatee.lastName"), " ", null));

        assertThat(SubjectPathConverter.toClaimPaths(profile)).containsExactly(
                ClaimPath.of("mandate", "mandatee", "firstName"),
                ClaimPath.of("mandate", "mandatee", "lastName"));
    }

    @Test
    void toClaimPaths_ofMandateW3c_prefixesCredentialSubjectAndMandate() {
        CredentialProfile profile = profile(W3C, null,
                new CredentialProfile.SubjectExtraction("concat", List.of("mandatee.firstName"), " ", null));

        assertThat(SubjectPathConverter.toClaimPaths(profile))
                .containsExactly(ClaimPath.of("credentialSubject", "mandate", "mandatee", "firstName"));
    }

    @Test
    void toClaimPaths_ofAPathAlreadyPrefixedInSdJwt_doesNotPrefixItTwice() {
        CredentialProfile profile = profile(SD_JWT, "mandate",
                new CredentialProfile.SubjectExtraction("concat", List.of("mandate.mandatee.firstName"), " ", null));

        assertThat(SubjectPathConverter.toClaimPaths(profile))
                .containsExactly(ClaimPath.of("mandate", "mandatee", "firstName"));
    }

    @Test
    void toClaimPaths_ofAPathStartingAtMandateInW3c_onlyAddsCredentialSubject() {
        CredentialProfile profile = profile(W3C, "mandate",
                new CredentialProfile.SubjectExtraction("concat", List.of("mandate.mandatee.firstName"), " ", null));

        assertThat(SubjectPathConverter.toClaimPaths(profile))
                .containsExactly(ClaimPath.of("credentialSubject", "mandate", "mandatee", "firstName"));
    }

    @Test
    void toClaimPaths_ofAPathCarryingTheWholeW3cPrefix_keepsItAsIs() {
        CredentialProfile profile = profile(W3C, "mandate",
                new CredentialProfile.SubjectExtraction("concat",
                        List.of("credentialSubject.mandate.mandatee.firstName"), " ", null));

        assertThat(SubjectPathConverter.toClaimPaths(profile))
                .containsExactly(ClaimPath.of("credentialSubject", "mandate", "mandatee", "firstName"));
    }

    @Test
    void toClaimPaths_withoutSubjectExtractionOrFields_isEmpty() {
        assertThat(SubjectPathConverter.toClaimPaths(profile(SD_JWT, "direct", null))).isEmpty();
        assertThat(SubjectPathConverter.toClaimPaths(profile(SD_JWT, "direct",
                new CredentialProfile.SubjectExtraction("concat", null, " ", null)))).isEmpty();
    }

    private static CredentialProfile profile(String format, String strategy,
                                             CredentialProfile.SubjectExtraction extraction) {
        return CredentialProfile.builder()
                .credentialConfigurationId("test.type.1")
                .format(format)
                .credentialSubjectStrategy(strategy)
                .subjectExtraction(extraction)
                .build();
    }
}
