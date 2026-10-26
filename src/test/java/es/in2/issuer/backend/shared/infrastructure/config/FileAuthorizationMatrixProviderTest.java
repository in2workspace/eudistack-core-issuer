package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix.Scope;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** FR-15 / AC-13: the rules are configuration and a change applies to the next request without a restart. */
class FileAuthorizationMatrixProviderTest {

    @TempDir
    Path dir;

    /** A clock the test moves forward, so the re-read interval does not need real waiting. */
    private static final class MovableClock extends Clock {
        private Instant now = Instant.parse("2026-10-16T10:00:00Z");

        void advance(long seconds) {
            now = now.plusSeconds(seconds);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private static String bundled() throws IOException {
        try (InputStream is = FileAuthorizationMatrixProviderTest.class.getClassLoader()
                .getResourceAsStream(FileAuthorizationMatrixProvider.CLASSPATH_DEFAULT)) {
            // LF only: the edits below match LF text, and a checkout with core.autocrlf has CRLF.
            return new String(is.readAllBytes(), StandardCharsets.UTF_8).replace("\r\n", "\n");
        }
    }

    private static Scope revokeScopeOfOrganizationAdmin(AuthorizationMatrix matrix) {
        return matrix.action("R1").scope().get("organization_admin");
    }

    @Test
    void bundledMatrix_isValidAndDefinesTheIssuerActions() {
        AuthorizationMatrix matrix = new FileAuthorizationMatrixProvider("").current();

        assertThat(matrix.recognitionOrder()).containsExactly("platform_admin", "tenant_admin", "organization_admin", "user");
        assertThat(matrix.action("E4").scope().get("tenant_admin")).isEqualTo(Scope.DENY);
        assertThat(matrix.action("E6").credentialTypesOrEmpty()).contains("gx:LabelCredential", "gx.labelcredential.*");
        assertThat(matrix.action("E9").grantsOutsideTenant()).isTrue();
        assertThat(revokeScopeOfOrganizationAdmin(matrix)).isEqualTo(Scope.OWN_ORGANIZATION);
    }

    @Test
    void changedRule_appliesOnTheNextCall_withoutRestart() throws IOException {
        Path file = dir.resolve("authorization-matrix.yaml");
        Files.writeString(file, bundled());
        MovableClock clock = new MovableClock();
        FileAuthorizationMatrixProvider provider = new FileAuthorizationMatrixProvider(file.toString(), clock);
        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.OWN_ORGANIZATION);

        String changed = bundled().replace(
                "  - id: R1\n    name: Revoke an attestation\n    writes: true\n    scope: { platform_admin: any_organization, tenant_admin: any_organization, organization_admin: own_organization, user: deny }",
                "  - id: R1\n    name: Revoke an attestation\n    writes: true\n    scope: { platform_admin: any_organization, tenant_admin: any_organization, organization_admin: deny, user: deny }");
        assertThat(changed).isNotEqualTo(bundled());
        Files.writeString(file, changed);
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(60)));
        clock.advance(FileAuthorizationMatrixProvider.CHECK_INTERVAL.toSeconds() + 1);

        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.DENY);
    }

    @Test
    void invalidChange_isRejected_andThePreviousRulesStay() throws IOException {
        Path file = dir.resolve("authorization-matrix.yaml");
        Files.writeString(file, bundled());
        MovableClock clock = new MovableClock();
        FileAuthorizationMatrixProvider provider = new FileAuthorizationMatrixProvider(file.toString(), clock);

        // R1 loses the scope of one user type: an incomplete rule must never read as "allowed".
        Files.writeString(file, bundled().replace("organization_admin: own_organization, user: deny }\n\n  - id: R2",
                "user: deny }\n\n  - id: R2"));
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().plusSeconds(60)));
        clock.advance(FileAuthorizationMatrixProvider.CHECK_INTERVAL.toSeconds() + 1);

        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.OWN_ORGANIZATION);
    }

    @Test
    void invalidMatrixAtStartup_failsFast() throws IOException {
        Path file = dir.resolve("broken.yaml");
        Files.writeString(file, "version: 1\nuser_types: {}\n");

        assertThatThrownBy(() -> new FileAuthorizationMatrixProvider(file.toString()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void missingExternalFile_fallsBackToTheBundledMatrix() {
        AuthorizationMatrix matrix = new FileAuthorizationMatrixProvider(dir.resolve("absent.yaml").toString()).current();

        assertThat(matrix.action("R1")).isNotNull();
    }
}
