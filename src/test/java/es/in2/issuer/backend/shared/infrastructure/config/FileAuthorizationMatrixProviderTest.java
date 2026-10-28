package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix.Scope;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/** FR-15 / AC-13: the rules are configuration and a change applies to the next request without a restart. */
class FileAuthorizationMatrixProviderTest {

    private static final String R1_OWN = """
              - id: R1
                name: Revoke an attestation
                writes: true
                scope: { platform_admin: any_organization, tenant_admin: any_organization, organization_admin: own_organization, user: deny }\
            """;
    private static final String R1_DENY = R1_OWN.replace("organization_admin: own_organization", "organization_admin: deny");

    @TempDir
    Path dir;

    private final AuditService auditService = mock(AuditService.class);

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

    private FileAuthorizationMatrixProvider providerOf(String content) throws IOException {
        Path file = dir.resolve("authorization-matrix.yaml");
        Files.writeString(file, content);
        return new FileAuthorizationMatrixProvider(file.toString(), auditService);
    }

    private void change(String content) throws IOException {
        Files.writeString(dir.resolve("authorization-matrix.yaml"), content);
    }

    @Test
    void FileAuthorizationMatrixProvider_current_bundledMatrixIsValidAndDefinesTheIssuerActions() {
        // When
        AuthorizationMatrix matrix = new FileAuthorizationMatrixProvider("", auditService).current();

        // Then
        assertThat(matrix.recognitionOrder()).containsExactly("platform_admin", "tenant_admin", "organization_admin", "user");
        assertThat(matrix.action("E4").scope()).containsEntry("tenant_admin", Scope.DENY);
        assertThat(matrix.action("E6").credentialTypesOrEmpty()).contains("gx:LabelCredential", "gx.labelcredential.*");
        assertThat(matrix.action("E9").grantsOutsideTenant()).isTrue();
        assertThat(revokeScopeOfOrganizationAdmin(matrix)).isEqualTo(Scope.OWN_ORGANIZATION);
    }

    @Test
    void FileAuthorizationMatrixProvider_reloadIfChanged_changedRuleAppliesWithoutRestart() throws IOException {
        // Given
        FileAuthorizationMatrixProvider provider = providerOf(bundled());
        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.OWN_ORGANIZATION);
        assertThat(bundled()).contains(R1_OWN);

        // When
        change(bundled().replace(R1_OWN, R1_DENY));
        provider.reloadIfChanged();

        // Then
        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.DENY);
    }

    @Test
    void FileAuthorizationMatrixProvider_reloadIfChanged_detectsAChangeWithTheSameModificationTime() throws IOException {
        // Given: a half-written file is read first and rejected
        FileAuthorizationMatrixProvider provider = providerOf(bundled());
        Path file = dir.resolve("authorization-matrix.yaml");
        FileTime mtime = Files.getLastModifiedTime(file);
        change(bundled().substring(0, bundled().length() / 2));
        Files.setLastModifiedTime(file, mtime);
        provider.reloadIfChanged();

        // When: the finished file lands within the same mtime granularity
        change(bundled().replace(R1_OWN, R1_DENY));
        Files.setLastModifiedTime(file, mtime);
        provider.reloadIfChanged();

        // Then
        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.DENY);
    }

    @Test
    void FileAuthorizationMatrixProvider_reloadIfChanged_invalidChangeIsRejectedAndThePreviousRulesStay() throws IOException {
        // Given
        FileAuthorizationMatrixProvider provider = providerOf(bundled());

        // When: R1 loses the scope of one user type -- an incomplete rule must never read as "allowed"
        change(bundled().replace(R1_OWN, R1_OWN.replace("organization_admin: own_organization, ", "")));
        provider.reloadIfChanged();
        provider.reloadIfChanged();

        // Then: kept, and audited once (the same rejected content is not re-reported)
        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.OWN_ORGANIZATION);
        verify(auditService, times(1)).auditFailure(eq(FileAuthorizationMatrixProvider.EVENT_REJECTED),
                anyString(), eq("invalid"), anyMap());
    }

    /** F4: every misspelt or missing key that would open a permission is rejected, not read as "absent". */
    private static final String ORG_ADMIN_RECOGNITION =
            "    recognized_by:\n      - { type: domain, domain: \"{tenant}\", function: Onboarding, action: Execute }\n";

    static Stream<Arguments> matricesThatWouldOpenAPermission() {
        return Stream.of(
                Arguments.of(Named.of("misspelt recognized_by: the platform administrator recognized by no power",
                        "    recognized_by:\n      - { type: organization, domain: EUDISTACK"),
                        "    recognised_by:\n      - { type: organization, domain: EUDISTACK"),
                Arguments.of(Named.of("misspelt requires_power: anyone could issue product certifications",
                        "    requires_power:"), "    require_power:"),
                Arguments.of(Named.of("action without writes: the platform tenant's read-only mode would not apply",
                        "  - id: R1\n    name: Revoke an attestation\n    writes: true\n"),
                        "  - id: R1\n    name: Revoke an attestation\n"),
                Arguments.of(Named.of("incomplete power pattern",
                        "domain: EUDISTACK, function: System, action: Administration"), "domain: EUDISTACK, function: System"),
                Arguments.of(Named.of("platform administrator recognized by nothing (only the last type is the catch-all)",
                        "    recognized_by:\n      - { type: organization, domain: EUDISTACK, function: System, action: Administration }\n"),
                        "    recognized_by: []\n"),
                Arguments.of(Named.of("no rule for powers outside the tenant (E9)", "    grants_outside_tenant: true\n"), "\n"),
                Arguments.of(Named.of("an action the issuer decides goes missing", "  - id: R2\n"), "  - id: R2-renamed\n"),
                Arguments.of(Named.of("renamed user type: its holders would silently read as USER",
                        "recognition_order: [platform_admin, tenant_admin,"),
                        "recognition_order: [platform_admin, tenant_administrator,"),
                // Round 2 (W-N1): removing a key that protects a permission
                Arguments.of(Named.of("E4 without grants: anyone who can issue would grant the tenant administrator power",
                        "    grants: { type: organization, domain: \"{tenant}\", function: Onboarding, action: Execute }\n"), ""),
                Arguments.of(Named.of("E6 without requires_power: every user type would issue product certifications",
                        "    requires_power: { type: domain, domain: \"{tenant}\", function: Certification, action: Attest }\n"), ""),
                Arguments.of(Named.of("misspelt platform_tenant: the platform administrator could write from the platform tenant",
                        "    platform_tenant: read_only\n"), "    platform_tenant: readonly\n"),
                Arguments.of(Named.of("platform_tenant removed from the platform administrator",
                        "    platform_tenant: read_only\n"), ""),
                // Round 4 (N-R1): the read-only view of every tenant is only for a platform power
                Arguments.of(Named.of("platform_tenant on the organization administrator: it would see every tenant",
                        ORG_ADMIN_RECOGNITION), ORG_ADMIN_RECOGNITION + "    platform_tenant: read_only\n"));
    }

    @ParameterizedTest
    @MethodSource("matricesThatWouldOpenAPermission")
    void FileAuthorizationMatrixProvider_reloadIfChanged_rejectsAMatrixThatWouldOpenAPermission(String from, String to)
            throws IOException {
        // Given
        assertThat(bundled()).contains(from);
        FileAuthorizationMatrixProvider provider = providerOf(bundled());

        // When
        change(bundled().replace(from, to));
        provider.reloadIfChanged();

        // Then
        verify(auditService).auditFailure(eq(FileAuthorizationMatrixProvider.EVENT_REJECTED), anyString(), eq("invalid"), anyMap());
        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.OWN_ORGANIZATION);
    }

    @Test
    void FileAuthorizationMatrixProvider_reloadIfChanged_auditsEveryLoadWithItsDigest() throws IOException {
        // Given
        FileAuthorizationMatrixProvider provider = providerOf(bundled());

        // When
        change(bundled().replace(R1_OWN, R1_DENY));
        provider.reloadIfChanged();

        // Then: startup and the change
        verify(auditService, times(2)).auditSuccess(eq(FileAuthorizationMatrixProvider.EVENT_LOADED),
                anyString(), eq("authorization_matrix"), anyString(), anyMap());
    }

    @Test
    void FileAuthorizationMatrixProvider_constructor_invalidMatrixAtStartupFailsFast() throws IOException {
        // Given
        Path file = dir.resolve("broken.yaml");
        Files.writeString(file, "version: 1\nuser_types: {}\n");
        String path = file.toString();

        // When / Then
        assertThatThrownBy(() -> new FileAuthorizationMatrixProvider(path, auditService))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void FileAuthorizationMatrixProvider_constructor_missingConfiguredFileFailsFast() {
        // Given: a configured path whose mount failed must not silently fall back to the bundled rules
        String absent = dir.resolve("absent.yaml").toString();

        // When / Then
        assertThatThrownBy(() -> new FileAuthorizationMatrixProvider(absent, auditService))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void FileAuthorizationMatrixProvider_reloadIfChanged_fileRemovedAfterStartupKeepsTheRules() throws IOException {
        // Given
        FileAuthorizationMatrixProvider provider = providerOf(bundled());

        // When
        Files.delete(dir.resolve("authorization-matrix.yaml"));
        provider.reloadIfChanged();

        // Then
        assertThat(revokeScopeOfOrganizationAdmin(provider.current())).isEqualTo(Scope.OWN_ORGANIZATION);
        verify(auditService).auditFailure(eq(FileAuthorizationMatrixProvider.EVENT_REJECTED), anyString(), eq("unreadable"), anyMap());
    }
}
