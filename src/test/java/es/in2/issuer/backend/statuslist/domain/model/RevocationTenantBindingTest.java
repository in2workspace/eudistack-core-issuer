package es.in2.issuer.backend.statuslist.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exhaustive coverage of the four combinations (message tenantId present/absent ×
 * binding declared/absent) — AC-11, AC-12, AC-13, NFR-S-225-07.
 */
class RevocationTenantBindingTest {

    // ---------------------------------------------------------------- binding absent (default, multi-tenant)

    @Test
    void resolve_bindingAbsent_messageTenantPresent_returnsFromMessage() {
        RevocationTenantBinding binding = RevocationTenantBinding.none();

        TenantBindingResolution result = binding.resolve("cgcom");

        assertThat(result).isEqualTo(new TenantBindingResolution.FromMessage("cgcom"));
    }

    @Test
    void resolve_bindingAbsent_messageTenantAbsent_returnsUnresolved() {
        RevocationTenantBinding binding = RevocationTenantBinding.none();

        TenantBindingResolution result = binding.resolve(null);

        assertThat(result).isEqualTo(new TenantBindingResolution.Unresolved());
    }

    @Test
    void resolve_bindingAbsent_messageTenantBlank_returnsUnresolved() {
        RevocationTenantBinding binding = RevocationTenantBinding.none();

        TenantBindingResolution result = binding.resolve("   ");

        assertThat(result).isEqualTo(new TenantBindingResolution.Unresolved());
    }

    // ---------------------------------------------------------------- binding declared (single-tenant, AD-8)

    @Test
    void resolve_bindingDeclared_messageTenantAbsent_returnsFromDeployment() {
        RevocationTenantBinding binding = RevocationTenantBinding.of("prh");

        TenantBindingResolution result = binding.resolve(null);

        assertThat(result).isEqualTo(new TenantBindingResolution.FromDeployment("prh"));
    }

    @Test
    void resolve_bindingDeclared_messageTenantBlank_returnsFromDeployment() {
        RevocationTenantBinding binding = RevocationTenantBinding.of("prh");

        TenantBindingResolution result = binding.resolve("");

        assertThat(result).isEqualTo(new TenantBindingResolution.FromDeployment("prh"));
    }

    @Test
    void resolve_bindingDeclared_messageTenantMatches_returnsFromMessage() {
        RevocationTenantBinding binding = RevocationTenantBinding.of("prh");

        TenantBindingResolution result = binding.resolve("prh");

        assertThat(result).isEqualTo(new TenantBindingResolution.FromMessage("prh"));
    }

    @Test
    void resolve_bindingDeclared_messageTenantDiffers_returnsMismatch() {
        RevocationTenantBinding binding = RevocationTenantBinding.of("prh");

        TenantBindingResolution result = binding.resolve("cgcom");

        assertThat(result).isEqualTo(new TenantBindingResolution.Mismatch("cgcom", "prh"));
    }

    // ---------------------------------------------------------------- isDeclared()

    @Test
    void isDeclared_none_isFalse() {
        assertThat(RevocationTenantBinding.none().isDeclared()).isFalse();
    }

    @Test
    void isDeclared_blankValue_isFalse() {
        assertThat(RevocationTenantBinding.of("  ").isDeclared()).isFalse();
    }

    @Test
    void isDeclared_realValue_isTrue() {
        assertThat(RevocationTenantBinding.of("prh").isDeclared()).isTrue();
    }

    // ---------------------------------------------------------------- exhaustive switch compiles (NFR-S-225-07)

    @Test
    void switchOverResolution_isExhaustiveWithoutADefaultBranch() {
        TenantBindingResolution resolution = RevocationTenantBinding.of("prh").resolve("cgcom");

        String described = switch (resolution) {
            case TenantBindingResolution.FromMessage r -> "from-message:" + r.tenantId();
            case TenantBindingResolution.FromDeployment r -> "from-deployment:" + r.tenantId();
            case TenantBindingResolution.Mismatch r -> "mismatch:" + r.declaredInMessage() + "/" + r.configured();
            case TenantBindingResolution.Unresolved r -> "unresolved";
        };

        assertThat(described).isEqualTo("mismatch:cgcom/prh");
    }
}
