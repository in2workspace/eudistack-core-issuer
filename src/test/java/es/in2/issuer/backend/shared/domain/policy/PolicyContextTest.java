package es.in2.issuer.backend.shared.domain.policy;

import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyContextTest {

    @Test
    void hasPower_returnsTrueWhenMatchingFunctionAndStringAction() {
        Power power = Power.builder().function("Onboarding").action("Execute").build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPower("Onboarding", "Execute")).isTrue();
    }

    @Test
    void hasPower_returnsTrueWhenMatchingFunctionAndListAction() {
        Power power = Power.builder().function("Onboarding").action(List.of("Execute", "Read")).build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPower("Onboarding", "Execute")).isTrue();
        assertThat(ctx.hasPower("Onboarding", "Read")).isTrue();
    }

    @Test
    void hasPower_returnsFalseWhenFunctionDoesNotMatch() {
        Power power = Power.builder().function("Certification").action("Execute").build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPower("Onboarding", "Execute")).isFalse();
    }

    @Test
    void hasPower_returnsFalseWhenActionDoesNotMatch() {
        Power power = Power.builder().function("Onboarding").action("Read").build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPower("Onboarding", "Execute")).isFalse();
    }

    @Test
    void hasPower_returnsFalseWhenNoPowers() {
        PolicyContext ctx = new PolicyContext("ORG1", List.of(), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPower("Onboarding", "Execute")).isFalse();
    }

    @Test
    void hasPowerWithDomain_returnsTrueWhenAllMatch() {
        Power power = Power.builder().function("Onboarding").action("Execute").domain("DOME").build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPowerWithDomain("Onboarding", "Execute", "DOME")).isTrue();
    }

    @Test
    void hasPowerWithDomain_returnsFalseWhenDomainDoesNotMatch() {
        Power power = Power.builder().function("Onboarding").action("Execute").domain("OTHER").build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPowerWithDomain("Onboarding", "Execute", "DOME")).isFalse();
    }

    @Test
    void hasPowerWithDomain_returnsFalseWhenFunctionDoesNotMatch() {
        Power power = Power.builder().function("Certification").action("Execute").domain("DOME").build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPowerWithDomain("Onboarding", "Execute", "DOME")).isFalse();
    }

    @Test
    void hasPowerWithDomain_worksWithActionAsList() {
        Power power = Power.builder().function("Onboarding").action(List.of("Execute", "Read")).domain("DOME").build();
        PolicyContext ctx = new PolicyContext("ORG1", List.of(power), null, null, null, false, false, null, null, null);

        assertThat(ctx.hasPowerWithDomain("Onboarding", "Execute", "DOME")).isTrue();
        assertThat(ctx.hasPowerWithDomain("Onboarding", "Read", "DOME")).isTrue();
    }

    @Test
    void allPowersMatchFunction_returnsTrueWhenAllMatch() {
        Power p1 = Power.builder().function("ProductOffering").action("Create").build();
        Power p2 = Power.builder().function("ProductOffering").action("Update").build();

        assertThat(PolicyContext.allPowersMatchFunction(List.of(p1, p2), "ProductOffering")).isTrue();
    }

    @Test
    void allPowersMatchFunction_returnsFalseWhenNotAllMatch() {
        Power p1 = Power.builder().function("ProductOffering").action("Create").build();
        Power p2 = Power.builder().function("Onboarding").action("Execute").build();

        assertThat(PolicyContext.allPowersMatchFunction(List.of(p1, p2), "ProductOffering")).isFalse();
    }

    @Test
    void allPowersMatchFunction_returnsTrueForEmptyList() {
        assertThat(PolicyContext.allPowersMatchFunction(List.of(), "ProductOffering")).isTrue();
    }

    @Test
    void hasAction_returnsTrueForStringAction() {
        Power power = Power.builder().function("Onboarding").action("Execute").build();

        assertThat(PolicyContext.hasAction(power, "Execute")).isTrue();
    }

    @Test
    void hasAction_returnsFalseForNonMatchingStringAction() {
        Power power = Power.builder().function("Onboarding").action("Read").build();

        assertThat(PolicyContext.hasAction(power, "Execute")).isFalse();
    }

    @Test
    void hasAction_returnsTrueForListActionContaining() {
        Power power = Power.builder().function("Onboarding").action(List.of("Execute", "Read")).build();

        assertThat(PolicyContext.hasAction(power, "Execute")).isTrue();
    }

    @Test
    void hasAction_returnsFalseForListActionNotContaining() {
        Power power = Power.builder().function("Onboarding").action(List.of("Read", "Write")).build();

        assertThat(PolicyContext.hasAction(power, "Execute")).isFalse();
    }
}
