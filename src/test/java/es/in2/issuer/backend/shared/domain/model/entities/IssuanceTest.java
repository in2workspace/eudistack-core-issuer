package es.in2.issuer.backend.shared.domain.model.entities;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;


import static org.assertj.core.api.Assertions.assertThat;

class IssuanceTest {

    @ParameterizedTest
    @CsvSource({
            "ui, UI",
            "email, EMAIL",
            "'email,ui', UI",
            "'ui, email', UI",
            "'direct,email', EMAIL"
    })
    void Issuance_offerDeliveryMode_prefersUiThenEmail(String delivery, DeliveryMode expected) {
        Issuance issuance = Issuance.builder().delivery(delivery).build();

        assertThat(issuance.offerDeliveryMode()).contains(expected);
    }

    @ParameterizedTest
    @NullSource
    @CsvSource({"direct", "''"})
    void Issuance_offerDeliveryMode_isEmptyWithoutAnOfferMode(String delivery) {
        Issuance issuance = Issuance.builder().delivery(delivery).build();

        assertThat(issuance.offerDeliveryMode()).isEmpty();
    }
}
