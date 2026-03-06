package es.in2.issuer.backend.shared.domain.model.dto.credential;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CredentialStatusTest {

    @Test
    void fromStatusListEntry_mapsAllFieldsCorrectly() {
        StatusListEntry entry = StatusListEntry.builder()
                .id("https://issuer.example/status/42#7")
                .type("BitstringStatusListEntry")
                .statusPurpose(StatusPurpose.REVOCATION)
                .statusListIndex("7")
                .statusListCredential("https://issuer.example/status/42")
                .build();

        CredentialStatus status = CredentialStatus.fromStatusListEntry(entry);

        assertEquals("https://issuer.example/status/42#7", status.id());
        assertEquals("BitstringStatusListEntry", status.type());
        assertEquals("revocation", status.statusPurpose());
        assertEquals("7", status.statusListIndex());
        assertEquals("https://issuer.example/status/42", status.statusListCredential());
    }

    @Test
    void fromStatusListEntry_tokenStatusListType() {
        StatusListEntry entry = StatusListEntry.builder()
                .id("https://issuer.example/token/v1/credentials/status/55#100")
                .type("TokenStatusList")
                .statusPurpose(StatusPurpose.REVOCATION)
                .statusListIndex("100")
                .statusListCredential("https://issuer.example/token/v1/credentials/status/55")
                .build();

        CredentialStatus status = CredentialStatus.fromStatusListEntry(entry);

        assertEquals("TokenStatusList", status.type());
        assertEquals("revocation", status.statusPurpose());
        assertEquals("100", status.statusListIndex());
    }
}
