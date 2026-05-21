package es.in2.issuer.backend.dome;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HexFormat;
import java.util.List;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration test — AC-06 (plan B re-issuance path).
 *
 * <p>Verifies that {@code GET /.well-known/jwks.json} returns exactly two distinct EC keys
 * when plan B re-issuance is active and the {@code kms_key_migration} row has status
 * {@code PLAN_B_REISSUE}.  The "dual JWKS" window allows wallets holding credentials
 * signed with the legacy key to continue verifying them during re-issuance.
 *
 * <p>The legacy public key used in this test is generated synthetically via
 * {@link KeyPairGenerator} at class-load time to comply with the prohibition of
 * hardcoding real cryptographic material in test code.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-b-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=test-legacy-key"
})
@DisplayName("JWKS endpoint returns dual keys when plan B reissuance is active")
class JwksControllerDualPlanBIT {

    private static final String JWKS_URI = "/.well-known/jwks.json";
    private static final String LEGACY_KEY_ID = "test-legacy-key";

    /**
     * Synthetic EC P-256 public key (uncompressed, 65 bytes) generated at class-load
     * time.  Never logs or exposes private material — only the public coordinates are used.
     */
    private static final String LEGACY_PUBLIC_KEY_HEX;

    static {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    "EC", BouncyCastleProviderSingleton.getInstance());
            kpg.initialize(ecSpec);
            KeyPair kp = kpg.generateKeyPair();

            // Cast to BouncyCastle ECPublicKey to access the raw EC point
            ECPublicKey bcPubKey = (ECPublicKey) kp.getPublic();
            // false = uncompressed encoding (04 || x || y), 65 bytes for P-256
            byte[] uncompressedPoint = bcPubKey.getQ().getEncoded(false);
            LEGACY_PUBLIC_KEY_HEX = HexFormat.of().formatHex(uncompressedPoint);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void registerLegacyPublicKeyHex(DynamicPropertyRegistry registry) {
        registry.add("issuer.dome.key-migration.legacy-public-key-hex",
                () -> LEGACY_PUBLIC_KEY_HEX);
    }

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private KmsKeyMigrationRepositoryPort migrationRepository;

    /**
     * Pre-configured TenantRegistryService mock provided via @TestConfiguration so that
     * reactive @Scheduled schedulers can build their Publisher chain during
     * ScheduledAnnotationBeanPostProcessor processing — before any @BeforeEach runs.
     */
    @TestConfiguration
    static class TenantStubConfig {
        @Bean
        @Primary
        TenantRegistryService tenantRegistryService() {
            TenantRegistryService mock = Mockito.mock(TenantRegistryService.class);
            when(mock.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("localhost")));
            return mock;
        }
    }

    @BeforeEach
    void setUp() {
        // Arrange — simulate a migration row at status PLAN_B_REISSUE
        KmsKeyMigration migration = KmsKeyMigration.builder()
                .legacyKeyId(LEGACY_KEY_ID)
                .migrationStatus("PLAN_B_REISSUE")
                .build();
        when(migrationRepository.findByLegacyKeyId(any(LegacyKeyId.class)))
                .thenReturn(Mono.just(migration));
    }

    @Test
    @DisplayName("JWKS endpoint returns exactly two EC keys with different kids during plan B reissuance")
    void getJwks_WhenPlanBReissueActive_ReturnsDualEcKeys() {
        // Act + Assert
        webTestClient.get()
                .uri(JWKS_URI)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.keys").isArray()
                .jsonPath("$.keys.length()").isEqualTo(2)
                .jsonPath("$.keys[0].kty").isEqualTo("EC")
                .jsonPath("$.keys[1].kty").isEqualTo("EC")
                .jsonPath("$.keys[0].crv").isEqualTo("P-256")
                .jsonPath("$.keys[1].crv").isEqualTo("P-256");
    }

    @Test
    @DisplayName("JWKS endpoint returns keys with different kid values during plan B reissuance")
    void getJwks_WhenPlanBReissueActive_KeysHaveDistinctKids() {
        // Act
        webTestClient.get()
                .uri(JWKS_URI)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                // Legacy key kid is prefixed with "legacy-" — assert exactly one key matches
                .jsonPath("$.keys[?(@.kid =~ /^legacy-.+/)]").value(hasSize(1));
    }
}
