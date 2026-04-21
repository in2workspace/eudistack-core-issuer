package es.in2.issuer.backend.signing.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignDocSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignHashSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SigningProviderConfigTest {

    @Mock private RuntimeSigningConfig runtimeSigningConfig;
    @Mock private TenantSigningConfigService tenantSigningConfigService;
    @Mock private RemoteSignatureService remoteSignatureService;
    @Mock private QtspAuthClient qtspAuthClient;
    @Mock private QtspIssuerService qtspIssuerService;
    @Mock private JwsSignHashService jwsSignHashService;
    @Mock private JadesHeaderBuilderService jadesHeaderBuilder;
    @Mock private CscSigningProperties cscSigningProperties;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private SigningProvider createProvider() {
        return new SigningProviderConfig().signingProvider(
                runtimeSigningConfig,
                tenantSigningConfigService,
                remoteSignatureService,
                qtspAuthClient,
                qtspIssuerService,
                jwsSignHashService,
                jadesHeaderBuilder,
                cscSigningProperties,
                objectMapper
        );
    }

    @Test
    void signingProvider_createsDelegatingProviderWithOperationKeys() {
        SigningProvider provider = createProvider();

        assertInstanceOf(DelegatingSigningProvider.class, provider);

        @SuppressWarnings("unchecked")
        Map<String, SigningProvider> providersByOperation =
                (Map<String, SigningProvider>) ReflectionTestUtils.getField(provider, "providersByOperation");

        assertNotNull(providersByOperation);
        assertEquals(2, providersByOperation.size());
        assertTrue(providersByOperation.containsKey(DelegatingSigningProvider.OP_SIGN_HASH));
        assertTrue(providersByOperation.containsKey(DelegatingSigningProvider.OP_SIGN_DOC));

        assertInstanceOf(CscSignHashSigningProvider.class, providersByOperation.get(DelegatingSigningProvider.OP_SIGN_HASH));
        assertInstanceOf(CscSignDocSigningProvider.class, providersByOperation.get(DelegatingSigningProvider.OP_SIGN_DOC));
    }

    @Test
    void signingProvider_wiresDependenciesIntoCscProviders() {
        SigningProvider provider = createProvider();

        @SuppressWarnings("unchecked")
        Map<String, SigningProvider> providersByOperation =
                (Map<String, SigningProvider>) ReflectionTestUtils.getField(provider, "providersByOperation");

        Object cscDoc = providersByOperation.get(DelegatingSigningProvider.OP_SIGN_DOC);
        assertSame(remoteSignatureService, ReflectionTestUtils.getField(cscDoc, "remoteSignatureService"));

        Object cscHash = providersByOperation.get(DelegatingSigningProvider.OP_SIGN_HASH);
        assertSame(qtspAuthClient, ReflectionTestUtils.getField(cscHash, "qtspAuthClient"));
        assertSame(qtspIssuerService, ReflectionTestUtils.getField(cscHash, "qtspIssuerService"));
        assertSame(jwsSignHashService, ReflectionTestUtils.getField(cscHash, "jwsSignHashService"));
        assertSame(jadesHeaderBuilder, ReflectionTestUtils.getField(cscHash, "jadesHeaderBuilder"));
        assertSame(cscSigningProperties, ReflectionTestUtils.getField(cscHash, "cscSigningProperties"));
        assertSame(objectMapper, ReflectionTestUtils.getField(cscHash, "objectMapper"));
    }

    @Test
    void signingProvider_setsRuntimeSigningConfigIntoDelegatingProvider() {
        SigningProvider provider = createProvider();
        assertSame(runtimeSigningConfig, ReflectionTestUtils.getField(provider, "runtimeSigningConfig"));
    }
}
