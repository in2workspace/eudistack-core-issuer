package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.OrgContext;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AccessTokenServiceImplTest {

    @Mock
    private SignedJWT mockSignedJwt;
    @Mock
    private ObjectMapper mockObjectMapper;
    @Mock
    private IssuerProperties mockAppConfig;
    @InjectMocks
    private AccessTokenServiceImpl accessTokenServiceImpl;

    @Test
    void testGetCleanBearerToken_Valid() {
        String validHeader = "Bearer validToken123";
        Mono<String> result = accessTokenServiceImpl.getCleanBearerToken(validHeader);
        StepVerifier.create(result)
                .expectNext("validToken123")
                .verifyComplete();
    }

    @Test
    void testGetCleanBearerToken_Invalid() {
        String invalidHeader = "invalidToken123";
        Mono<String> result = accessTokenServiceImpl.getCleanBearerToken(invalidHeader);
        StepVerifier.create(result)
                .expectNext(invalidHeader)
                .verifyComplete();
    }

    @Test
    void testGetOrganizationId_ValidToken() throws JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String expectedOrganizationId = "org123";
        String jwtPayload = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organizationIdentifier\":\"" + expectedOrganizationId + "\"}}}}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);


            Mono<String> result = accessTokenServiceImpl.getOrganizationId("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectNext(expectedOrganizationId)
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationId_InvalidToken() {
        String invalidJwtToken = "invalid-jwt-token";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenThrow(new ParseException("Invalid token", 0));

            Mono<String> result = accessTokenServiceImpl.getOrganizationId("Bearer " + invalidJwtToken);

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

    @Test
    void testGetOrganizationIdFromCurrentSession_ValidToken() throws ParseException, JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String expectedOrganizationId = "org123";
        String jwtPayload = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organizationIdentifier\":\"" + expectedOrganizationId + "\"}}}}}";

        Jwt jwt = Jwt.withTokenValue(validJwtToken).header("alg", "HS256").claim("organizationIdentifier", expectedOrganizationId).build();
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt);
        SecurityContext securityContext = new SecurityContextImpl(jwtAuthenticationToken);

        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class);
             MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {

            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.just(securityContext));

            // Create a JWSHeader and JWTClaimsSet from the payload
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSHeader.parse("{\"alg\":\"HS256\"}")).build();
            JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(jwtPayload);
            SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

            mockedJwtStatic.when(() -> SignedJWT.parse(validJwtToken)).thenReturn(signedJWT);
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectNext(expectedOrganizationId)
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationIdFromCurrentSession_InvalidToken() {
        String invalidJwtToken = "invalid-jwt-token";

        // Creamos un JWT con una reclamación mínima
        Jwt jwt = Jwt.withTokenValue(invalidJwtToken)
                .header("alg", "none")
                .claim("sub", "subject")
                .build();

        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt);
        SecurityContext securityContext = new SecurityContextImpl(jwtAuthenticationToken);

        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class);
             MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {

            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.just(securityContext));

            mockedJwtStatic.when(() -> SignedJWT.parse(invalidJwtToken)).thenThrow(new ParseException("Invalid token", 0));

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }


    @Test
    void testGetOrganizationIdFromCurrentSession_EmptyToken() {
        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class)) {
            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.empty());

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_ValidToken(){
        // Arrange
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        String jti = "jti123";
        String procedureId = UUID.randomUUID().toString();
        long exp = Instant.now().plusSeconds(3600).getEpochSecond();

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);

        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of(
                "jti", jti,
                "pid", procedureId,
                "exp", exp
        ));

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic
                    .when(() -> JWSObject.parse(validToken))
                    .thenReturn(mockJwsObject);

            // Act
            Mono<AccessTokenContext> result =
                    accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            // Assert
            StepVerifier.create(result)
                    .expectNextMatches(context ->
                            validToken.equals(context.rawToken())
                                    && jti.equals(context.jti())
                                    && procedureId.equals(context.procedureId())
                    )
                    .verifyComplete();
        }
    }


    @Test
    void testResolveAccessTokenContext_TokenWithoutJti() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of("exp", 1234567890L)); // Missing jti

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token without jti")
                    )
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_TokenWithoutExp() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of("jti", "jti123", "pid", "proc-1")); // Missing exp

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token without exp")
                    )
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_ExpiredToken() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        long exp = System.currentTimeMillis() / 1000 - 3600; // 1 hour ago
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of(
                "jti", "jti123",
                "pid", "proc-1",
                "exp", exp
        ));

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token expired")
                    )
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_TokenWithoutPid() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of(
                "jti", "jti123",
                "exp", System.currentTimeMillis() / 1000 + 3600
        ));

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token without pid")
                    )
                    .verify();
        }
    }

    @Test
    void testGetOrganizationContext_AdminOrgWithOnboardingPower() throws JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String adminOrgId = "ADMIN_ORG_123";
        String jwtPayload = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organizationIdentifier\":\"" + adminOrgId + "\"},\"power\":[{\"function\":\"Onboarding\",\"action\":\"Execute\"}]}}}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);
            when(mockAppConfig.getAdminOrganizationId()).thenReturn(adminOrgId);

            Mono<OrgContext> result = accessTokenServiceImpl.getOrganizationContext("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectNextMatches(ctx ->
                            ctx.organizationIdentifier().equals(adminOrgId) && ctx.sysAdmin())
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationContext_AdminOrgWithoutOnboardingPower_notSysAdmin() throws JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String adminOrgId = "ADMIN_ORG_123";
        String jwtPayload = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organizationIdentifier\":\"" + adminOrgId + "\"},\"power\":[{\"function\":\"ProductOffering\",\"action\":\"Execute\"}]}}}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);
            when(mockAppConfig.getAdminOrganizationId()).thenReturn(adminOrgId);

            Mono<OrgContext> result = accessTokenServiceImpl.getOrganizationContext("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectNextMatches(ctx ->
                            ctx.organizationIdentifier().equals(adminOrgId) && !ctx.sysAdmin())
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationContext_RegularOrg() throws JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String orgId = "org123";
        String jwtPayload = "{\"vc\":{\"credentialSubject\":{\"mandate\":{\"mandator\":{\"organizationIdentifier\":\"" + orgId + "\"},\"power\":[{\"function\":\"Onboarding\",\"action\":\"Execute\"}]}}}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);
            when(mockAppConfig.getAdminOrganizationId()).thenReturn("ADMIN_ORG_123");

            Mono<OrgContext> result = accessTokenServiceImpl.getOrganizationContext("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectNextMatches(ctx ->
                            ctx.organizationIdentifier().equals(orgId) && !ctx.sysAdmin())
                    .verifyComplete();
        }
    }

}