package es.in2.issuer.backend.shared.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.infrastructure.config.security.SecurityProblemResolver.ProblemSpec;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import org.springframework.core.io.buffer.DataBufferUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ProblemAuthenticationEntryPointTest {

    private ObjectMapper objectMapper;
    private ErrorResponseFactory errorResponseFactory;
    private SecurityProblemResolver resolver;

    private ProblemAuthenticationEntryPoint entryPoint;

    @BeforeEach
    void setUp() {
        objectMapper = mock(ObjectMapper.class);
        errorResponseFactory = mock(ErrorResponseFactory.class);
        resolver = mock(SecurityProblemResolver.class);
        entryPoint = new ProblemAuthenticationEntryPoint(objectMapper, errorResponseFactory, resolver, java.util.List.of());
    }

    @Test
    void commence_writesProblemJson_whenObjectMapperSucceeds() throws Exception {
        // given
        AuthenticationException ex = new BadCredentialsException("bad token");
        ProblemSpec spec = new ProblemSpec(
                "auth.invalid_token",
                "Invalid token",
                HttpStatus.UNAUTHORIZED,
                "Invalid token"
        );
        when(resolver.resolve(same(ex), anyBoolean())).thenReturn(spec);

        MockServerHttpRequest request = MockServerHttpRequest.get("/oid4vci/test").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GlobalErrorMessage gem = new GlobalErrorMessage(
                spec.type(), spec.title(), spec.status().value(), "bad token", "instance-123"
        );
        when(errorResponseFactory.handleWithNow(
                same(ex),
                any(ServerHttpRequest.class),
                argThat(s -> s.equals(spec.type())),
                argThat(s -> s.equals(spec.title())),
                argThat(status -> status == spec.status()),
                argThat(s -> s.equals(spec.fallbackDetail()))
        )).thenReturn(gem);

        byte[] serialized = "{\"type\":\"auth.invalid_token\",\"title\":\"Invalid token\",\"status\":401,\"detail\":\"bad token\",\"instance\":\"instance-123\"}"
                .getBytes(StandardCharsets.UTF_8);
        when(objectMapper.writeValueAsBytes(same(gem))).thenReturn(serialized);

        // when
        Mono<Void> result = entryPoint.commence(exchange, ex);

        // then (complete successfully)
        StepVerifier.create(result).verifyComplete();

        // verify status + content-type
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.valueOf("application/problem+json"));

        // verify body content
        String body = DataBufferUtils.join(exchange.getResponse().getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return new String(bytes, StandardCharsets.UTF_8);
                }).block();

        assertThat(body).isEqualTo(new String(serialized, StandardCharsets.UTF_8));

        // verify resolver was called with isAuthenticationPhase=true
        verify(resolver).resolve(ex, true);

        // verify ErrorResponseFactory called with the right args
        ArgumentCaptor<ServerHttpRequest> reqCaptor = ArgumentCaptor.forClass(ServerHttpRequest.class);
        verify(errorResponseFactory).handleWithNow(
                same(ex),
                reqCaptor.capture(),
                argThat(s -> s.equals(spec.type())),
                argThat(s -> s.equals(spec.title())),
                argThat(status -> status == spec.status()),
                argThat(s -> s.equals(spec.fallbackDetail()))
        );
        assertThat(reqCaptor.getValue().getPath().value()).isEqualTo("/oid4vci/test");
    }

    @Test
    void commence_writesFallbackJson_whenObjectMapperThrows() throws Exception {
        // given
        AuthenticationException ex = new BadCredentialsException("oops");
        ProblemSpec spec = new ProblemSpec(
                "auth.default",
                "Unauthorized",
                HttpStatus.UNAUTHORIZED,
                "Authentication failed"
        );
        when(resolver.resolve(same(ex), anyBoolean())).thenReturn(spec);

        MockServerHttpRequest request = MockServerHttpRequest.get("/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GlobalErrorMessage gem = new GlobalErrorMessage(
                spec.type(), spec.title(), spec.status().value(), "oops", "inst-999"
        );
        when(errorResponseFactory.handleWithNow(
                same(ex),
                any(ServerHttpRequest.class),
                anyString(),
                anyString(),
                any(HttpStatus.class),
                anyString()
        )).thenReturn(gem);

        // Force ObjectMapper to fail
        when(objectMapper.writeValueAsBytes(any())).thenThrow(new RuntimeException("marshalling error"));

        // when
        Mono<Void> result = entryPoint.commence(exchange, ex);

        // then
        StepVerifier.create(result).verifyComplete();

        // headers
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .isEqualTo(MediaType.valueOf("application/problem+json"));

        // fallback body
        String body = DataBufferUtils.join(exchange.getResponse().getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return new String(bytes, StandardCharsets.UTF_8);
                }).block();

        assertThat(body).isEqualTo("{\"title\":\"Unauthorized\",\"status\":401}");

        verify(resolver).resolve(ex, true);
        verify(errorResponseFactory).handleWithNow(
                same(ex),
                any(ServerHttpRequest.class),
                argThat(s -> s.equals(spec.type())),
                argThat(s -> s.equals(spec.title())),
                argThat(status -> status == spec.status()),
                argThat(s -> s.equals(spec.fallbackDetail()))
        );
    }

    /** The contracts of the management API set instance to the request path, as the rest of their errors. */
    @Test
    void commence_managementApi_setsTheInstanceToTheRequestPath() throws Exception {
        AuthenticationException ex = new BadCredentialsException("bad token");
        ProblemSpec spec = new ProblemSpec("authentication_error", "Unauthorized", HttpStatus.UNAUTHORIZED, "Authentication failed");
        when(resolver.resolve(same(ex), anyBoolean())).thenReturn(spec);
        when(errorResponseFactory.handleWithNow(any(), any(), any(), any(), any(), any()))
                .thenReturn(new GlobalErrorMessage("authentication_error", "Unauthorized", 401, "bad token", "a-random-uuid"));
        ArgumentCaptor<GlobalErrorMessage> written = ArgumentCaptor.forClass(GlobalErrorMessage.class);
        when(objectMapper.writeValueAsBytes(written.capture())).thenReturn("{}".getBytes(StandardCharsets.UTF_8));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/issuances/0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90/revocation").build());

        StepVerifier.create(entryPoint.commence(exchange, ex)).verifyComplete();

        assertThat(written.getValue().instance()).isEqualTo("/api/v1/issuances/0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90/revocation");
        assertThat(written.getValue().type()).isEqualTo("authentication_error");
    }
}
