package es.in2.issuer.backend.statuslist.infrastructure.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.test.StepVerifier;

import java.net.InetSocketAddress;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class RevocationAuthenticationAuditorTest {

    private static final String ID = "0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90";
    private static final String ROUTE = "/api/v1/issuances/" + ID + "/revocation";

    private RevocationWorkflow workflow;
    private RevocationAuthenticationAuditor auditor;

    @BeforeEach
    void setUp() {
        workflow = mock(RevocationWorkflow.class);
        auditor = new RevocationAuthenticationAuditor(workflow, new ObjectMapper());
    }

    private void reject(MockServerHttpRequest request) {
        StepVerifier.create(auditor.onRejected(MockServerWebExchange.from(request), "invalid_token")).verifyComplete();
    }

    @Test
    void onRejected_revocationWithoutAValidToken_tracesTheIdTheReasonAndTheAddress() {
        reject(MockServerHttpRequest.post(ROUTE)
                .remoteAddress(new InetSocketAddress("203.0.113.7", 443))
                .body("{\"reason\":\"Baja del empleado\"}"));

        verify(workflow).traceUnauthenticated(ID, "Baja del empleado", "invalid_token", "203.0.113.7");
    }

    @Test
    void onRejected_contextPathDoesNotHideTheRoute() {
        reject(MockServerHttpRequest.post("/issuer" + ROUTE).contextPath("/issuer").body("{\"reason\":\"x\"}"));

        verify(workflow).traceUnauthenticated(eq(ID), eq("x"), eq("invalid_token"), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{not json", "{}", "{\"reason\":5}", "{\"reason\":null}"})
    void onRejected_bodyWithoutAStringReason_stillTracesTheRequest(String body) {
        reject(MockServerHttpRequest.post(ROUTE).body(body));

        verify(workflow).traceUnauthenticated(eq(ID), isNull(), eq("invalid_token"), any());
    }

    @Test
    void onRejected_bodyAboveTheLimit_isNotReadAndStillTracesTheRequest() {
        reject(MockServerHttpRequest.post(ROUTE).body("{\"reason\":\"" + "x".repeat(20_000) + "\"}"));

        verify(workflow).traceUnauthenticated(eq(ID), isNull(), eq("invalid_token"), any());
    }

    @Test
    void onRejected_anotherRouteOrMethod_tracesNothing() {
        reject(MockServerHttpRequest.post("/api/v1/issuances").body("{}"));
        reject(MockServerHttpRequest.post("/api/v1/issuances/" + ID).body("{}"));
        reject(MockServerHttpRequest.get(ROUTE).build());

        verifyNoInteractions(workflow);
    }
}
