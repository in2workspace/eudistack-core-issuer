package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.model.NonceResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_NONCE_PATH;

@RestController
@RequestMapping(OID4VCI_NONCE_PATH)
@RequiredArgsConstructor
public class NonceController {

    private final NonceService nonceService;

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<NonceResponse>> issueNonce() {
        return nonceService.issueNonce()
                .map(response -> ResponseEntity.status(HttpStatus.OK)
                        .header(HttpHeaders.CACHE_CONTROL, "no-store")
                        .body(response));
    }
}
