package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.GetCredentialIssuerMetadataWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.ENGLISH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_WILDCARD_PATH;

@Slf4j
@RestController
@RequiredArgsConstructor
public class CredentialIssuerMetadataController {

    private final GetCredentialIssuerMetadataWorkflow getCredentialIssuerMetadataWorkflow;
    private final UrlResolver urlResolver;

    // MediaType.ALL_VALUE alongside APPLICATION_JSON: we don't implement signed
    // metadata (optional per OID4VCI 1.0 §12.2.3) yet, so an Accept: application/jwt
    // request has nothing to negotiate against and would otherwise get a hard 406 -
    // this keeps serving the plain JSON body regardless of what was requested,
    // letting the caller itself notice it isn't signed instead of being rejected
    // outright (EUD-215, oid4vci-1_0-issuer-metadata-test-signed).
    @GetMapping(
            value = {CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH, CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_WILDCARD_PATH},
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.ALL_VALUE}
    )
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialIssuerMetadata> getCredentialIssuerMetadata(ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().add(HttpHeaders.CONTENT_LANGUAGE, ENGLISH);
        return getCredentialIssuerMetadataWorkflow.execute(processId, publicIssuerBaseUrl)
                .doFirst(() ->
                        log.info("Process ID: {} - Getting Credential Issuer Metadata...", processId))
                .doOnSuccess(credentialOffer ->
                        log.info("Process ID: {} - Credential Issuer Metadata generated successfully.", processId));
    }

}
