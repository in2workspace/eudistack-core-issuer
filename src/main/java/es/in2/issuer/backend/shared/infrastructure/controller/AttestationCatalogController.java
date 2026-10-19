package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.CatalogEntryNotFoundException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryETag;
import es.in2.issuer.backend.shared.domain.policy.service.CatalogPdpService;
import es.in2.issuer.backend.shared.domain.service.AttestationCatalogService;
import es.in2.issuer.backend.shared.infrastructure.controller.dto.CatalogEntryConfigurationRequest;
import es.in2.issuer.backend.shared.infrastructure.controller.dto.CatalogEntryCreateRequest;
import es.in2.issuer.backend.shared.infrastructure.controller.dto.CatalogEntryEnabledRequest;
import es.in2.issuer.backend.shared.infrastructure.controller.dto.CatalogEntryResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriUtils;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ATTESTATION_CATALOG_PATH;

/**
 * Attestation Catalogue API (EUD-266): one entry per credential type of the tenant, with the delivery
 * modes, validity, subject and search identifiers the tenant configured. Errors are
 * {@code application/problem+json} (see {@link CatalogExceptionHandler}). The tenant always comes from
 * the Reactor context, never from the body.
 *
 * <p>Authorization: reads use {@link CatalogPdpService#authorizeRead} (administrator, SysAdmin or the
 * tenant's operator), writes {@link CatalogPdpService#authorizeWrite} (tenant administrator). A write
 * receives its body as a {@code Mono} and subscribes to it only once the PDP has allowed the caller: a
 * body already decoded by Spring would answer 400 to an operator who sent a malformed one, instead of
 * {@code insufficient_permission}.
 *
 * <p>The mappings declare no {@code consumes} nor {@code produces}: a content type or {@code Accept} the
 * mapping refused would fail before this controller is chosen and escape the problem+json advice, while one
 * refused when the body is read or written is answered by it.
 *
 * <p>The version of an entry is its strong ETag, sent on every single-entry response. PUT and PATCH take
 * it in {@code If-Match}, which is declared optional here so that its absence is a 428 raised by the
 * service ({@code precondition_required}) and not Spring's 400 for a missing header.
 *
 * <p>A stored row whose credential type file is no longer loaded and was never completed has no delivery
 * modes nor validity, which the contract does not allow in a response. The list leaves it out and a single
 * read answers 404, as if it did not exist: it cannot be issued either, so the tenant loses nothing it could
 * use.
 */
@Slf4j
@RestController
@RequestMapping(ATTESTATION_CATALOG_PATH)
@RequiredArgsConstructor
public class AttestationCatalogController {

    private final CatalogPdpService catalogPdpService;
    private final AttestationCatalogService attestationCatalogService;

    @GetMapping
    public Mono<List<CatalogEntryResponse>> list(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestParam(name = "enabled", required = false) Boolean enabled) {
        return catalogPdpService.authorizeRead(authorizationHeader)
                .thenMany(attestationCatalogService.list(enabled))
                .filter(AttestationCatalogController::isPresentable)
                .map(CatalogEntryResponse::from)
                .collectList();
    }

    @PostMapping
    public Mono<ResponseEntity<CatalogEntryResponse>> create(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestBody Mono<CatalogEntryCreateRequest> body,
            ServerHttpRequest request) {
        return catalogPdpService.authorizeWrite(authorizationHeader)
                .then(body)
                .flatMap(entry -> attestationCatalogService.create(entry.toCommand()))
                .map(AttestationCatalogController::requirePresentable)
                .map(entry -> ResponseEntity.status(HttpStatus.CREATED)
                        .location(locationOf(request, entry))
                        .eTag(CatalogEntryETag.of(entry))
                        .body(CatalogEntryResponse.from(entry)));
    }

    @GetMapping("/{id}")
    public Mono<ResponseEntity<CatalogEntryResponse>> get(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String credentialConfigurationId) {
        return catalogPdpService.authorizeRead(authorizationHeader)
                .then(Mono.defer(() -> attestationCatalogService.get(credentialConfigurationId)))
                .map(AttestationCatalogController::requirePresentable)
                .map(AttestationCatalogController::ok);
    }

    @PutMapping("/{id}")
    public Mono<ResponseEntity<CatalogEntryResponse>> replace(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String credentialConfigurationId,
            @RequestHeader(value = HttpHeaders.IF_MATCH, required = false) String ifMatch,
            @RequestBody Mono<CatalogEntryConfigurationRequest> body) {
        return catalogPdpService.authorizeWrite(authorizationHeader)
                .then(body)
                .flatMap(configuration -> attestationCatalogService.replace(
                        credentialConfigurationId, configuration.toInputIgnoringUnknownFields(), ifMatch))
                .map(AttestationCatalogController::requirePresentable)
                .map(AttestationCatalogController::ok);
    }

    @PatchMapping("/{id}")
    public Mono<ResponseEntity<CatalogEntryResponse>> setEnabled(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String credentialConfigurationId,
            @RequestHeader(value = HttpHeaders.IF_MATCH, required = false) String ifMatch,
            @RequestBody Mono<CatalogEntryEnabledRequest> body) {
        return catalogPdpService.authorizeWrite(authorizationHeader)
                .then(body)
                .flatMap(change -> attestationCatalogService.setEnabled(
                        credentialConfigurationId, change.requireEnabled(), ifMatch))
                .map(AttestationCatalogController::requirePresentable)
                .map(AttestationCatalogController::ok);
    }

    private static ResponseEntity<CatalogEntryResponse> ok(CatalogEntry entry) {
        return ResponseEntity.ok().eTag(CatalogEntryETag.of(entry)).body(CatalogEntryResponse.from(entry));
    }

    /**
     * Relative to the host root and including the context path ({@code /issuer}), because that is what a
     * client resolves it against. Not the absolute URI of the request: behind the load balancer it may
     * carry the internal host.
     */
    private static URI locationOf(ServerHttpRequest request, CatalogEntry entry) {
        return URI.create(request.getPath().contextPath().value() + ATTESTATION_CATALOG_PATH + "/"
                + UriUtils.encodePathSegment(entry.credentialConfigurationId(), StandardCharsets.UTF_8));
    }

    private static boolean isPresentable(CatalogEntry entry) {
        boolean presentable = entry.isFilled();
        if (!presentable) {
            log.warn("Catalog entry '{}' is not shown: its credential type file is not loaded and it was never completed",
                    entry.credentialConfigurationId());
        }
        return presentable;
    }

    private static CatalogEntry requirePresentable(CatalogEntry entry) {
        if (!isPresentable(entry)) {
            throw new CatalogEntryNotFoundException(entry.credentialConfigurationId());
        }
        return entry;
    }
}
