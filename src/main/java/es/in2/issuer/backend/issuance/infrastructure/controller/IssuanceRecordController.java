package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequestMapping("/issuance/v1/issuances")
@RequiredArgsConstructor
public class IssuanceRecordController {

    private final IssuanceService issuanceService;
    private final AccessTokenService accessTokenService;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<IssuanceList> getAllIssuanceList(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return accessTokenService.getOrganizationContext(authorizationHeader)
                .flatMap(ctx -> issuanceService.getAllIssuancesVisibleFor(
                        ctx.organizationIdentifier(), ctx.sysAdmin()));
    }

    @GetMapping(value = "/{issuance_id}/credential-decoded", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialDetails> getCredentialByIssuanceId(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
                                                             @PathVariable("issuance_id") String issuanceId) {
        return accessTokenService.getOrganizationContext(authorizationHeader)
                .flatMap(ctx -> issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(
                        ctx.organizationIdentifier(), issuanceId, ctx.sysAdmin()));
    }

}
