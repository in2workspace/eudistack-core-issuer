package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.service.GrantsService;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_CODE_SIZE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_INPUT_MODE;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Service
@RequiredArgsConstructor
@Slf4j
public class GrantsServiceImpl implements GrantsService {

    private final PreAuthorizedCodeService preAuthorizedCodeService;

    @Override
    @Observed(name = "issuance.generate-grants", contextualName = "generate-credential-offer-grants")
    public Mono<GrantsResult> generateGrants(String processId, Mono<String> procedureIdMono) {
        Mono<PreAuthorizedCodeResponse> preAuthMono = preAuthorizedCodeService.generatePreAuthorizedCode(processId, procedureIdMono);
        Mono<String> issuerStateMono = generateCustomNonce();

        return Mono.zip(preAuthMono, issuerStateMono)
                .map(tuple -> {
                    PreAuthorizedCodeResponse preAuthResponse = tuple.getT1();
                    String issuerState = tuple.getT2();

                    AuthorizationCodeGrant authCodeGrant = AuthorizationCodeGrant.builder()
                            .issuerState(issuerState)
                            .build();

                    PreAuthorizedCodeGrant preAuthGrant = PreAuthorizedCodeGrant.builder()
                            .preAuthorizedCode(preAuthResponse.preAuthorizedCode())
                            .txCode(TxCode.builder()
                                    .length(TX_CODE_SIZE)
                                    .inputMode(TX_INPUT_MODE)
                                    .description("Enter the activation code")
                                    .build())
                            .build();

                    CredentialOfferGrants grants = CredentialOfferGrants.builder()
                            .authorizationCode(authCodeGrant)
                            .preAuthorizedCode(preAuthGrant)
                            .build();

                    log.info("ProcessId: {} - Generated both grants for credential offer", processId);

                    return GrantsResult.builder()
                            .grants(grants)
                            .txCodeValue(preAuthResponse.pin())
                            .build();
                });
    }

}
