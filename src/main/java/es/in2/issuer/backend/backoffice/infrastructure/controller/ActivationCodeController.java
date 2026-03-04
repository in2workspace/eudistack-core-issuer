package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.backoffice.application.workflow.ActivationCodeWorkflow;
import es.in2.issuer.backend.backoffice.domain.model.dtos.CredentialOfferUriResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/credential-offer")
@RequiredArgsConstructor
public class ActivationCodeController {

    private final ActivationCodeWorkflow activationCodeWorkflow;

    /**
     * @deprecated Replaced by the simplified flow where credential offers are generated at issuance time.
     * Use {@link #reissueCredentialOffer(String)} for re-emission. Will be removed in a future version.
     */
    @Deprecated(since = "3.0.0", forRemoval = true)
    @GetMapping("/transaction-code/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialOfferUriResponse> getCredentialOfferByTransactionCode(@PathVariable("id") String transactionCode) {
        log.info("Retrieving Credential Offer with Transaction Code...");
        String processId = UUID.randomUUID().toString();
        return activationCodeWorkflow.buildCredentialOfferUri(processId, transactionCode)
                .doOnSuccess(credentialOfferUri -> {
                            log.debug("Credential Offer URI created successfully: {}", credentialOfferUri);
                            log.info("Credential Offer created successfully.");
                        }
                );
    }

    /**
     * @deprecated Replaced by the simplified flow where credential offers are generated at issuance time.
     * Use {@link #reissueCredentialOffer(String)} for re-emission. Will be removed in a future version.
     */
    @Deprecated(since = "3.0.0", forRemoval = true)
    @GetMapping("/c-transaction-code/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialOfferUriResponse> getCredentialOfferByCTransactionCode(@PathVariable("id") String cTransactionCode) {
        log.info("Retrieving Credential Offer with C Transaction Code...");
        String processId = UUID.randomUUID().toString();
        return activationCodeWorkflow.buildNewCredentialOfferUri(processId, cTransactionCode);
    }

    @GetMapping(value = "/reissue/{transactionCode}", produces = "text/html")
    @ResponseStatus(HttpStatus.OK)
    public Mono<String> reissueCredentialOffer(@PathVariable String transactionCode) {
        log.info("Re-issuing credential offer...");
        String processId = UUID.randomUUID().toString();
        return activationCodeWorkflow.reissueCredentialOffer(processId, transactionCode)
                .thenReturn("""
                        <!DOCTYPE html>
                        <html lang="en">
                        <head><meta charset="UTF-8"><title>Credential Offer Sent</title></head>
                        <body style="font-family: Arial, sans-serif; text-align: center; padding: 60px; background-color: #f5f5f5;">
                            <div style="max-width: 480px; margin: 0 auto; background: white; border-radius: 10px; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                                <h2 style="color: #2D58A7; margin-bottom: 20px;">Email Sent</h2>
                                <p style="color: #333; font-size: 16px;">A new credential offer has been sent to your email address.</p>
                                <p style="color: #666; font-size: 14px;">Please check your inbox and scan the QR code with your wallet app.</p>
                            </div>
                        </body>
                        </html>
                        """);
    }

}
