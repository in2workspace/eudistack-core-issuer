package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.application.workflow.SendReminderWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/issuance/v1/notifications")
@RequiredArgsConstructor
public class SendReminderController {

    private final SendReminderWorkflow sendReminderWorkflow;

    @PostMapping(value = "/{procedure_id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> sendEmailReminder(@RequestHeader(HttpHeaders.AUTHORIZATION) String bearerToken, @PathVariable("procedure_id") String issuanceId) {
        String processId = UUID.randomUUID().toString();
        return sendReminderWorkflow.sendReminder(processId, issuanceId, bearerToken);
    }
    
}
