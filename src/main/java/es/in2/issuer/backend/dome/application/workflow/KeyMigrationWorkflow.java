package es.in2.issuer.backend.dome.application.workflow;

import reactor.core.publisher.Mono;

public interface KeyMigrationWorkflow {

    Mono<Void> executePoc(String legacyKeyId);
}

