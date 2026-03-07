package es.in2.issuer.backend.statuslist.domain.spi;

import es.in2.issuer.backend.statuslist.domain.model.StatusListIndexData;
import reactor.core.publisher.Mono;

public interface StatusListIndexReservation {
    Mono<StatusListIndexData> reserve(Long statusListId, String issuanceId);
}
