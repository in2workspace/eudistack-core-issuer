package es.in2.issuer.backend.statuslist.domain.service;

import es.in2.issuer.backend.statuslist.domain.model.StatusListData;

public interface StatusListRevocationService {
    StatusListData applyRevocation(StatusListData current, int index);
}
