package es.in2.issuer.backend.statuslist.domain.service.impl;

import es.in2.issuer.backend.statuslist.domain.model.StatusListData;
import es.in2.issuer.backend.statuslist.domain.service.StatusListRevocationService;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@RequiredArgsConstructor
@Service
public class BitstringStatusListRevocationService
        implements StatusListRevocationService {

    private final BitstringEncoder encoder = new BitstringEncoder();

    @Override
    public StatusListData applyRevocation(StatusListData currentStatusList, int idx) {
        requireNonNullParam(currentStatusList, "current");
        requireNonNullParam(idx, "idx");

        String updatedEncoded =
                encoder.setBit(currentStatusList.encodedList(), idx, true);

        return new StatusListData(
                currentStatusList.id(),
                currentStatusList.purpose(),
                currentStatusList.format(),
                updatedEncoded,
                currentStatusList.signedCredential(),
                currentStatusList.createdAt(),
                currentStatusList.updatedAt()
        );
    }
}
