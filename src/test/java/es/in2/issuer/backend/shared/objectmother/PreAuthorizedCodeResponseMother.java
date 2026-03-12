package es.in2.issuer.backend.shared.objectmother;

import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.model.dto.TxCode;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.*;

public final class PreAuthorizedCodeResponseMother {

    private PreAuthorizedCodeResponseMother() {
    }

    public static PreAuthorizedCodeResponse dummy() {
        return new PreAuthorizedCodeResponse(
                "preAuthorizedCode",
                new TxCode(5, "inputMode", "description"),
                "txCodeValue"
        );
    }

    public static PreAuthorizedCodeResponse withPreAuthorizedCodeAndTxCode(String preAuthorizedCode, String txCodeValue) {
        return new PreAuthorizedCodeResponse(
                preAuthorizedCode,
                new TxCode(TX_CODE_SIZE, TX_INPUT_MODE, null),
                txCodeValue
        );
    }
}
