package es.in2.issuer.backend.shared.domain.util;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum GlobalErrorTypes {

    INVALID_TOKEN("invalid_token"),
    INVALID_JWT("invalid_jwt"),
    UNSUPPORTED_CREDENTIAL_TYPE("unsupported_credential_type"),
    INVALID_OR_MISSING_PROOF("invalid_or_missing_proof"),
    OPERATION_NOT_SUPPORTED("operation_not_supported"),
    FORMAT_IS_NOT_SUPPORTED("format_is_not_supported"),
    INSUFFICIENT_PERMISSION("insufficient_permission"),
    MISSING_HEADER("missing_header"),
    SAD_ERROR("sad_error"),
    NO_SUCH_ELEMENT("no_such_element"),
    PARSE_ERROR("parse_error"),
    PROOF_VALIDATION_ERROR("proof_validation_error"),
    CREDENTIAL_NOT_FOUND("credential_not_found"),
    PRE_AUTHORIZATION_CODE_GET("pre_authorization_code_get_error"),
    CREDENTIAL_OFFER_NOT_FOUND("credential_offer_not_found"),
    CREDENTIAL_ALREADY_ISSUED("credential_already_issued"),
    JWT_VERIFICATION("jwt_verification_error"),
    UNAUTHORIZED_ROLE("unauthorized_role"),
    EMAIL_COMMUNICATION("email_communication_error"),
    CREDENTIAL_SERIALIZATION("credential_serialization"),
    CREDENTIAL_PROCEDURE_INVALID_STATUS("credential_procedure_invalid_status"),
    CREDENTIAL_PROCEDURE_NOT_FOUND("credential_procedure_not_found"),
    INVALID_CREDENTIAL_FORMAT("invalid_credential_format"),
    DID_KEY_CREATION_ERROR("did_key_creation_error"),
    EC_KEY_CREATION_ERROR("ec_key_creation_error"),
    JWT_CLAIM_MISSING_ERROR("jwt_claim_missing_error"),
    JWT_CREATION_ERROR("jwt_creation_error"),
    MISSING_CREDENTIAL_TYPE_ERROR("missing_credential_type_error"),
    MISSING_EMAIL_OWNER_ERROR("missing_email_owner_error"),
    PARSE_ERROR_EXCEPTION("parse_error_exception"),
    REMOTE_SIGNATURE_ERROR("remote_signature_error"),
    TOKEN_FETCH_ERROR("token_fetch_error"),
    WELL_KNOWN_INFO_FETCH_ERROR("well_known_info_fetch_error");




    private final String code;

}
