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
    UNSUPPORTED_CREDENTIAL_FORMAT("unsupported_credential_format"),
    INVALID_CREDENTIAL_REQUEST("invalid_credential_request"),
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
    ISSUANCE_INVALID_STATUS("issuance_invalid_status"),
    ISSUANCE_NOT_FOUND("issuance_not_found"),
    PAYLOAD_VALIDATION("payload_validation_error"),
    TENANT_MISMATCH("tenant_mismatch"),
    REMOTE_SIGNATURE("remote_signature_error"),
    NO_SUCH_ENTITY("no_such_entity"),
    TEMPLATE_READ_ERROR("template_read_error"),
    ORGANIZATION_ID_MISMATCH("organization_id_mismatch"),
    MISSING_REQUIRED_DATA("missing_required_data"),
    INVALID_STATUS("invalid_status"),
    STATUS_LIST_NOT_FOUND("status_list_not_found"),
    STATUS_LIST_NOT_AVAILABLE("status_list_not_available"),
    INVALID_CREDENTIAL_FORMAT("invalid_credential_format"),
    DID_KEY_CREATION_ERROR("did_key_creation_error"),
    EC_KEY_CREATION_ERROR("ec_key_creation_error"),
    JWT_CLAIM_MISSING_ERROR("jwt_claim_missing_error"),
    JWT_CREATION_ERROR("jwt_creation_error"),
    MISSING_CREDENTIAL_TYPE_ERROR("missing_credential_type_error"),
    MISSING_EMAIL_OWNER_ERROR("missing_email_owner_error"),
    PARSE_ERROR_EXCEPTION("parse_error_exception"),
    TOKEN_FETCH_ERROR("token_fetch_error"),
    WELL_KNOWN_INFO_FETCH_ERROR("well_known_info_fetch_error");

    private final String code;

}
