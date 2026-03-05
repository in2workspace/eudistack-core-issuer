-- Migrate credential_type column from CredentialType enum names to credential_configuration_id values.
-- Previously the enum name (e.g. "LEAR_CREDENTIAL_EMPLOYEE") was stored; now the OID4VCI
-- credential_configuration_id is stored directly (e.g. "LEARCredentialEmployeeW3C").
-- Note: LEAR_CREDENTIAL_EMPLOYEE was the jwt_vc_json variant → now LEARCredentialEmployeeW3C.
--       LEAR_CREDENTIAL_EMPLOYEE_SD_JWT was the dc+sd-jwt variant → now LEARCredentialEmployeeSdJwt.

UPDATE credential_procedure SET credential_type = 'LEARCredentialEmployeeW3C'
    WHERE credential_type = 'LEAR_CREDENTIAL_EMPLOYEE';

UPDATE credential_procedure SET credential_type = 'LEARCredentialEmployeeSdJwt'
    WHERE credential_type = 'LEAR_CREDENTIAL_EMPLOYEE_SD_JWT';

UPDATE credential_procedure SET credential_type = 'LEARCredentialMachineW3C'
    WHERE credential_type = 'LEAR_CREDENTIAL_MACHINE';

UPDATE credential_procedure SET credential_type = 'LEARCredentialMachineSdJwt'
    WHERE credential_type = 'LEAR_CREDENTIAL_MACHINE_SD_JWT';

UPDATE credential_procedure SET credential_type = 'gx:LabelCredential'
    WHERE credential_type = 'LABEL_CREDENTIAL';
