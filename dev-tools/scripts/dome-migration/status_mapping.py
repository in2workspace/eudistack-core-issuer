"""
status_mapping.py — Canonical mapping of source credential_status values to
target issuance status values for the DOME tenant migration.

All mappings confirmed with PO. Rationale per status:
  • DRAFT          → WITHDRAWN : in v3, DRAFTs >1 month auto-convert to WITHDRAWN;
                                 semantically equivalent — offer never redeemed
  • PEND_SIGNATURE → WITHDRAWN : never signed, 6-11 months old; same "never redeemed"
                                 semantics as DRAFT
  • ISSUED         → ARCHIVED  : all 7 PRD records are test data left in error state
  • WITHDRAWN      → WITHDRAWN : direct equivalent — offer explicitly cancelled
"""

# Keys: exact values found in issuer.credential_procedure.credential_status
# Values: target values for dome_issuer.issuance.credential_status
STATUS_MAP: dict[str, str] = {
    "EXPIRED":        "EXPIRED",    # direct copy
    "DRAFT":          "WITHDRAWN",  # offer never redeemed; v3 auto-converts DRAFTs >1 month to WITHDRAWN
    "VALID":          "VALID",      # direct copy
    "REVOKED":        "REVOKED",    # direct copy
    "PEND_SIGNATURE": "WITHDRAWN",  # never signed, effectively abandoned
    "ISSUED":         "ARCHIVED",   # all PRD records are test data left in error state
    "PEND_DOWNLOAD":  "ISSUED",     # 0 in PRD; closest semantic equivalent
    "WITHDRAWN":      "WITHDRAWN",  # direct copy — consistent with DRAFT and PEND_SIGNATURE
}


class UnmappedStatusError(Exception):
    """Raised when a credential_status value has no entry in STATUS_MAP."""

    def __init__(self, raw_value: str, issuance_id: str) -> None:
        super().__init__(
            f"No mapping defined for credential_status='{raw_value}' "
            f"(issuance_id={issuance_id}). "
            "Add the value to STATUS_MAP in status_mapping.py after confirming "
            "the correct target status with the PO."
        )
        self.raw_value   = raw_value
        self.issuance_id = issuance_id


def map_status(raw_value: str, issuance_id: str) -> str:
    """
    Return the mapped target status for raw_value.
    Raises UnmappedStatusError — never silently ignores unknown values.
    """
    try:
        return STATUS_MAP[raw_value]
    except KeyError:
        raise UnmappedStatusError(raw_value, issuance_id)
