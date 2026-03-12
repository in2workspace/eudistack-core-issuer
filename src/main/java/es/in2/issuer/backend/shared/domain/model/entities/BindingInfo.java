package es.in2.issuer.backend.shared.domain.model.entities;

import java.util.Map;

public record BindingInfo(String subjectId, Map<String, Object> cnf) {}