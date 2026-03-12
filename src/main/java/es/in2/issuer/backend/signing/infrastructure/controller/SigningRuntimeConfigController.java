package es.in2.issuer.backend.signing.infrastructure.controller;

import org.springframework.web.bind.annotation.*;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningConfigPushRequest;
import jakarta.validation.Valid;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/signing")
public class SigningRuntimeConfigController {

    private final RuntimeSigningConfig runtimeSigningConfig;
    private final AuditService auditService;
    private static final String PROVIDER = "provider";

    @GetMapping("/provider")
    public ResponseEntity<Map<String, String>> getProvider() {
        return ResponseEntity.ok(Map.of(
                PROVIDER, runtimeSigningConfig.getProvider()
        ));
    }

    @PutMapping("/config")
    public ResponseEntity<Map<String, String>> pushSigningConfig(@Valid @RequestBody SigningConfigPushRequest request){
        String provider = request.provider();
        RemoteSignatureDto remoteSignature = request.remoteSignature();
        if (provider == null || provider.isBlank() || remoteSignature == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Missing field '"+ PROVIDER +"'"
            ));
        }
        runtimeSigningConfig.setProvider(provider.trim());
        runtimeSigningConfig.setRemoteSignature(remoteSignature);
        auditService.auditSuccess("signing.config.changed", null, "signing", provider.trim(),
                Map.of("action", "pushSigningConfig"));
        return ResponseEntity.ok(Map.of(
                PROVIDER, runtimeSigningConfig.getProvider()
        ));
    }
}