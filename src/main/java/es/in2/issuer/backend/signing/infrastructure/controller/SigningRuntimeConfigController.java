package es.in2.issuer.backend.signing.infrastructure.controller;

import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningConfigPushRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/signing")
public class SigningRuntimeConfigController {

    private final RuntimeSigningConfig runtimeSigningConfig;
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
        return ResponseEntity.ok(Map.of(
                PROVIDER, runtimeSigningConfig.getProvider()
        ));
    }
}