package es.in2.issuer.backend.signing.infrastructure.controller;

import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/signing")
@ConditionalOnProperty(prefix = "issuer.signing.runtime", name = "controller-enabled", havingValue = "true", matchIfMissing = true)
public class SigningRuntimeConfigController {

    private final RuntimeSigningConfig runtimeSigningConfig;

    @GetMapping("/provider")
    public ResponseEntity<Map<String, String>> getProvider() {
        return ResponseEntity.ok(Map.of(
                "provider", runtimeSigningConfig.getProvider()
        ));
    }

    @PutMapping("/provider")
    public ResponseEntity<Map<String, String>> setProvider(@RequestBody Map<String, String> body) {
        String provider = body.get("provider");
        if (provider == null || provider.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Missing field 'provider'"
            ));
        }

        runtimeSigningConfig.setProvider(provider.trim());
        return ResponseEntity.ok(Map.of(
                "provider", runtimeSigningConfig.getProvider()
        ));
    }
}