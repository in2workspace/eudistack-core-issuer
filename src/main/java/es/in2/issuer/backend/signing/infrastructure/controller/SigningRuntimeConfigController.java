package es.in2.issuer.backend.signing.infrastructure.controller;

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

    @PutMapping("/provider")
    public ResponseEntity<Map<String, String>> setProvider(@RequestBody Map<String, String> body) {
        String provider = body.get(PROVIDER);
        if (provider == null || provider.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Missing field '"+ PROVIDER +"'"
            ));
        }

        runtimeSigningConfig.setProvider(provider.trim());
        return ResponseEntity.ok(Map.of(
                PROVIDER, runtimeSigningConfig.getProvider()
        ));
    }
}