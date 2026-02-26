# Plan: Policy Decision Point (PDP) Restructuring

## Current State: 3 Scattered PDP Services

### VerifiableCredentialPolicyAuthorizationServiceImpl
- **Location**: `shared/infrastructure/config/security/service/impl/`
- **Guards**: VCI issuance (`/vci/v1/issuances`)
- **~320 lines**, most complex PDP
- **Does**:
  1. Parse JWT token
  2. Extract `role` claim → must be `LEAR`
  3. Extract `vc` claim → parse into LEARCredential (Employee or Machine)
  4. Route by credential schema:
     - LEARCredentialEmployee: signer policy (admin org + Onboarding/Execute) OR mandator policy (same org + ProductOffering only)
     - LEARCredentialMachine: signer policy OR mandator policy (same org + Onboarding only)
     - LabelCredential: machine VC required + ID token validation + Certification/Attest power

### BackofficePdpServiceImpl
- **Location**: `backoffice/application/workflow/policies/impl/`
- **Guards**: sign credential, send reminder
- **~130 lines**
- **Does**:
  1. Parse JWT token *(duplicated)*
  2. Extract `role` → must be `LEAR` *(duplicated)*
  3. Extract `vc` → parse LEARCredentialEmployee → get mandator org *(duplicated)*
  4. Sys-admin bypass *(duplicated)*
  5. Match user org vs credential org *(duplicated)*

### StatusListPdpServiceImpl
- **Location**: `statuslist/application/workflow/policies/impl/`
- **Guards**: revoke credential
- **~160 lines**
- **Does**:
  1. Validate credential status == VALID *(unique)*
  2. Parse JWT token *(duplicated)*
  3. Extract `role` → must be `LEAR` *(duplicated)*
  4. Extract `vc` → parse LEARCredentialEmployee → get mandator org *(duplicated)*
  5. Sys-admin bypass *(duplicated)*
  6. Match user org vs credential org *(duplicated)*

## Duplicated Code Across the 3 PDPs

| Operation | VcPolicy | BackofficePdp | StatusListPdp |
|-----------|----------|---------------|---------------|
| `jwtService.parseJWT(token)` | Yes | Yes | Yes |
| Extract `role` claim | Yes | Yes | Yes |
| Validate role == `LEAR` | Yes | Yes | Yes |
| Extract `vc` claim | Yes | Yes | Yes |
| Parse VC into LEARCredential | Yes (Employee + Machine) | Yes (Employee only) | Yes (Employee only) |
| Get `mandator.organizationIdentifier` | Yes | Yes | Yes |
| Sys-admin bypass (`adminOrganizationId`) | Implicit in signer policy | Explicit `isSysAdmin()` | Explicit `isSysAdmin()` |
| Match user org vs resource org | Implicit in mandator policy | Explicit | Explicit |

**Estimated duplication**: ~60% of BackofficePdp and StatusListPdp is copy-pasted from each other.

## Proposed Architecture

### New Package Structure

```
shared/domain/policy/
├── PolicyContext.java                  # Value object with pre-parsed token data
├── PolicyContextFactory.java          # Extracts PolicyContext from JWT (single parse)
├── PolicyRule.java                    # Functional interface for composable rules
├── PolicyEnforcer.java                # Composes and executes rules
└── rules/
    ├── RequireRoleRule.java           # role == X
    ├── RequireOrganizationRule.java   # org match or sys-admin bypass
    ├── RequireIssuancePowerRule.java  # power-based authorization (Onboarding/Execute, etc.)
    ├── RequireCredentialStatusRule.java # credential status == VALID
    └── RequireIdTokenRule.java        # ID token validation for LabelCredential
```

### PolicyContext (value object)

```java
/**
 * Pre-parsed authorization context from a JWT access token.
 * Created once per request by PolicyContextFactory.
 */
public record PolicyContext(
    String role,                        // "LEAR", "SYS_ADMIN", "LER", null
    String organizationIdentifier,      // mandator's org ID from VC claim
    List<Power> powers,                 // powers from the mandate
    LEARCredential credential,          // full parsed credential
    String credentialType,              // "LEARCredentialEmployee", "LEARCredentialMachine"
    boolean sysAdmin                    // pre-computed: orgId == adminOrganizationId
) {
    /**
     * Checks if the user has a specific power function with a specific action.
     */
    public boolean hasPower(String function, String action) {
        return powers.stream().anyMatch(p ->
            function.equals(p.function()) &&
            (p.action() instanceof List<?> actions
                ? actions.stream().anyMatch(a -> action.equals(a.toString()))
                : action.equals(p.action().toString()))
        );
    }

    /**
     * Checks if all powers in a list match a specific function.
     */
    public static boolean allPowersMatchFunction(List<Power> powers, String function) {
        return powers.stream().allMatch(p -> function.equals(p.function()));
    }
}
```

### PolicyContextFactory

```java
@Component
@RequiredArgsConstructor
public class PolicyContextFactory {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final AppConfig appConfig;
    // Generic credential parser (replaces factory-specific parsing)

    /**
     * Extracts a PolicyContext from a raw JWT token string.
     * This is the SINGLE place where token parsing happens.
     */
    public Mono<PolicyContext> fromToken(String token) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
            .map(signedJWT -> {
                // 1. Extract role
                String role = extractRole(signedJWT);

                // 2. Extract and parse VC
                String vcClaim = jwtService.getClaimFromPayload(signedJWT.getPayload(), "vc");
                JsonNode vcNode = objectMapper.readTree(vcClaim);
                String credentialType = detectCredentialType(vcNode);
                LEARCredential credential = parseCredential(vcClaim, credentialType);

                // 3. Extract org and powers
                String orgId = extractOrganizationId(credential, credentialType);
                List<Power> powers = extractPowers(credential);
                boolean isSysAdmin = appConfig.getAdminOrganizationId().equals(orgId);

                return new PolicyContext(role, orgId, powers, credential, credentialType, isSysAdmin);
            });
    }

    // ... private helper methods (moved from the 3 PDPs into one place)
}
```

### PolicyRule (functional interface)

```java
/**
 * A composable authorization rule.
 * Returns Mono.empty() on success, Mono.error() on failure.
 */
@FunctionalInterface
public interface PolicyRule<T> {
    Mono<Void> evaluate(PolicyContext context, T target);
}
```

### PolicyEnforcer

```java
@Component
public class PolicyEnforcer {

    /**
     * Evaluates all rules in sequence. Fails fast on first violation.
     */
    @SafeVarargs
    public final <T> Mono<Void> enforce(PolicyContext context, T target, PolicyRule<T>... rules) {
        return Flux.fromArray(rules)
            .concatMap(rule -> rule.evaluate(context, target))
            .then();
    }

    /**
     * Evaluates rules with OR semantics. Succeeds if ANY rule passes.
     */
    @SafeVarargs
    public final <T> Mono<Void> enforceAny(PolicyContext context, T target, PolicyRule<T>... rules) {
        return Flux.fromArray(rules)
            .flatMap(rule -> rule.evaluate(context, target)
                .thenReturn(true)
                .onErrorResume(e -> Mono.just(false)))
            .any(Boolean::booleanValue)
            .flatMap(anyPassed -> anyPassed
                ? Mono.empty()
                : Mono.error(new InsufficientPermissionException("No policy matched")));
    }
}
```

### Concrete Rules

```java
// RequireRoleRule.java
public class RequireRoleRule<T> implements PolicyRule<T> {
    private final String requiredRole;

    public static <T> RequireRoleRule<T> of(String role) {
        return new RequireRoleRule<>(role);
    }

    @Override
    public Mono<Void> evaluate(PolicyContext ctx, T target) {
        if (requiredRole.equals(ctx.role())) return Mono.empty();
        return Mono.error(new UnauthorizedRoleException(
            "Access denied: Unauthorized role '" + ctx.role() + "'"));
    }
}

// RequireOrganizationRule.java
public class RequireOrganizationRule implements PolicyRule<String> {  // target = resourceOrgId

    @Override
    public Mono<Void> evaluate(PolicyContext ctx, String resourceOrgId) {
        if (ctx.sysAdmin()) return Mono.empty();
        if (ctx.organizationIdentifier().equals(resourceOrgId)) return Mono.empty();
        return Mono.error(new UnauthorizedRoleException(
            "Access denied: Unauthorized organization identifier"));
    }
}

// RequireIssuancePowerRule.java
public class RequireIssuancePowerRule implements PolicyRule<Void> {
    private final String function;
    private final String action;

    public static RequireIssuancePowerRule of(String function, String action) {
        return new RequireIssuancePowerRule(function, action);
    }

    @Override
    public Mono<Void> evaluate(PolicyContext ctx, Void target) {
        if (ctx.hasPower(function, action)) return Mono.empty();
        return Mono.error(new InsufficientPermissionException(
            "Missing required power: " + function + "/" + action));
    }
}

// RequireCredentialStatusRule.java
public class RequireCredentialStatusRule implements PolicyRule<CredentialProcedure> {

    @Override
    public Mono<Void> evaluate(PolicyContext ctx, CredentialProcedure procedure) {
        if (procedure.getCredentialStatus() == CredentialStatusEnum.VALID) return Mono.empty();
        return Mono.error(new InvalidStatusException(
            "Invalid status: " + procedure.getCredentialStatus()));
    }
}
```

## Refactored PDP Services

### BackofficePdpServiceImpl (BEFORE: ~130 lines → AFTER: ~30 lines)

```java
@Service
@RequiredArgsConstructor
public class BackofficePdpServiceImpl implements BackofficePdpService {

    private final PolicyContextFactory contextFactory;
    private final PolicyEnforcer enforcer;
    private final CredentialProcedureRepository credentialProcedureRepository;

    @Override
    public Mono<Void> validateSignCredential(String processId, String token, String credentialProcedureId) {
        return validateAction(token, credentialProcedureId);
    }

    @Override
    public Mono<Void> validateSendReminder(String processId, String token, String credentialProcedureId) {
        return validateAction(token, credentialProcedureId);
    }

    private Mono<Void> validateAction(String token, String credentialProcedureId) {
        return contextFactory.fromToken(token)
            .flatMap(ctx -> enforcer.enforce(ctx, null, RequireRoleRule.of("LEAR"))
                .then(ctx.sysAdmin()
                    ? Mono.empty()
                    : credentialProcedureRepository.findById(UUID.fromString(credentialProcedureId))
                        .flatMap(proc -> enforcer.enforce(ctx, proc.getOrganizationIdentifier(),
                            new RequireOrganizationRule()))
                ));
    }
}
```

### StatusListPdpServiceImpl (BEFORE: ~160 lines → AFTER: ~30 lines)

```java
@Service
@RequiredArgsConstructor
public class StatusListPdpServiceImpl implements StatusListPdpService {

    private final PolicyContextFactory contextFactory;
    private final PolicyEnforcer enforcer;

    @Override
    public Mono<Void> validateRevokeCredential(String processId, String token, CredentialProcedure procedure) {
        return contextFactory.fromToken(token)
            .flatMap(ctx -> enforcer.enforce(ctx, procedure,
                new RequireCredentialStatusRule(),
                RequireRoleRule.of("LEAR"),
                (ctxInner, proc) -> new RequireOrganizationRule()
                    .evaluate(ctxInner, proc.getOrganizationIdentifier())
            ));
    }

    @Override
    public Mono<Void> validateRevokeCredentialSystem(String processId, CredentialProcedure procedure) {
        if (procedure.getCredentialStatus() == CredentialStatusEnum.VALID) return Mono.empty();
        return Mono.error(new InvalidStatusException("Invalid status: " + procedure.getCredentialStatus()));
    }
}
```

### VerifiableCredentialPolicyAuthorizationServiceImpl (BEFORE: ~320 lines → AFTER: ~80 lines)

```java
@Service
@RequiredArgsConstructor
public class VerifiableCredentialPolicyAuthorizationServiceImpl
        implements VerifiableCredentialPolicyAuthorizationService {

    private final PolicyContextFactory contextFactory;
    private final PolicyEnforcer enforcer;
    private final ObjectMapper objectMapper;
    private final VerifierService verifierService;
    private final JWTService jwtService;

    @Override
    public Mono<Void> authorize(String token, String schema, JsonNode payload, String idToken) {
        return contextFactory.fromToken(token)
            .flatMap(ctx -> {
                // Role check (LEAR required, LabelCredential needs specific handling)
                if (LABEL_CREDENTIAL.equals(schema)) {
                    return authorizeLabelCredential(ctx, idToken);
                }
                return enforcer.enforce(ctx, null, RequireRoleRule.of("LEAR"))
                    .then(authorizeBySchema(ctx, schema, payload));
            });
    }

    private Mono<Void> authorizeBySchema(PolicyContext ctx, String schema, JsonNode payload) {
        return switch (schema) {
            case LEAR_CREDENTIAL_EMPLOYEE -> enforcer.enforceAny(ctx, payload,
                signerPolicy(),       // admin org + Onboarding/Execute
                mandatorEmployeePolicy()  // same org + ProductOffering only
            );
            case LEAR_CREDENTIAL_MACHINE -> enforcer.enforceAny(ctx, payload,
                signerPolicy(),
                mandatorMachinePolicy()
            );
            default -> Mono.error(new InsufficientPermissionException("Unsupported schema"));
        };
    }

    // ... policy rule factory methods (signerPolicy, mandatorPolicy, etc.)
}
```

## Migration Strategy

### Step 1: Create new policy package (no behavior change)
- Create `PolicyContext`, `PolicyContextFactory`, `PolicyRule`, `PolicyEnforcer`
- Create all rule classes
- Write unit tests for each rule independently

### Step 2: Refactor BackofficePdpServiceImpl (lowest risk)
- Replace internals with PolicyContextFactory + PolicyEnforcer
- Run existing tests — must all pass
- Add regression tests comparing old vs new behavior

### Step 3: Refactor StatusListPdpServiceImpl
- Same approach as Step 2

### Step 4: Refactor VerifiableCredentialPolicyAuthorizationServiceImpl (highest complexity)
- This one has the most complex logic (signer/mandator/certification policies)
- Refactor carefully, one policy at a time
- Run existing tests after each sub-change

### Step 5: Delete duplicated code
- Remove private helper methods from old PDPs that are now in PolicyContextFactory
- Clean up imports

## Benefits

1. **Single token parsing point**: `PolicyContextFactory.fromToken()` — no more copy-paste
2. **Composable rules**: Add new policies by creating a new `PolicyRule`, not modifying 3 services
3. **Testable in isolation**: Each rule has its own unit test
4. **Future PDP migration**: When implementing an external PDP, only `PolicyEnforcer` changes
5. **Readability**: 30-line PDP services instead of 130-160 lines

## Test Strategy

- **Unit tests**: One per `PolicyRule` (RequireRole, RequireOrganization, etc.)
- **Integration tests**: Existing PDP tests must pass unchanged (same inputs → same outputs)
- **Regression tests**: Serialize test cases from current behavior, replay against new code
