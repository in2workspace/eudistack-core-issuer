package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.STATUS_LIST_BASE;

/**
 * Which volume-limited operation a request is (EUD-269), from its method and its path within the
 * application (without the {@code /issuer} base path). Requests of no listed route have no operation.
 *
 * <ul>
 *   <li>Issuance: {@code POST /api/v1/issuances}, and the renewal of its credential offer
 *       ({@code POST /api/v1/issuances/{id}/credential-offer}, EUD-295), which has "the volume limit of
 *       the issuance".</li>
 *   <li>Revocation: {@code POST /api/v1/issuances/{id}/revocation}, the status changes of
 *       {@code PATCH /api/v1/issuances/{id}} and the deprecated {@code POST .../status/revoke}.</li>
 *   <li>Search: {@code POST /api/v1/issuances/search} (EUD-255, not built yet).</li>
 *   <li>Read: list and detail, {@code GET /api/v1/issuances[/{id}]}.</li>
 * </ul>
 */
public final class ApiOperationResolver {

    /** Every route of the issuance, revocation and query APIs is under this path. */
    public static final String MANAGEMENT_API_PREFIX = ISSUANCES_PATH;

    private record Route(HttpMethod method, PathPattern pattern, ApiOperation operation) {
        boolean matches(HttpMethod requestMethod, PathContainer path) {
            return method.equals(requestMethod) && pattern.matches(path);
        }
    }

    private static final PathPatternParser PARSER = PathPatternParser.defaultInstance;

    // The literal routes go before the {id} ones they would otherwise match.
    private static final List<Route> ROUTES = List.of(
            route(HttpMethod.POST, ISSUANCES_PATH, ApiOperation.ISSUANCE),
            route(HttpMethod.POST, ISSUANCES_PATH + "/search", ApiOperation.SEARCH),
            route(HttpMethod.POST, ISSUANCES_PATH + "/{id}/credential-offer", ApiOperation.ISSUANCE),
            route(HttpMethod.POST, ISSUANCES_PATH + "/{id}/revocation", ApiOperation.REVOCATION),
            route(HttpMethod.PATCH, ISSUANCES_PATH + "/{id}", ApiOperation.REVOCATION),
            route(HttpMethod.POST, STATUS_LIST_BASE + "/revoke", ApiOperation.REVOCATION),
            route(HttpMethod.GET, ISSUANCES_PATH, ApiOperation.READ),
            route(HttpMethod.GET, ISSUANCES_PATH + "/{id}", ApiOperation.READ));

    private ApiOperationResolver() {
    }

    public static Optional<ApiOperation> resolve(HttpMethod method, String pathWithinApplication) {
        if (method == null || pathWithinApplication == null) {
            return Optional.empty();
        }
        PathContainer path = PathContainer.parsePath(pathWithinApplication);
        return ROUTES.stream()
                .filter(route -> route.matches(method, path))
                .map(Route::operation)
                .findFirst();
    }

    private static Route route(HttpMethod method, String pattern, ApiOperation operation) {
        return new Route(method, PARSER.parse(pattern), operation);
    }
}
