package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyPolicy;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.SlidingWindow;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitPolicy;
import es.in2.issuer.backend.shared.domain.service.IdempotencyService;
import es.in2.issuer.backend.shared.domain.service.VolumeLimitService;
import es.in2.issuer.backend.shared.infrastructure.config.properties.ApiRequestControlProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/** Builds the domain policies of the idempotency and the volume limits from their properties (EUD-269). */
@Configuration
public class ApiRequestControlConfig {

    @Bean
    public VolumeLimitPolicy volumeLimitPolicy(ApiRequestControlProperties properties) {
        ApiRequestControlProperties.VolumeLimit volume = properties.getVolumeLimit();
        return new VolumeLimitPolicy(new SlidingWindow(volume.getWindow()), Map.of(
                ApiOperation.ISSUANCE, limits(volume.getIssuance()),
                ApiOperation.REVOCATION, limits(volume.getRevocation()),
                ApiOperation.SEARCH, limits(volume.getSearch()),
                ApiOperation.READ, limits(volume.getRead())));
    }

    @Bean
    public IdempotencyPolicy idempotencyPolicy(ApiRequestControlProperties properties) {
        return new IdempotencyPolicy(properties.getIdempotency().getRetention(), properties.getIdempotency().getLease());
    }

    /*
     * The two web filters are beans of this configuration rather than @Components: @WebFluxTest slices load
     * every @Component WebFilter, and would need these dependencies in every controller test.
     */

    @Bean
    public ApiVolumeLimitFilter apiVolumeLimitFilter(RequesterResolver requesterResolver,
                                                     VolumeLimitService volumeLimitService,
                                                     ObjectMapper objectMapper, IssuanceMetrics issuanceMetrics) {
        return new ApiVolumeLimitFilter(requesterResolver, volumeLimitService,
                new FilterProblemWriter(objectMapper), issuanceMetrics);
    }

    @Bean
    public IdempotencyFilter idempotencyFilter(RequesterResolver requesterResolver,
                                               IdempotencyService idempotencyService,
                                               ObjectMapper objectMapper, IssuanceMetrics issuanceMetrics,
                                               @Value("${issuer.api.max-payload-size:262144}") long maxPayloadBytes) {
        return new IdempotencyFilter(requesterResolver, idempotencyService,
                new FilterProblemWriter(objectMapper), issuanceMetrics, maxPayloadBytes);
    }

    private static VolumeLimitPolicy.Limits limits(ApiRequestControlProperties.Limits limits) {
        return new VolumeLimitPolicy.Limits(limits.getSystemsPerOrganization(), limits.getPerPerson());
    }
}
