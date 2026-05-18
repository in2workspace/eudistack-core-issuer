package es.in2.issuer.backend.shared.infrastructure.config.logging;

import com.fasterxml.jackson.core.JsonStreamContext;
import net.logstash.logback.mask.ValueMasker;

public class MaskingJsonGeneratorDecorator
        extends net.logstash.logback.mask.MaskingJsonGeneratorDecorator {

    public MaskingJsonGeneratorDecorator() {
        addValueMasker(new PiiValueMasker());
    }

    static ValueMasker newPiiValueMasker() {
        return new PiiValueMasker();
    }

    private static final class PiiValueMasker implements ValueMasker {

        @Override
        public Object mask(final JsonStreamContext context, final Object value) {
            if (!(value instanceof String original)) {
                return null;
            }
            String masked = MaskingPatternLayout.mask(original);
            return masked.equals(original) ? null : masked;
        }
    }
}
