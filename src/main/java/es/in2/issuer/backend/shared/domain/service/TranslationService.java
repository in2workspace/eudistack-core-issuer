package es.in2.issuer.backend.shared.domain.service;

public interface TranslationService {
    public String getLocale();

    /**
     * Resolves the locale to use, preferring the caller-supplied value (e.g. a per-tenant
     * language). When {@code requested} is null, blank or not supported, falls back to the
     * global default returned by {@link #getLocale()}.
     */
    public String getLocaleOrDefault(String requested);

    public String translate(String code, Object... args);

    /**
     * Translates a message code using the given language tag instead of the global default.
     * A distinct name (not a {@code translate} overload) is used deliberately: an overload with
     * a {@code String locale} before the {@code Object... args} would be ambiguous with
     * {@link #translate(String, Object...)} and silently capture a string message argument as the locale.
     */
    public String translateWithLocale(String code, String locale, Object... args);
}
