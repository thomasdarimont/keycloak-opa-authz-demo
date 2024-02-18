package com.thomasdarimont.keycloak.opa.config;

import java.util.Map;

public class AuthenticatorConfig implements ConfigWrapper {

    private final String authProviderId;

    private final String authProviderAlias;

    private final Map<String, String> authenticatorConfig;

    public AuthenticatorConfig(String authProviderId, String authProviderAlias, Map<String, String> authenticatorConfig) {
        this.authProviderId = authProviderId;
        this.authProviderAlias = authProviderAlias;
        this.authenticatorConfig = authenticatorConfig != null ? authenticatorConfig : Map.of();
    }

    @Override
    public String getType() {
        return "authenticator";
    }

    @Override
    public String getSource() {
        return authProviderId + ":"+ authProviderAlias;
    }

    @Override
    public boolean containsKey(String key) {
        return authenticatorConfig.containsKey(key);
    }

    @Override
    public String getValue(String key) {
        return authenticatorConfig.get(key);
    }
}
