package com.thomasdarimont.keycloak.opa.config;

import org.keycloak.Config;

import java.util.Set;

public class ScopeConfig implements ConfigWrapper {

    private final Config.Scope scope;

    private final Set<String> keys;

    public ScopeConfig(Config.Scope scope) {
        this.scope = scope;
        this.keys = scope.getPropertyNames();
    }

    @Override
    public String getType() {
        return "Scope";
    }

    @Override
    public String getSource() {
        return "spi";
    }

    @Override
    public boolean containsKey(String key) {
        return keys.contains(key);
    }

    @Override
    public String getValue(String key) {
        return scope.get(key);
    }
}
