package com.thomasdarimont.keycloak.opa.config;

import java.util.Collections;
import java.util.Map;

public class ComponentConfig implements ConfigWrapper {

    private final Map<String, String> config;

    public ComponentConfig(Map<String, String> config) {
        this.config = config == null ? Collections.emptyMap() : config;
    }

    public Map<String, String> getConfig() {
        return config;
    }

    @Override
    public String getType() {
        return "ComponentConfig";
    }

    @Override
    public String getSource() {
        return "component";
    }

    @Override
    public boolean containsKey(String key) {
        return config.containsKey(key);
    }

    @Override
    public String getValue(String key) {
        return config.get(key);
    }
}
