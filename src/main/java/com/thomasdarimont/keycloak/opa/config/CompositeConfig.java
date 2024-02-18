package com.thomasdarimont.keycloak.opa.config;

import java.util.List;

public class CompositeConfig implements ConfigWrapper {

    private final List<ConfigWrapper> configs;

    public CompositeConfig(List<ConfigWrapper> configs) {
        this.configs = configs;
    }

    @Override
    public String getType() {
        return "composite";
    }

    @Override
    public String getSource() {
        return "config-aggregation";
    }

    @Override
    public boolean containsKey(String key) {
        return configs.stream().anyMatch(config -> config.containsKey(key));
    }

    @Override
    public String getValue(String key) {
        for (ConfigWrapper config : configs) {
            if (config.containsKey(key)) {
                return config.getValue(key);
            }
        }
        return null;
    }
}
