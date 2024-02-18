package com.thomasdarimont.keycloak.opa.config;

import org.keycloak.models.ClientModel;

public class ClientConfig implements ConfigWrapper {

    private final ClientModel client;

    public ClientConfig(ClientModel client) {
        this.client = client;
    }

    public ClientModel getClient() {
        return client;
    }

    @Override
    public String getType() {
        return "Client";
    }

    @Override
    public String getSource() {
        return client.getClientId();
    }

    public String getValue(String key) {
        return client.getAttribute(key);
    }

    public boolean containsKey(String key) {
        return client.getAttributes().containsKey(key);
    }


}

