package com.thomasdarimont.keycloak.opa.checkaccess;

import com.google.auto.service.AutoService;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProviderFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.util.HashMap;
import java.util.Map;

@AutoService(AccessPolicyProviderFactory.class)
public class OpaAccessPolicyProviderFactory implements AccessPolicyProviderFactory {

    private Map<String, String> config;

    @Override
    public String getId() {
        return OpaAccessPolicyProvider.ID;
    }

    @Override
    public AccessPolicyProvider create(KeycloakSession session) {
        return new OpaAccessPolicyProvider(config);
    }

    @Override
    public void init(Config.Scope scope) {
        this.config = readConfig(scope);
    }

    protected Map<String, String> readConfig(Config.Scope scope) {
        Map<String, String> config = new HashMap<>();
        for (var option : OpaAccessPolicyProvider.Option.values()) {
            config.put(option.getKey(), scope.get(option.getKey()));
        }
        return config;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }
}