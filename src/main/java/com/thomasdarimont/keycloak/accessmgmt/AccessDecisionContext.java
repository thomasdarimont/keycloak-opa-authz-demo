package com.thomasdarimont.keycloak.accessmgmt;

import com.thomasdarimont.keycloak.opa.config.ConfigWrapper;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class AccessDecisionContext {

    private final KeycloakSession session;

    private final RealmModel realm;

    private final UserModel user;

    private final ClientModel client;

    private final ConfigWrapper configOverride;

    public AccessDecisionContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user) {
        this(session, realm, client, user, null);
    }

    public AccessDecisionContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, ConfigWrapper configOverride) {
        this.session = session;
        this.realm = realm;
        this.user = user;
        this.client = client;
        this.configOverride = configOverride;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public ClientModel getClient() {
        return client;
    }

    public UserModel getUser() {
        return user;
    }

    public KeycloakSession getSession() {
        return session;
    }

    public ConfigWrapper getConfigOverride() {
        return configOverride;
    }
}
