package com.thomasdarimont.keycloak.accessmgmt;

import com.thomasdarimont.keycloak.opa.config.ConfigWrapper;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class AccessDecisionContext {

    public static final String ACTION_LOGIN = "login";

    public static final String ACTION_CHECK_ACCESS = "access";

    public static final String ACTION_MANAGE = "manage";

    private final KeycloakSession session;

    private final RealmModel realm;

    private final UserModel user;

    private final ClientModel client;

    private final RealmResource resource;

    private final String action;

    private final ConfigWrapper configOverride;

    public AccessDecisionContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, String action, RealmResource resource) {
        this(session, realm, client, user, resource, action, null);
    }

    public AccessDecisionContext(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, RealmResource resource, String action, ConfigWrapper configOverride) {
        this.session = session;
        this.realm = realm;
        this.user = user;
        this.client = client;
        this.resource = resource;
        this.action = action;
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

    public RealmResource getResource() {
        return resource;
    }

    public String getAction() {
        return action;
    }
}
