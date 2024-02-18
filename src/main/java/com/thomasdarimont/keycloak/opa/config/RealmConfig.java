package com.thomasdarimont.keycloak.opa.config;

import org.keycloak.models.RealmModel;

public class RealmConfig implements ConfigWrapper {

    private final RealmModel realm;

    private final String prefix;

    public RealmConfig(RealmModel realm) {
        this(realm, "");
    }

    public RealmConfig(RealmModel realm, String prefix) {
        this.realm = realm;
        this.prefix = prefix;
    }

    public RealmModel getRealm() {
        return realm;
    }

    @Override
    public String getType() {
        return "Realm";
    }

    @Override
    public String getSource() {
        return realm.getName();
    }

    public String getValue(String key) {
        return realm.getAttribute(prefixed(key));
    }

    public boolean containsKey(String key) {
        return realm.getAttributes().containsKey(prefixed(key));
    }

    private String prefixed(String key) {
        return prefix == null ? key : prefix + key;
    }
}
