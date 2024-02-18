package com.thomasdarimont.keycloak.opa.client;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Data
public class OpaResponse {

    public static final OpaResponse DENY;

    static {
        OpaResponse deny = new OpaResponse();
        deny.setResult(false);
        deny.setMetadata(Collections.emptyMap());
        DENY = deny;
    }

    private Boolean result;

    private String decisionId;

    private Map<String, Object> metadata;

    @JsonIgnore
    public boolean isAllowed() {
        return result == Boolean.TRUE;
    }

    @JsonAnySetter
    public void handleUnknownProperty(String key, Object value) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        this.metadata.put(key, value);
    }
}
