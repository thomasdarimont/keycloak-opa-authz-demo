package com.thomasdarimont.keycloak.opa.client;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class OpaResource {

    private String realm;

    private Map<String, Object> realmAttributes;

    private String clientId;

    private Map<String, Object> clientAttributes;
}
