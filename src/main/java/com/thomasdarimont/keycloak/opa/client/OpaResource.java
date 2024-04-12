package com.thomasdarimont.keycloak.opa.client;

import lombok.Builder;
import lombok.Data;

import java.util.Map;
import java.util.Set;

@Data
@Builder
public class OpaResource {

    private String realm;

    private Map<String, Object> realmAttributes;

    private String clientId;

    private Map<String, Object> clientAttributes;

    private String resourceId;

    private String resourceType;

    private String resourcePath;

    private String resourceName;

    private Set<String> resourceScopes;
}
