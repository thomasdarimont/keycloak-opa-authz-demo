package com.thomasdarimont.keycloak.opa.client;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class OpaSubject {

    private String id;

    private String username;

    private List<String> realmRoles;

    private List<String> clientRoles;

    private Map<String, Object> attributes;

    private List<String> groups;
}
