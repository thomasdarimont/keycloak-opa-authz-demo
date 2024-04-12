package com.thomasdarimont.keycloak.accessmgmt;

import lombok.Builder;
import lombok.Data;

import java.util.Set;

@Data
@Builder
public class RealmResource {

    private String id;

    private String type;

    private String path;

    private String name;

    private Set<String> scopes;
}
