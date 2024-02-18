package com.thomasdarimont.keycloak.opa.client;

import lombok.Data;

@Data
public class OpaRequest {

    private final OpaPolicyQuery input;
}
