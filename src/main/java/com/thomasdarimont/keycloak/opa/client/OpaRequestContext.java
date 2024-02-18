package com.thomasdarimont.keycloak.opa.client;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class OpaRequestContext {

    private final Map<String, Object> attributes;

    private final Map<String, Object> headers;
}
