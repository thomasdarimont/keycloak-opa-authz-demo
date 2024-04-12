package com.thomasdarimont.keycloak.opa.authzservices;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;

@Getter
@Setter
public class OpaPolicyRepresentation extends AbstractPolicyRepresentation {

    private String policyUrl;

    private String code;

    @Override
    public String getType() {
        return "opa-policy-provider";
    }
}
