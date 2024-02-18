package com.thomasdarimont.keycloak.support;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.http.HttpRequest;

public class AuthenticatorUtils {

    public static boolean isGrantTypePasswordRequest(HttpRequest httpRequest) {
        return httpRequest.getUri().getPath().endsWith("/protocol/openid-connect/token") //
                && OAuth2Constants.PASSWORD.equals(httpRequest.getDecodedFormParameters().getFirst(OAuth2Constants.GRANT_TYPE));
    }
}
