package com.thomasdarimont.keycloak.opa.checkaccess;

import com.google.auto.service.AutoService;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecision;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecisionContext;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import com.thomasdarimont.keycloak.accessmgmt.RealmResource;
import com.thomasdarimont.keycloak.support.AuthenticatorUtils;
import jakarta.ws.rs.core.Response;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.messages.Messages;

public class OpaCheckAccessRequiredActionProvider implements RequiredActionProvider {

    public static final String ID = "action-opa-check-access";

    public static final String ACTION_ALREADY_EXECUTED_MARKER = ID;

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

        if (AuthenticatorUtils.isGrantTypePasswordRequest(context.getHttpRequest())) {
            // exclude grant_type=password requests
            // we need to use a special authenticator for that
            return;
        }

        var authSession = context.getAuthenticationSession();
        if (authSession.getAuthNote(ACTION_ALREADY_EXECUTED_MARKER) != null) {
            return;
        }
        authSession.setAuthNote(ACTION_ALREADY_EXECUTED_MARKER, "true");

        authSession.addRequiredAction(ID);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {

        var realm = context.getRealm();
        var user = context.getUser();
        var session = context.getSession();
        var authSession = context.getAuthenticationSession();
        var client = authSession.getClient();

        // TODO take configuration from "opa-check-access-profile" -> "opa-client-access-policy-enforcer"
        //  session.clientPolicy().getClientProfiles(realm, false).getProfiles().get(0).getExecutors().get(0).getConfiguration()

        RealmResource resource = RealmResource.builder() //
                .id(client.getId()) //
                .name(client.getClientId()) //
                .type("client") //
                .path(realm.getName() + "/clients/" + client.getId()) //
                .build();

        AccessPolicyProvider accessPolicyProvider = session.getProvider(AccessPolicyProvider.class, OpaAccessPolicyProvider.ID);
        AccessDecisionContext decisionContext = new AccessDecisionContext(session, realm, client, user, resource, AccessDecisionContext.ACTION_CHECK_ACCESS, null);
        AccessDecision accessDecision = accessPolicyProvider.evaluate(decisionContext);

        if (accessDecision.isAllowed()) {
            context.success();
            return;
        }

        // deny access

        String error = Messages.ACCESS_DENIED;

        var loginForm = session.getProvider(LoginFormsProvider.class);
        loginForm.setError(error, user.getUsername());

        var event = context.getEvent();
        event.user(user);
        event.detail("username", user.getUsername());
        event.error(error);

        context.challenge(loginForm.createErrorPage(Response.Status.FORBIDDEN));

    }

    @Override
    public void processAction(RequiredActionContext context) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    @AutoService(RequiredActionFactory.class)
    public static class Factory implements RequiredActionFactory {

        private static final OpaCheckAccessRequiredActionProvider INSTANCE = new OpaCheckAccessRequiredActionProvider();

        @Override
        public String getId() {
            return OpaCheckAccessRequiredActionProvider.ID;
        }

        @Override
        public String getDisplayText() {
            return "OpenPolicyAgent: Check Access";
        }

        @Override
        public boolean isOneTimeAction() {
            return false;
        }

        @Override
        public RequiredActionProvider create(KeycloakSession session) {
            return INSTANCE;
        }

        @Override
        public void init(Config.Scope scope) {
            // NOOP
        }

        @Override
        public void postInit(KeycloakSessionFactory factory) {
            // NOOP
        }

        @Override
        public void close() {
            // NOOP
        }
    }
}
