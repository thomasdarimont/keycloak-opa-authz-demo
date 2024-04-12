package com.thomasdarimont.keycloak.opa.checkaccess;

import com.google.auto.service.AutoService;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecision;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecisionContext;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import com.thomasdarimont.keycloak.accessmgmt.RealmResource;
import com.thomasdarimont.keycloak.opa.config.AuthenticatorConfig;
import com.thomasdarimont.keycloak.opa.config.ConfigWrapper;
import com.thomasdarimont.keycloak.support.AuthenticatorUtils;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.messages.Messages;

import java.util.Collections;
import java.util.List;

/**
 * The OpaAuthenticator uses the Open Policy Agent to evaluate a configured auth policy to determine whether a user is allowed to access the desired client.
 */
@JBossLog
public class OpaCheckAccessAuthenticator implements Authenticator {

    public static final String PROVIDER_ID = "auth-opa-authz";

    public static final String OPA_ACTION_LOGIN = "login";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        var realm = context.getRealm();
        var user = context.getUser();
        var session = context.getSession();
        var authSession = context.getAuthenticationSession();
        var client = authSession.getClient();

        AccessPolicyProvider accessPolicyProvider = session.getProvider(AccessPolicyProvider.class, OpaAccessPolicyProvider.ID);
        ConfigWrapper authenticatorConfigWrapper = getAuthenticatorConfigWrapper(context);

        RealmResource resource = RealmResource.builder() //
                .id(client.getId()) //
                .name(client.getClientId()) //
                .type("client") //
                .path(realm.getName() + "/clients/" + client.getId()) //
                .build();

        AccessDecisionContext decisionContext = new AccessDecisionContext(session, realm, client, user, resource, AccessDecisionContext.ACTION_CHECK_ACCESS, authenticatorConfigWrapper);
        AccessDecision accessDecision = accessPolicyProvider.evaluate(decisionContext);

        if (accessDecision.isAllowed()) {
            context.getEvent().success();
            context.success();
            return;
        }

        // deny access

        if (AuthenticatorUtils.isGrantTypePasswordRequest(context.getHttpRequest())) {
            context.getEvent().error(Errors.ACCESS_DENIED);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), Errors.INVALID_REQUEST, "OPA: Authorization Failed");
            context.failure(AuthenticationFlowError.ACCESS_DENIED, challengeResponse);
            return;
        }

        var loginForm = session.getProvider(LoginFormsProvider.class);
        loginForm.setError(Messages.ACCESS_DENIED, user.getUsername());

        var event = context.getEvent();
        event.user(user);
        event.detail("username", user.getUsername());
        event.error(Errors.ACCESS_DENIED);

        context.failure(AuthenticationFlowError.ACCESS_DENIED, loginForm.createErrorPage(Response.Status.FORBIDDEN));
    }

    AuthenticatorConfig getAuthenticatorConfigWrapper(AuthenticationFlowContext context) {

        var authenticatorConfig = context.getAuthenticatorConfig();
        var alias = authenticatorConfig != null ? authenticatorConfig.getAlias() : null;
        var config = authenticatorConfig != null ? authenticatorConfig.getConfig() : null;

        return new AuthenticatorConfig(PROVIDER_ID, alias, config);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // NOOP
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    /**
     * Taken from org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator
     *
     * @param status
     * @param error
     * @param errorDescription
     * @return
     */
    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @AutoService(AuthenticatorFactory.class)
    public static class Factory implements AuthenticatorFactory {

        private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;
        public static final OpaCheckAccessAuthenticator INSTANCE = new OpaCheckAccessAuthenticator();

        static {
            var listBuilder = ProviderConfigurationBuilder.create(); //
            for (var option : OpaAccessPolicyProvider.Option.values()) {
                listBuilder.property() //
                        .name(option.getKey()) //
                        .type(option.getType()) //
                        .label(option.getLabel()) //
                        .helpText(option.getHelpText()) //
                        .defaultValue(option.getDefaultValue()) //
                        .add(); //
            }
            CONFIG_PROPERTIES = Collections.unmodifiableList(listBuilder.build());
        }

        public String getId() {
            return OpaCheckAccessAuthenticator.PROVIDER_ID;
        }

        @Override
        public String getDisplayType() {
            return "OPA Access Policy Authenticator";
        }

        @Override
        public Authenticator create(KeycloakSession session) {
            return INSTANCE;
        }

        @Override
        public String getReferenceCategory() {
            return "opa";
        }

        @Override
        public String getHelpText() {
            return "Controls access to clients based on an OPA policy.";
        }

        @Override
        public boolean isConfigurable() {
            return !CONFIG_PROPERTIES.isEmpty();
        }

        @Override
        public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
            return REQUIREMENT_CHOICES;
        }

        @Override
        public boolean isUserSetupAllowed() {
            return false;
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            return CONFIG_PROPERTIES;
        }

        @Override
        public void init(Config.Scope config) {
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