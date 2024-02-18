package com.thomasdarimont.keycloak.opa.checkaccess;

import com.google.auto.service.AutoService;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecision;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecisionContext;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import com.thomasdarimont.keycloak.opa.config.MapConfig;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * ClientPolicyExecutorProvider to enforce OPA Client Access Checks for clients using grant_type=password and grant_type=client_credentials.
 */
@JBossLog
public class OpaCheckAccessClientPolicyEnforcer implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    public static final String PROVIDER_ID = "opa-client-access-policy-enforcer";

    private final KeycloakSession session;

    private ClientPolicyExecutorConfigurationRepresentation config;

    public OpaCheckAccessClientPolicyEnforcer(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return PROVIDER_ID;
    }

    @Override
    public void setupConfiguration(ClientPolicyExecutorConfigurationRepresentation configuration) {
        this.config = configuration;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {

        ClientPolicyEvent event = context.getEvent();
        switch (event) {
            case RESOURCE_OWNER_PASSWORD_CREDENTIALS_RESPONSE: {
                log.debugf("OPA: Check Access for grant_type: password");
                checkAccess(createAccessDecisionContextForDirectAccessGrant());
            }
            break;

            case SERVICE_ACCOUNT_TOKEN_REQUEST: {
                log.debugf("OPA: Check Access for grant_type: client_credentials");
                checkAccess(createAccessDecisionContextForClientCredentialsGrant());
            }
            break;
        }
    }

    public void checkAccess(AccessDecisionContext decisionContext) throws ClientPolicyException {

        AccessPolicyProvider accessPolicyProvider = session.getProvider(AccessPolicyProvider.class, OpaAccessPolicyProvider.ID);
        AccessDecision accessDecision = accessPolicyProvider.evaluate(decisionContext);

        if (!accessDecision.isAllowed()) {
            throw new ClientPolicyException(Errors.ACCESS_DENIED, "OPA Access Check failed.");
        }
    }

    private AccessDecisionContext createAccessDecisionContextForDirectAccessGrant() {
        var context = session.getContext();
        var realm = context.getRealm();
        var client = context.getClient();
        var authSession = context.getAuthenticationSession();
        var user = authSession.getAuthenticatedUser();
        var configWrapper = new MapConfig((Map<String, String>) (Object) config.getConfigAsMap());
        return new AccessDecisionContext(session, realm, client, user, configWrapper);
    }

    private AccessDecisionContext createAccessDecisionContextForClientCredentialsGrant() {
        var context = session.getContext();
        var realm = context.getRealm();
        var client = context.getClient();
        var serviceAccountUser = session.users().getServiceAccount(client);
        var configWrapper = new MapConfig((Map<String, String>) (Object) config.getConfigAsMap());
        return new AccessDecisionContext(session, realm, client, serviceAccountUser, configWrapper);
    }

    @AutoService(ClientPolicyExecutorProviderFactory.class)
    public static class Factory implements ClientPolicyExecutorProviderFactory {

        private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

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

        @Override
        public ClientPolicyExecutorProvider create(KeycloakSession session) {
            return new OpaCheckAccessClientPolicyEnforcer(session);
        }

        @Override
        public void init(Config.Scope config) {
        }

        @Override
        public void postInit(KeycloakSessionFactory factory) {
        }

        @Override
        public void close() {
        }

        @Override
        public String getId() {
            return PROVIDER_ID;
        }

        @Override
        public String getHelpText() {
            return "Ensure access is allowed for given target client.";
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            return CONFIG_PROPERTIES;
        }

    }

}
