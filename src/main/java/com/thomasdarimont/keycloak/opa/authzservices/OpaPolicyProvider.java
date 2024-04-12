package com.thomasdarimont.keycloak.opa.authzservices;

import com.google.auto.service.AutoService;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecision;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecisionContext;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import com.thomasdarimont.keycloak.accessmgmt.RealmResource;
import com.thomasdarimont.keycloak.opa.checkaccess.OpaAccessPolicyProvider;
import com.thomasdarimont.keycloak.opa.config.MapConfig;
import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.DefaultEvaluation;
import org.keycloak.authorization.policy.evaluation.Evaluation;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class OpaPolicyProvider implements PolicyProvider {

    private final AuthorizationProvider authorizationProvider;

    public OpaPolicyProvider(AuthorizationProvider authorizationProvider) {
        this.authorizationProvider = authorizationProvider;
    }

    @Override
    public void evaluate(Evaluation evaluation) {

        KeycloakSession session = authorizationProvider.getKeycloakSession();

        AccessDecisionContext accessDecisionContext = createAccessDecisionContext(session, evaluation);

        AccessPolicyProvider accessPolicyProvider = session.getProvider(AccessPolicyProvider.class, OpaAccessPolicyProvider.ID);
        AccessDecision accessDecision = accessPolicyProvider.evaluate(accessDecisionContext);

        if (accessDecision.isAllowed()) {
            evaluation.grant();
        } else {
            evaluation.deny();
        }

    }

    private AccessDecisionContext createAccessDecisionContext(KeycloakSession session, Evaluation evaluation) {

        RealmModel realm = authorizationProvider.getRealm();
        Policy policy = evaluation.getPolicy();
        ClientModel client = realm.getClientByClientId(policy.getResourceServer().getClientId());
        if (client == null) {
            client = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        }
        var user = session.users().getUserById(realm, evaluation.getContext().getIdentity().getId());

        Map<String, String> config = new HashMap<>(policy.getConfig());
        config.put(OpaAccessPolicyProvider.Option.USE_GROUPS.getKey(),"true");
        var configWrapper = new MapConfig(config);

        ResourcePermission permission = evaluation.getPermission();

        Resource permissionResource = permission.getResource();

        String resourceName = evaluation.getPermission().getResource().getName();
        String resourceId = resourceName.substring(resourceName.lastIndexOf('.') + 1);
        String resourcePath = "";

        // TODO find a better way to determine the set of currently requested scopes?
        // Set<String> scopes = permissionResource.getScopes().stream().map(Scope::getName).collect(Collectors.toSet());
        Set<String> scopes = ((DefaultEvaluation) evaluation).getParentPolicy().getScopes().stream().map(Scope::getName).collect(Collectors.toSet());

        switch (permissionResource.getType()) {
            case "Group": {
                GroupModel group = session.groups().getGroupById(realm, resourceId);
                resourceName = group.getName();
                resourcePath = KeycloakModelUtils.buildGroupPath(group);
            }
            break;
            default:
                break;
        }

        RealmResource realmResource = RealmResource.builder() //
                .id(resourceId) //
                .name(resourceName) //
                .type(permissionResource.getType()) //
                .path(resourcePath) //
                .scopes(scopes) //
                .build();

        return new AccessDecisionContext(session, realm, client, user, realmResource, AccessDecisionContext.ACTION_MANAGE, configWrapper);
    }

    @Override
    public void close() {

    }

    @AutoService(PolicyProviderFactory.class)
    public static class Factory implements PolicyProviderFactory<OpaPolicyRepresentation> {

        @Override
        public PolicyProvider create(AuthorizationProvider authorizationProvider) {
            return new OpaPolicyProvider(authorizationProvider);
        }

        @Override
        public PolicyProvider create(KeycloakSession keycloakSession) {
            return null;
        }

        @Override
        public Class<OpaPolicyRepresentation> getRepresentationType() {
            return OpaPolicyRepresentation.class;
        }

        @Override
        public OpaPolicyRepresentation toRepresentation(Policy policy, AuthorizationProvider authorization) {
            return new OpaPolicyRepresentation();
        }

        @Override
        public void init(Config.Scope scope) {
            // called during startup
        }

        @Override
        public void postInit(KeycloakSessionFactory factory) {
            // called during startup, after init
        }

        @Override
        public void close() {
            // called on shutdown
        }

        @Override
        public String getId() {
            return "opa-policy-provider";
        }

        @Override
        public String getName() {
            return "Open Policy Agent";
        }

        @Override
        public String getGroup() {
            return null;
        }
    }

}
