package com.thomasdarimont.keycloak.opa.checkaccess;

import com.thomasdarimont.keycloak.accessmgmt.AccessDecision;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecisionContext;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import com.thomasdarimont.keycloak.opa.client.OpaClient;
import com.thomasdarimont.keycloak.opa.client.OpaPolicyQuery;
import com.thomasdarimont.keycloak.opa.client.OpaRequest;
import com.thomasdarimont.keycloak.opa.client.OpaRequestContext;
import com.thomasdarimont.keycloak.opa.client.OpaResource;
import com.thomasdarimont.keycloak.opa.client.OpaResponse;
import com.thomasdarimont.keycloak.opa.client.OpaSubject;
import com.thomasdarimont.keycloak.opa.config.ClientConfig;
import com.thomasdarimont.keycloak.opa.config.CompositeConfig;
import com.thomasdarimont.keycloak.opa.config.ConfigWrapper;
import com.thomasdarimont.keycloak.opa.config.MapConfig;
import com.thomasdarimont.keycloak.opa.config.RealmConfig;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriBuilder;
import lombok.Getter;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.utils.StringUtil;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class OpaAccessPolicyProvider implements AccessPolicyProvider {

    public static final String ID = "opa";

    public static final String ACTION_LOGIN = "login";

    public static final String ACTION_CHECK_ACCESS = "access";


    @Getter
    public enum Option {
        USE_REALM_ROLES("use-realm-roles", ProviderConfigProperty.BOOLEAN_TYPE, "Use realm roles", "If enabled, realm roles will be sent with OPA requests.", "true"), //

        USE_CLIENT_ROLES("use-client-roles", ProviderConfigProperty.BOOLEAN_TYPE, "Use client roles", "If enabled, client roles for the current client will be sent with OPA requests.", "true"), //

        USE_GROUPS("use-groups", ProviderConfigProperty.BOOLEAN_TYPE, "Use groups", "If enabled, group information will be sent with OPA requests.", "true"), //

        USER_ATTRIBUTES("user-attributes", ProviderConfigProperty.STRING_TYPE, "User Attributes", "Comma separated list of user attributes to send with OPA requests.", null), //

        CONTEXT_ATTRIBUTES("context-attributes", ProviderConfigProperty.STRING_TYPE, "Context Attributes", "Comma separated list of context attributes to send with OPA requests. Currently supported attributes: remoteAddress", null), //

        REALM_ATTRIBUTES("realm-attributes", ProviderConfigProperty.STRING_TYPE, "Realm Attributes", "Comma separated list of realm attributes to send with OPA requests.", null), //

        CLIENT_ATTRIBUTES("client-attributes", ProviderConfigProperty.STRING_TYPE, "Client Attributes", "Comma separated list of client attributes to send with OPA requests.", null), //

        REQUEST_HEADERS("request-headers", ProviderConfigProperty.STRING_TYPE, "Request Headers", "Comma separated list of request headers to send with OPA requests.", null), //

        URL("url", ProviderConfigProperty.STRING_TYPE, "URL", "URL of OPA Authz Server Resource", null), //

        POLICY_PATH("policy-path", ProviderConfigProperty.STRING_TYPE, "Policy Path", "Path of OPA policy relative to Authz Server URL", null), //
        ;

        private final String key;

        private final String type;

        private final String label;

        private final String helpText;

        private final String defaultValue;

        Option(String key, String type, String label, String helpText, String defaultValue) {
            this.key = key;
            this.type = type;
            this.label = label;
            this.helpText = helpText;
            this.defaultValue = defaultValue;
        }
    }

    private static final Pattern COMMA_PATTERN = Pattern.compile(",");

    private final Map<String, String> providerConfig;

    public OpaAccessPolicyProvider(Map<String, String> providerConfig) {
        this.providerConfig = providerConfig;
    }

    public AccessDecision evaluate(AccessDecisionContext context) {

        String action = ACTION_CHECK_ACCESS;

        ConfigWrapper config = getConfig(context);
        OpaSubject subject = createSubject(context.getUser(), context.getClient(), config);
        OpaResource resource = createResource(context.getRealm(), context.getClient(), config);
        OpaRequestContext requestContext = createRequestContext(context.getSession(), config);

        String policyUrl = createPolicyUrl(context.getRealm(), context.getClient(), action, config);

        OpaPolicyQuery accessRequest = createAccessRequest(subject, resource, requestContext, action);

        OpaClient opaClient = createOpaClient(context);

        OpaResponse policyResponse = opaClient.evaluatePolicy(policyUrl, new OpaRequest(accessRequest));

        return toAccessDecision(policyResponse);
    }

    private ConfigWrapper getConfig(AccessDecisionContext context) {
        if (context.getConfigOverride() == null) {
            return new MapConfig(providerConfig);
        }
        return new CompositeConfig(Arrays.asList(context.getConfigOverride(), new MapConfig(providerConfig)));
    }

    protected AccessDecision toAccessDecision(OpaResponse response) {
        return new AccessDecision(response.isAllowed(), response.getMetadata());
    }

    protected OpaPolicyQuery createAccessRequest(OpaSubject subject, OpaResource resource, OpaRequestContext requestContext, String action) {
        return OpaPolicyQuery.builder() //
                .subject(subject) //
                .resource(resource) //
                .context(requestContext) //
                .action(action) //
                .build();
    }

    protected OpaSubject createSubject(UserModel user, ClientModel client, ConfigWrapper config) {

        var subjectBuilder = OpaSubject.builder();
        subjectBuilder.id(user.getId());
        subjectBuilder.username(user.getUsername());
        if (config.getBoolean(Option.USE_REALM_ROLES.key, true)) {
            subjectBuilder.realmRoles(fetchRealmRoles(user));
        }
        if (config.getBoolean(Option.USE_CLIENT_ROLES.key, true)) {
            subjectBuilder.clientRoles(fetchClientRoles(user, client));
        }
        if (config.isConfigured(Option.USER_ATTRIBUTES.key, true)) {
            subjectBuilder.attributes(extractUserAttributes(user, config));
        }
        if (config.getBoolean(Option.USE_GROUPS.key, true)) {
            subjectBuilder.groups(fetchGroupNames(user));
        }
        return subjectBuilder.build();
    }

    protected OpaResource createResource(RealmModel realm, ClientModel client, ConfigWrapper config) {
        var resourceBuilder = OpaResource.builder();
        resourceBuilder.realm(realm.getName());
        resourceBuilder.clientId(client.getClientId());
        if (config.isConfigured(Option.REALM_ATTRIBUTES.key, false)) {
            resourceBuilder.realmAttributes(extractRealmAttributes(realm, config));
        }
        if (config.isConfigured(Option.CLIENT_ATTRIBUTES.key, false)) {
            resourceBuilder.clientAttributes(extractClientAttributes(client, config));
        }
        return resourceBuilder.build();
    }

    protected OpaClient createOpaClient(AccessDecisionContext context) {
        return new OpaClient(context.getSession());
    }

    protected String createPolicyUrl(RealmModel realm, ClientModel client, String action, ConfigWrapper config) {

        String opaUrl = config.getString(Option.URL.key);

        if (opaUrl == null) {
            throw new RuntimeException("missing opaUrl");
        }

        String policyPath = createPolicyPath(realm, client, action, config);

        return opaUrl + policyPath;
    }

    protected String createPolicyPath(RealmModel realm, ClientModel client, String action, ConfigWrapper config) {
        String policyPathTemplate = config.getString(Option.POLICY_PATH.key);
        Map<String, String> params = new HashMap<>();
        params.put("realm", realm.getName());
        params.put("action", action);
        params.put("client", client.getClientId());
        return UriBuilder.fromPath(policyPathTemplate).buildFromMap(params).toString();
    }

    protected OpaRequestContext createRequestContext(KeycloakSession session, ConfigWrapper config) {
        var builder = OpaRequestContext.builder();
        if (config.isConfigured(Option.CONTEXT_ATTRIBUTES.key, false)) {
            builder.attributes(extractContextAttributes(session, config));
        }
        if (config.isConfigured(Option.REQUEST_HEADERS.key, false)) {
            builder.headers(extractRequestHeaders(session, config));
        }
        return builder.build();
    }

    protected Map<String, Object> extractRequestHeaders(KeycloakSession session, ConfigWrapper config) {

        String headerNames = config.getValue(Option.REQUEST_HEADERS.key);
        if (headerNames == null || StringUtil.isBlank(headerNames)) {
            return null;
        }

        HttpHeaders requestHeaders = session.getContext().getRequestHeaders();
        Map<String, Object> headers = new HashMap<>();
        for (String header : COMMA_PATTERN.split(headerNames.trim())) {
            String value = requestHeaders.getHeaderString(header);
            headers.put(header, value);
        }

        if (headers.isEmpty()) {
            return null;
        }

        return headers;
    }

    protected Map<String, Object> extractContextAttributes(KeycloakSession session, ConfigWrapper config) {
        return extractAttributes(null, config, Option.CONTEXT_ATTRIBUTES.key, (source, attr) -> {
            Object value;
            switch (attr) {
                case "remoteAddress":
                    value = session.getContext().getConnection().getRemoteAddr();
                    break;
                case "protocol":
                    value = session.getContext().getAuthenticationSession().getProtocol();
                    break;
                case "grantType":
                    value = session.getContext().getHttpRequest().getDecodedFormParameters().getFirst("grant_type");
                    break;
                default:
                    value = null;
            }

            return value;
        }, u -> null);
    }

    protected <T> Map<String, Object> extractAttributes(T source, ConfigWrapper config, String attributesKey, BiFunction<T, String, Object> valueExtractor, Function<T, Map<String, Object>> defaultValuesExtractor) {

        if (config == null) {
            return defaultValuesExtractor.apply(source);
        }

        String attributeNames = config.getValue(attributesKey);
        if (attributeNames == null || StringUtil.isBlank(attributeNames)) {
            return defaultValuesExtractor.apply(source);
        }

        Map<String, Object> attributes = new HashMap<>();
        for (String attributeName : COMMA_PATTERN.split(attributeNames.trim())) {
            Object value = valueExtractor.apply(source, attributeName);
            attributes.put(attributeName, value);
        }

        return attributes;
    }

    protected Map<String, Object> extractUserAttributes(UserModel user, ConfigWrapper config) {

        return extractAttributes(user, config, Option.USER_ATTRIBUTES.key, (u, attr) -> {
            Object value;
            switch (attr) {
                // handle built-in attributes
                case "email":
                    value = user.getEmail();
                    break;
                case "emailVerified":
                    value = user.isEmailVerified();
                    break;
                case "createdTimestamp":
                    value = user.getCreatedTimestamp();
                    break;
                case "lastName":
                    value = user.getLastName();
                    break;
                case "firstName":
                    value = user.getFirstName();
                    break;
                case "federationLink":
                    value = user.getFederationLink();
                    break;
                case "serviceAccountLink":
                    value = user.getServiceAccountClientLink();
                    break;
                // handle generic attributes
                default:
                    value = user.getFirstAttribute(attr);
                    break;
            }
            return value;
        }, this::extractDefaultUserAttributes);
    }

    protected Map<String, Object> extractDefaultUserAttributes(UserModel user) {
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("email", user.getEmail());
        return userAttributes;
    }

    protected Map<String, Object> extractClientAttributes(ClientModel client, ConfigWrapper config) {
        ClientConfig clientConfig = new ClientConfig(client);
        return extractAttributes(client, config, Option.CLIENT_ATTRIBUTES.key, (c, attr) -> clientConfig.getValue(attr), c -> null);
    }

    protected Map<String, Object> extractRealmAttributes(RealmModel realm, ConfigWrapper config) {
        RealmConfig realmConfig = new RealmConfig(realm);
        return extractAttributes(realm, config, Option.REALM_ATTRIBUTES.key, (r, attr) -> realmConfig.getValue(attr), r -> null);
    }

    protected List<String> fetchGroupNames(UserModel user) {
        List<String> groupNames = user.getGroupsStream().map(GroupModel::getName).collect(Collectors.toList());
        return groupNames.isEmpty() ? null : groupNames;
    }

    protected List<String> fetchClientRoles(UserModel user, ClientModel client) {
        Stream<RoleModel> explicitClientRoles = RoleUtils.expandCompositeRolesStream(user.getClientRoleMappingsStream(client));
        Stream<RoleModel> implicitClientRoles = RoleUtils.expandCompositeRolesStream(user.getRealmRoleMappingsStream());
        return Stream.concat(explicitClientRoles, implicitClientRoles) //
                .filter(RoleModel::isClientRole) //
                .map(this::normalizeRoleName) //
                .collect(Collectors.toList());
    }

    protected List<String> fetchRealmRoles(UserModel user) {
        return RoleUtils.expandCompositeRolesStream(user.getRealmRoleMappingsStream()) //
                .filter(r -> !r.isClientRole()).map(this::normalizeRoleName) //
                .collect(Collectors.toList());
    }

    protected String normalizeRoleName(RoleModel role) {
        if (role.isClientRole()) {
            return ((ClientModel) role.getContainer()).getClientId() + ":" + role.getName();
        }
        return role.getName();
    }
}
