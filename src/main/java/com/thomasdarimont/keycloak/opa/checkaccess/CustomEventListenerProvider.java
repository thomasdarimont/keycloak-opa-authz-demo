package com.thomasdarimont.keycloak.opa.checkaccess;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import com.thomasdarimont.keycloak.accessmgmt.RealmResource;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecision;
import com.thomasdarimont.keycloak.accessmgmt.AccessDecisionContext;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import com.thomasdarimont.keycloak.opa.config.MapConfig;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.idm.ClientPolicyConditionConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;
import org.keycloak.services.ForbiddenException;
import java.util.Map;
import java.util.Collections;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.WebApplicationException;
import com.google.auto.service.AutoService;
import com.thomasdarimont.keycloak.opa.config.AuthenticatorConfig;
import com.thomasdarimont.keycloak.opa.config.ConfigWrapper;
import com.thomasdarimont.keycloak.support.AuthenticatorUtils;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.services.messages.Messages;
import org.keycloak.events.EventBuilder;

public class CustomEventListenerProvider
        implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(CustomEventListenerProvider.class);

    public static final String PROVIDER_ID = "custom-event-listener";
    private final KeycloakSession session;
    private final RealmProvider model;
    private ClientPolicyConditionConfigurationRepresentation config;

    public CustomEventListenerProvider(KeycloakSession session) {
        this.session = session;
        this.model = session.realms();
    }
    
    
    public void setupConfiguration(ClientPolicyConditionConfigurationRepresentation configuration) {
        this.config = configuration;
    }
    
    
    public void onEvent(Event event) {
        var sessionContext = session.getContext();
       
        log.debugf("New %s Event", event.getType());
        log.debugf("onEvent-> %s", toString(event));
        try{
            if (EventType.PERMISSION_TOKEN.equals(event.getType())) {
                event.getDetails().forEach((key, value) -> log.debugf("%s : %s", key, value));
                log.debugf("OPA: PERMISSION_TOKEN");
                RealmModel realm = this.model.getRealm(event.getRealmId());
                UserModel user = this.session.users().getUserById(realm, event.getUserId());
                sendUserData(user);
                checkAccess(createAccessDecisionContext(user));
            }
                
        } catch (ClientPolicyException e){
            log.debugf("Access not authorized...");
            RealmModel realm = this.model.getRealm(event.getRealmId());
            UserModel user = this.session.users().getUserById(realm, event.getUserId());
            EventBuilder eventBuilder = new EventBuilder(realm, session);
            eventBuilder.user(user)
                        .detail("error", "permission_token_error")
                        .event(EventType.PERMISSION_TOKEN_ERROR)
                        .detail("realmId", realm.getId())
                        .detail("userId", user.getId())
                        .detail("username", user.getUsername())
                        .error("Access denied");
            
            
            response();
            System.out.println("Closing...");
            System.exit(1);
        }

    }

    public Response response(){
        return Response.status(400).build();
    }

    public void checkAccess(AccessDecisionContext decisionContext) throws ClientPolicyException {

        AccessPolicyProvider accessPolicyProvider = session.getProvider(AccessPolicyProvider.class, OpaAccessPolicyProvider.ID);
        AccessDecision accessDecision = accessPolicyProvider.evaluate(decisionContext);

        if (!accessDecision.isAllowed()) {
            throw new ClientPolicyException(Errors.ACCESS_DENIED, "OPA Access Check failed.", Response.Status.FORBIDDEN);
        }
    }

    private AccessDecisionContext createAccessDecisionContext(UserModel user) {
        var context = session.getContext();
        var realm = context.getRealm();
        var client = context.getClient();
        var configMap = config != null ? config.getConfigAsMap() : Collections.emptyMap();
        var configWrapper = new MapConfig((Map<String, String>) (Object) configMap);
        var resource = RealmResource.builder() //
                .id(client.getId()) //
                .name(client.getClientId()) //
                .type("client") //
                .path(realm.getName() + "/clients/" + client.getId()) //
                .build();

        return new AccessDecisionContext(session, realm, client, user, resource, AccessDecisionContext.ACTION_CHECK_ACCESS, configWrapper);
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {
        log.debug("onEvent(AdminEvent)");
        log.debugf("Resource path: %s", adminEvent.getResourcePath());
        log.debugf("Resource type: %s", adminEvent.getResourceType());
        log.debugf("Operation type: %s", adminEvent.getOperationType());
        log.debugf("AdminEvent.toString(): %s", toString(adminEvent));
        if (ResourceType.USER.equals(adminEvent.getResourceType())
                && OperationType.CREATE.equals(adminEvent.getOperationType())) {
            RealmModel realm = this.model.getRealm(adminEvent.getRealmId());
            UserModel user = this.session.users().getUserById(realm, adminEvent.getResourcePath().substring(6));

            sendUserData(user);
        }
    }

    private void sendUserData(UserModel user) {
        String data =
                "{\"id\": " + user.getId() + "\"," +
                        "{\"email\": " + user.getEmail() + "\"," +
                        "\"userName\":\"" + user.getUsername() + "\"," +
                        "\"firstName\":\"" + user.getFirstName() + "\"," +
                        "\"lastName\":\"" + user.getLastName() + "\"," +
                        "}";
        try {
            log.debugf("User data: %s", data);
        } catch (Exception e) {
            log.errorf("Failed to send user data: %s", e);
        }
    }


    @Override
    public void close() {
    }

    private String toString(Event event) {

        StringBuilder sb = new StringBuilder();
        sb.append("type=");
        sb.append(event.getType());
        sb.append(", realmId=");
        sb.append(event.getRealmId());
        sb.append(", clientId=");
        sb.append(event.getClientId());
        sb.append(", userId=");
        sb.append(event.getUserId());
        sb.append(", ipAddress=");
        sb.append(event.getIpAddress());
        if (event.getError() != null) {
            sb.append(", error=");
            sb.append(event.getError());
        }


        if (event.getDetails() != null) {
            for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
                sb.append(", ");
                sb.append(e.getKey());
                if (e.getValue() == null || e.getValue().indexOf(' ') == -1) {
                    sb.append("=");
                    sb.append(e.getValue());
                } else {
                    sb.append("='");
                    sb.append(e.getValue());
                    sb.append("'");
                }
            }
        }

        return sb.toString();
    }

    private String toString(AdminEvent event) {

        RealmModel realm = this.model.getRealm(event.getRealmId());

        UserModel newRegisteredUser =
                this.session.users().getUserById(realm, event.getAuthDetails().getUserId());


        StringBuilder sb = new StringBuilder();
        sb.append("operationType=");
        sb.append(event.getOperationType());
        sb.append(", realmId=");
        sb.append(event.getAuthDetails().getRealmId());
        sb.append(", clientId=");
        sb.append(event.getAuthDetails().getClientId());
        sb.append(", userId=");
        sb.append(event.getAuthDetails().getUserId());

        if (newRegisteredUser != null) {
            sb.append(", email=");
            sb.append(newRegisteredUser.getEmail());
            sb.append(", getUsername=");
            sb.append(newRegisteredUser.getUsername());
            sb.append(", getFirstName=");
            sb.append(newRegisteredUser.getFirstName());
            sb.append(", getLastName=");
            sb.append(newRegisteredUser.getLastName());
        }
        sb.append(", ipAddress=");
        sb.append(event.getAuthDetails().getIpAddress());
        sb.append(", resourcePath=");
        sb.append(event.getResourcePath());
        if (event.getError() != null) {
            sb.append(", error=");
            sb.append(event.getError());
        }

        return sb.toString();
    }
}
