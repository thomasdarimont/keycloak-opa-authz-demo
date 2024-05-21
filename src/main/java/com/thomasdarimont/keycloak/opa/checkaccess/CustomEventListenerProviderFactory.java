package com.thomasdarimont.keycloak.opa.checkaccess;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import com.thomasdarimont.keycloak.accessmgmt.AccessPolicyProvider;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import java.util.Collections;
import java.util.List;

public class CustomEventListenerProviderFactory
        implements EventListenerProviderFactory {
    
    private final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    {
        var listBuilder = ProviderConfigurationBuilder.create();
        for (var option : OpaAccessPolicyProvider.Option.values()) {
            listBuilder.property()
                    .name(option.getKey())
                    .type(option.getType())
                    .label(option.getLabel())
                    .helpText(option.getHelpText())
                    .defaultValue(option.getDefaultValue())
                    .add();
        }
        CONFIG_PROPERTIES = Collections.unmodifiableList(listBuilder.build());
    }

    @Override
    public EventListenerProvider create(KeycloakSession keycloakSession) {
        return new CustomEventListenerProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "custom-event-listener";
    }

    
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
