package it.profesia.wemodi.keymanager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;

@Component(
        name = "wemodi.PDND.keymanager",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)

public class PDNDConnectorConfiguration implements KeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {

        return PDNDKeyManagerImpl.class.getName();
    }

    @Override
    public String getJWTValidator() {

        // If you need to implement a custom JWT validation logic you need to implement
        // org.wso2.carbon.apimgt.impl.jwt.JWTValidator interface and instantiate it in here.
        return PDNDJWTValidatorImpl.class.getName();
    }

    /*
     *   Provides list of configurations need to create Oauth applications in Oauth server in Devportal
     *
     * */
    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();

       // todo add application configuration parameters that need create an OAuth application in the OAuth Server
        configurationDtoList.add(new ConfigurationDto("private_key", "Chiave privata", "file", "BEGIN PRIVATE KEY", null, true, false, Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto("client_id", "Client ID", "input", "Client ID", null, true, false, Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto("jwks_url", "URL JWKS", "input", "JWKS", null, true, false, Collections.emptyList(), false));

        return configurationDtoList;
    }


    /**
     * This method returns keymanager endpoint configurations.
     */
    @Override
    public List<ConfigurationDto> getEndpointConfigurations() {
        List<ConfigurationDto> configurationDtos = new ArrayList<>();
        /*configurationDtos.add(new ConfigurationDto("client_registration_endpoint", "Client Registration Endpoint",
                "input", String.format("E.g.,%s/client-registration/v0.17/register",
                APIConstants.DEFAULT_KEY_MANAGER_HOST), "", true, false, Collections.emptyList(), false));
        configurationDtos.add(new ConfigurationDto("introspection_endpoint", "Introspection Endpoint", "input",
                String.format("E.g., %s/oauth2/introspect", APIConstants.DEFAULT_KEY_MANAGER_HOST), "", true, false, Collections.emptyList(), false));*/
        configurationDtos.add(new ConfigurationDto("token_endpoint", "Token Endpoint", "input",
                String.format("E.g., %s/oauth2/token", PDNDConstants.DEFAULT_KEY_MANAGER_HOST), ""
                , true, false, Collections.emptyList(), false));
        configurationDtos.add(new ConfigurationDto("revoke_endpoint", "Revoke Endpoint", "input",
                String.format("E.g., %s/oauth2/revoke", PDNDConstants.DEFAULT_KEY_MANAGER_HOST), "", true, false,
                Collections.emptyList(), false));
        /*configurationDtos.add(new ConfigurationDto("userinfo_endpoint", "UserInfo Endpoint", "input",
                String.format("E.g., %s/oauth2/userinfo", APIConstants.DEFAULT_KEY_MANAGER_HOST), "", false, false,
                Collections.emptyList(), false));
        configurationDtos.add(new ConfigurationDto("authorize_endpoint", "Authorize Endpoint", "input",
                String.format("E.g., %s/oauth2/authorize",APIConstants.DEFAULT_KEY_MANAGER_HOST), "", false, false, Collections.emptyList(), false));
        configurationDtos.add(new ConfigurationDto("display_token_endpoint", "Display Token Endpoint", "input",
                String.format("E.g., %s/oauth2/token",APIConstants.DEFAULT_KEY_MANAGER_HOST), "", false, false, Collections.emptyList(), false));
        configurationDtos.add(new ConfigurationDto("display_revoke_endpoint", "Display Revoke Endpoint", "input",
                String.format("E.g., %s/oauth2/authorize", APIConstants.DEFAULT_KEY_MANAGER_HOST), "", false, false,
                Collections.emptyList(), false));*/
        return configurationDtos;
    }

    @Override
    public String getType() {

        return PDNDConstants.TYPE;
    }

    @Override
    public String getDisplayName() {

        return PDNDConstants.DISPLAY_NAME;
    }

    /*
     *  Provides list of Configurations that need to show in Admin portal in order to connect with KeyManager
     *
     * */
    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<ConfigurationDto>();

        // todo add connection parameters that need to connect to the Custom KeymManager here
        return configurationDtoList;
    }
/*
    @Override
    public String getDefaultScopesClaim() {

        return APIConstants.JwtTokenConstants.SCOPE;
    }

    @Override
    public String getDefaultConsumerKeyClaim() {

        return APIConstants.JwtTokenConstants.AUTHORIZED_PARTY;
    }
*/
}
