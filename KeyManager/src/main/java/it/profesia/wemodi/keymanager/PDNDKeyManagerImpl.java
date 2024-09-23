package it.profesia.wemodi.keymanager;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.ExceptionCodes;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.dto.RevokeTokenInfoDTO;
import org.wso2.carbon.apimgt.impl.dto.ScopeDTO;
import org.wso2.carbon.apimgt.impl.dto.UserInfoDTO;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.carbon.apimgt.impl.kmclient.KMClientErrorDecoder;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import org.wso2.carbon.apimgt.impl.kmclient.model.AuthClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.Claim;
import org.wso2.carbon.apimgt.impl.kmclient.model.ClaimsList;
import org.wso2.carbon.apimgt.impl.kmclient.model.ClientInfo;
import org.wso2.carbon.apimgt.impl.kmclient.model.DCRClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectInfo;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectionClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.RevokeClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.ScopeClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.TenantHeaderInterceptor;
import org.wso2.carbon.apimgt.impl.kmclient.model.TokenInfo;
import org.wso2.carbon.apimgt.impl.kmclient.model.UserClient;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import com.google.gson.Gson;
import feign.Feign;
import feign.Response;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;

/**
 * Implementazione dell'Authorization Server PDND.
 */
public class PDNDKeyManagerImpl extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(PDNDKeyManagerImpl.class);
    private static final String GRANT_TYPE_VALUE = "client_credentials";

    private DCRClient dcrClient;
    private IntrospectionClient introspectionClient;
    private AuthClient authClient;
    private ScopeClient scopeClient;
    private UserClient userClient;
    private RevokeClient revokeClient;

    /**
     * Serve solo per la fase di test in modo da fare eseguire codice specifico per weModI.
     */
    private final static boolean IS_WEMODI = false;

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        /**
         * La generazione delle chiavi Oauth deve essere fatta dalla console weModI per essere associate
         *   al Client Id rilasciato da PDND
         */
        throw new APIManagementException("Non è permesso creare Oauth application per PDND, occorre utilizzare la console weModI.");
    }

    /**
     * Construct ClientInfo object for application create request
     *
     * @param info            The OAuthApplicationInfo object
     * @param oauthClientName The name of the OAuth application to be created
     * @param isUpdate        To determine whether the ClientInfo object is related to application update call
     * @return constructed ClientInfo object
     * @throws JSONException          for errors in parsing the OAuthApplicationInfo json string
     * @throws APIManagementException if an error occurs while constructing the ClientInfo object
     */
    private ClientInfo createClientInfo(OAuthApplicationInfo info, String oauthClientName, boolean isUpdate)
            throws JSONException, APIManagementException {

        ClientInfo clientInfo = new ClientInfo();
        JSONObject infoJson = new JSONObject(info.getJsonString());
        String applicationOwner = (String) info.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);
        if (infoJson.has(ApplicationConstants.OAUTH_CLIENT_GRANT)) {
            // this is done as there are instances where the grant string begins with a comma character.
            String grantString = infoJson.getString(ApplicationConstants.OAUTH_CLIENT_GRANT);
            if (grantString.startsWith(",")) {
                grantString = grantString.substring(1);
            }
            String[] grantTypes = grantString.split(",");
            clientInfo.setGrantTypes(Arrays.asList(grantTypes));
        }
        if (StringUtils.isNotEmpty(info.getCallBackURL())) {
            String callBackURL = info.getCallBackURL();
            String[] callbackURLs = callBackURL.trim().split("\\s*,\\s*");
            clientInfo.setRedirectUris(Arrays.asList(callbackURLs));
        }

        clientInfo.setClientName(oauthClientName);

        //todo: run tests by commenting the type
        if (APIConstants.JWT.equals(info.getTokenType())) {
            clientInfo.setTokenType(info.getTokenType());
        } else {
            clientInfo.setTokenType(APIConstants.TOKEN_TYPE_DEFAULT);
        }

        // Use a generated user as the app owner for cross tenant subscription scenarios, to avoid the tenant admin
        // being exposed in the JWT token.
        if (APIUtil.isCrossTenantSubscriptionsEnabled()
                && !tenantDomain.equals(MultitenantUtils.getTenantDomain(applicationOwner))) {
            clientInfo.setApplication_owner(APIUtil.retrieveDefaultReservedUsername());
        } else {
            clientInfo.setApplication_owner(MultitenantUtils.getTenantAwareUsername(applicationOwner));
        }
        if (StringUtils.isNotEmpty(info.getClientId())) {
            if (isUpdate) {
                clientInfo.setClientId(info.getClientId());
            } else {
                clientInfo.setPresetClientId(info.getClientId());
            }
        }
        if (StringUtils.isNotEmpty(info.getClientSecret())) {
            if (isUpdate) {
                clientInfo.setClientId(info.getClientSecret());
            } else {
                clientInfo.setPresetClientSecret(info.getClientSecret());
            }
        }
        Object parameter = info.getParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES);
        Map<String, Object> additionalProperties = new HashMap<>();
        if (parameter instanceof String) {
            additionalProperties = new Gson().fromJson((String) parameter, Map.class);
        }
        if (additionalProperties.containsKey(APIConstants.KeyManager.APPLICATION_ACCESS_TOKEN_EXPIRY_TIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(APIConstants.KeyManager.APPLICATION_ACCESS_TOKEN_EXPIRY_TIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        if (expiry < 0) {
                            throw new APIManagementException("Invalid application access token expiry time given for "
                                    + oauthClientName, ExceptionCodes.INVALID_APPLICATION_PROPERTIES);
                        }
                        clientInfo.setApplicationAccessTokenLifeTime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }
        if (additionalProperties.containsKey(APIConstants.KeyManager.USER_ACCESS_TOKEN_EXPIRY_TIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(APIConstants.KeyManager.USER_ACCESS_TOKEN_EXPIRY_TIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        if (expiry < 0) {
                            throw new APIManagementException("Invalid user access token expiry time given for "
                                    + oauthClientName, ExceptionCodes.INVALID_APPLICATION_PROPERTIES);
                        }
                        clientInfo.setUserAccessTokenLifeTime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }
        if (additionalProperties.containsKey(APIConstants.KeyManager.REFRESH_TOKEN_EXPIRY_TIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(APIConstants.KeyManager.REFRESH_TOKEN_EXPIRY_TIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        clientInfo.setRefreshTokenLifeTime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }
        if (additionalProperties.containsKey(APIConstants.KeyManager.ID_TOKEN_EXPIRY_TIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(APIConstants.KeyManager.ID_TOKEN_EXPIRY_TIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        clientInfo.setIdTokenLifeTime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        if (additionalProperties.containsKey(APIConstants.KeyManager.PKCE_MANDATORY)) {
            Object pkceMandatoryValue =
                    additionalProperties.get(APIConstants.KeyManager.PKCE_MANDATORY);
            if (pkceMandatoryValue instanceof String) {
                if (!APIConstants.KeyManager.PKCE_MANDATORY.equals(pkceMandatoryValue)) {
                    try {
                        Boolean pkceMandatory = Boolean.parseBoolean((String) pkceMandatoryValue);
                        clientInfo.setPkceMandatory(pkceMandatory);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        if (additionalProperties.containsKey(APIConstants.KeyManager.PKCE_SUPPORT_PLAIN)) {
            Object pkceSupportPlainValue =
                    additionalProperties.get(APIConstants.KeyManager.PKCE_SUPPORT_PLAIN);
            if (pkceSupportPlainValue instanceof String) {
                if (!APIConstants.KeyManager.PKCE_SUPPORT_PLAIN.equals(pkceSupportPlainValue)) {
                    try {
                        Boolean pkceSupportPlain = Boolean.parseBoolean((String) pkceSupportPlainValue);
                        clientInfo.setPkceSupportPlain(pkceSupportPlain);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        if (additionalProperties.containsKey(APIConstants.KeyManager.BYPASS_CLIENT_CREDENTIALS)) {
            Object bypassClientCredentialsValue =
                    additionalProperties.get(APIConstants.KeyManager.BYPASS_CLIENT_CREDENTIALS);
            if (bypassClientCredentialsValue instanceof String) {
                if (!APIConstants.KeyManager.BYPASS_CLIENT_CREDENTIALS.equals(bypassClientCredentialsValue)) {
                    try {
                        Boolean bypassClientCredentials = Boolean.parseBoolean((String) bypassClientCredentialsValue);
                        clientInfo.setBypassClientCredentials(bypassClientCredentials);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        // Set the display name of the application. This name would appear in the consent page of the app.
        clientInfo.setApplicationDisplayName(info.getClientName());

        return clientInfo;
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest appInfoDTO) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = appInfoDTO.getOAuthApplicationInfo();

        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);
        String applicationName = oAuthApplicationInfo.getClientName();
        String oauthClientName = oAuthApplicationInfo.getApplicationUUID();
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);

        // First we attempt to get the tenant domain from the userID and if it is not possible, we fetch it
        // from the ThreadLocalCarbonContext

        if (StringUtils.isNotEmpty(applicationName) && StringUtils.isNotEmpty(keyType)) {
            // Replace the domain name separator with an underscore for secondary user stores
            String domain = UserCoreUtil.extractDomainFromName(userId);
            if (domain != null && !domain.isEmpty() && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domain)) {
                userId = userId.replace(UserCoreConstants.DOMAIN_SEPARATOR, "_");
            }
            // Construct the application name subsequent to replacing email domain separator
            oauthClientName = String.format("%s_%s_%s", APIUtil.replaceEmailDomain(MultitenantUtils.
                    getTenantAwareUsername(userId)), oauthClientName, keyType);
        } else {
            throw new APIManagementException("Missing required information for OAuth application update.");
        }

        log.debug("Updating OAuth Client with ID : " + oAuthApplicationInfo.getClientId());
        if (log.isDebugEnabled() && oAuthApplicationInfo.getCallBackURL() != null) {
            log.debug("CallBackURL : " + oAuthApplicationInfo.getCallBackURL());
        }
        if (log.isDebugEnabled() && applicationName != null) {
            log.debug("Client Name : " + oauthClientName);
        }

        ClientInfo request = createClientInfo(oAuthApplicationInfo, oauthClientName, true);
        ClientInfo createdClient;
        try {
            createdClient = dcrClient.updateApplication(Base64.getUrlEncoder().encodeToString(
                    oAuthApplicationInfo.getClientId().getBytes(StandardCharsets.UTF_8)), request);
            return buildDTOFromClientInfo(createdClient, new OAuthApplicationInfo());
        } catch (KeyManagerClientException e) {
            handleException("Error occurred while updating OAuth Client : ", e);
            return null;
        }
    }

    @Override
    public OAuthApplicationInfo updateApplicationOwner(OAuthAppRequest appInfoDTO, String owner)
            throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = appInfoDTO.getOAuthApplicationInfo();
        log.debug("Updating Application Owner : " + oAuthApplicationInfo.getClientId());

        ClientInfo updatedClient;
        try {
            updatedClient = dcrClient.updateApplicationOwner(owner, Base64.getUrlEncoder().encodeToString(
                    oAuthApplicationInfo.getClientId().getBytes(StandardCharsets.UTF_8)));
            return buildDTOFromClientInfo(updatedClient, new OAuthApplicationInfo());
        } catch (KeyManagerClientException e) {
            handleException("Error occurred while updating OAuth Client : ", e);
            return null;
        }
    }

    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Trying to delete OAuth application for consumer key :" + consumerKey);
        }

        try {
            dcrClient.deleteApplication(Base64.getUrlEncoder().encodeToString(
                    consumerKey.getBytes(StandardCharsets.UTF_8)));
        } catch (KeyManagerClientException e) {
            handleException("Cannot remove service provider for the given consumer key : " + consumerKey, e);
        }
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Trying to retrieve OAuth application for consumer key :" + consumerKey);
        }
log.error("--------------------------------------------------------------- retrieveApplication");
log.error("retrieveApplication\n\tRecupera le informazioni della OAuth application a partire dal consumerKey: " + consumerKey);

		if (IS_WEMODI) {
			OAuthApplicationInfo oauthApplicationInfo = new OAuthApplicationInfo();
			oauthApplicationInfo.setApplicationUUID("f8da6847-481e-4c5a-ad9e-75180ac36e0e");
			oauthApplicationInfo.setClientId("dummy");
			oauthApplicationInfo.setClientName("YMCA");
			oauthApplicationInfo.setIsSaasApplication(false);

			return oauthApplicationInfo;
		}

        try {
            ClientInfo clientInfo = dcrClient.getApplication(Base64.getUrlEncoder().encodeToString(
                    consumerKey.getBytes(StandardCharsets.UTF_8)));
            return buildDTOFromClientInfo(clientInfo, new OAuthApplicationInfo());
        } catch (KeyManagerClientException e) {
            if (e.getStatusCode() == 404) {
                return null;
            }
            handleException("Cannot retrieve service provider for the given consumer key : " + consumerKey, e);
            return null;
        }
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {

        AccessTokenInfo tokenInfo;

        if (tokenRequest == null) {
            log.warn("No information available to generate Token.");
            return null;
        }

        //We do not revoke the previously obtained token anymore since we do not possess the access token.

        // When validity time set to a negative value, a token is considered never to expire.
        if (tokenRequest.getValidityPeriod() == OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
            // Setting a different -ve value if the set value is -1 (-1 will be ignored by TokenValidator)
            tokenRequest.setValidityPeriod(-2L);
        }

        //Generate New Access Token
        String scopes = String.join(" ", tokenRequest.getScope());
        TokenInfo tokenResponse;

        try {
            String credentials = tokenRequest.getClientId() + ':' + tokenRequest.getClientSecret();
            String authToken = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            if (APIConstants.OAuthConstants.TOKEN_EXCHANGE.equals(tokenRequest.getGrantType())) {
                tokenResponse = authClient.generate(tokenRequest.getClientId(), tokenRequest.getClientSecret(),
                        tokenRequest.getGrantType(), scopes, (String) tokenRequest.getRequestParam(APIConstants
                                .OAuthConstants.SUBJECT_TOKEN), APIConstants.OAuthConstants.JWT_TOKEN_TYPE);
            } else {
                tokenResponse = authClient.generate(authToken, GRANT_TYPE_VALUE, scopes);
            }

        } catch (KeyManagerClientException e) {
            throw new APIManagementException("Error occurred while calling token endpoint - " + e.getReason(), e);
        }

        tokenInfo = new AccessTokenInfo();
        if (StringUtils.isNotEmpty(tokenResponse.getScope())) {
            tokenInfo.setScope(tokenResponse.getScope().split(" "));
        } else {
            tokenInfo.setScope(new String[0]);
        }
        tokenInfo.setAccessToken(tokenResponse.getToken());
        tokenInfo.setValidityPeriod(tokenResponse.getExpiry());

        return tokenInfo;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest tokenRequest) throws APIManagementException {

        ClientInfo updatedClient;
        String encodedClientId =
                Base64.getUrlEncoder().encodeToString(tokenRequest.getClientId().getBytes(StandardCharsets.UTF_8));
        try {
            updatedClient = dcrClient.updateApplicationSecret(encodedClientId);
            return updatedClient.getClientSecret();

        } catch (KeyManagerClientException e) {
            handleException("Error while generating new consumer secret", e);
        }
        return null;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        try {
            IntrospectInfo introspectInfo = introspectionClient.introspect(accessToken);
            tokenInfo.setAccessToken(accessToken);
            boolean isActive = introspectInfo.isActive();
            if (!isActive) {
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                return tokenInfo;
            }
            tokenInfo.setTokenValid(true);
            if (introspectInfo.getIat() > 0 && introspectInfo.getExpiry() > 0) {
                if (introspectInfo.getExpiry() != Long.MAX_VALUE) {
                    long validityPeriod = introspectInfo.getExpiry() - introspectInfo.getIat();
                    tokenInfo.setValidityPeriod(validityPeriod * 1000L);
                } else {
                    tokenInfo.setValidityPeriod(Long.MAX_VALUE);
                }
                tokenInfo.setIssuedTime(introspectInfo.getIat() * 1000L);
            }
            if (StringUtils.isNotEmpty(introspectInfo.getScope())) {
                String[] scopes = introspectInfo.getScope().split(" ");
                tokenInfo.setScope(scopes);
            }
            tokenInfo.setConsumerKey(introspectInfo.getClientId());
            String username = introspectInfo.getUsername();
            if (!StringUtils.isEmpty(username)) {
                tokenInfo.setEndUserName(username);
            }

            String authorizedUserType = introspectInfo.getAut();
            if (!StringUtils.isEmpty(authorizedUserType) && StringUtils.equalsIgnoreCase(authorizedUserType,
                    APIConstants.ACCESS_TOKEN_USER_TYPE_APPLICATION)) {
                tokenInfo.setApplicationToken(true);
            }
            return tokenInfo;
        } catch (KeyManagerClientException e) {
            throw new APIManagementException("Error occurred in token introspection!", e);
        }
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
log.error("--------------------------------------------------------------- getKeyManagerConfiguration");
log.error("getKeyManagerConfiguration\n\tViene richiesta la configurazione del Key Manager.");

        return configuration;
    }

    /**
     * This method will create a new record at CLIENT_INFO table by given OauthAppRequest.
     *
     * @param appInfoRequest oAuth application properties will contain in this object
     * @return OAuthApplicationInfo with created oAuth application details.
     * @throws org.wso2.carbon.apimgt.api.APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest)
            throws APIManagementException {
log.error("--------------------------------------------------------------- mapOAuthApplication");
log.error("mapOAuthApplication\n\tIl metodo viene invocato quando venogno forniti Client Id (e secret) di service providers esterni.");
        //initiate OAuthApplicationInfo
log.error("mapOAuthApplication\n\tOAuthAppRequest appInfoRequest: " + new Gson().toJson(appInfoRequest));
        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();
log.error("mapOAuthApplication\n\tOAuthApplicationInfo oAuthApplicationInfo: " + new Gson().toJson(oAuthApplicationInfo));

        String consumerKey = oAuthApplicationInfo.getClientId();
log.error("mapOAuthApplication\nString consumerKey: " + consumerKey);
//{"clientId":"dummy","clientName":"Attemp2","clientSecret":"secret","parameters":{"tokenScope":"default","client_secret":"secret","KEY_TYPE":"PRODUCTION"},"isSaasApplication":false,"appAttributes":{},"tokenType":"DEFAULT"}

		if (IS_WEMODI) {
			OAuthApplicationInfo oauthClientInfo = appInfoRequest.getOAuthApplicationInfo();
log.error("mapOAuthApplication\nRestituisco OAuthApplicationInfo oauthClientInfo: " + new Gson().toJson(oauthClientInfo));
			return oauthClientInfo;
			//{"client_id":"Nb6Ej2QRxZ4cisV7xOGSAsQ7iPYa","client_name":"mapOAuthApplication","client_secret":"d1LaFMxEd9sN8X8LYfUOpKOW0Xsa","grant_types":["refresh_token","urn:ietf:params:oauth:grant-type:saml2-bearer","implicit","password","client_credentials","iwa:ntlm","urn:ietf:params:oauth:grant-type:device_code","authorization_code","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:jwt-bearer"],"redirect_uris":["https://localhost"],"ext_application_owner":"admin","ext_application_token_lifetime":3600,"ext_user_token_lifetime":3600,"ext_refresh_token_lifetime":86400,"ext_id_token_lifetime":3600,"pkceMandatory":false,"pkceSupportPlain":true,"bypassClientCredentials":false}
		}
		String tokenScope = (String) oAuthApplicationInfo.getParameter("tokenScope");
        String[] tokenScopes = new String[1];
        tokenScopes[0] = tokenScope;
        String clientSecret = (String) oAuthApplicationInfo.getParameter("client_secret");
        //for the first time we set default time period.
        oAuthApplicationInfo.addParameter(ApplicationConstants.VALIDITY_PERIOD,
                getConfigurationParamValue(APIConstants.IDENTITY_OAUTH2_FIELD_VALIDITY_PERIOD));

        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);

        // Verificare la corrispondenza tra i dati immessi (client id) e quanto censito sul server PDND
        ClientInfo clientInfo;
        try {
            clientInfo = dcrClient.getApplication(Base64.getUrlEncoder().encodeToString(
                    consumerKey.getBytes(StandardCharsets.UTF_8)));
log.error("mapOAuthApplication\nClient ifno restituito da dcrClient\nClientInfo clientInfo: " + new Gson().toJson(clientInfo));
// ClientInfo clientInfo: {"client_id":"Nb6Ej2QRxZ4cisV7xOGSAsQ7iPYa","client_name":"mapOAuthApplication","client_secret":"d1LaFMxEd9sN8X8LYfUOpKOW0Xsa","grant_types":["refresh_token","urn:ietf:params:oauth:grant-type:saml2-bearer","implicit","password","client_credentials","iwa:ntlm","urn:ietf:params:oauth:grant-type:device_code","authorization_code","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:jwt-bearer"],"redirect_uris":["https://localhost"],"ext_application_owner":"admin","ext_application_token_lifetime":3600,"ext_user_token_lifetime":3600,"ext_refresh_token_lifetime":86400,"ext_id_token_lifetime":3600,"pkceMandatory":false,"pkceSupportPlain":true,"bypassClientCredentials":false}
            // clientInfo = getPDNDApplication;
            buildDTOFromClientInfo(clientInfo, oAuthApplicationInfo);
        } catch (KeyManagerClientException e) {
            handleException("Some thing went wrong while getting OAuth application for given consumer key " +
                    oAuthApplicationInfo.getClientId(), e);
        }

        if (!clientSecret.equals(oAuthApplicationInfo.getClientSecret())) {
            throw new APIManagementException("The secret key is wrong for the given consumer key " + consumerKey);
        }
        oAuthApplicationInfo.addParameter("tokenScope", tokenScopes);
        oAuthApplicationInfo.setIsSaasApplication(false);

        if (log.isDebugEnabled()) {
            log.debug("Creating semi-manual application for consumer id  :  " + oAuthApplicationInfo.getClientId());
        }

        return oAuthApplicationInfo;
    }

    /**
     * Recupera le informazioni del client PDND
     * 
     * @return Informazzion sul client PDND
     * @throws KeyManagerClientException
     */
    private ClientInfo getPDNDApplication() throws KeyManagerClientException {
    	return null;
    }

    /**
     * Builds an OAuthApplicationInfo object using the ClientInfo response
     *
     * @param appResponse          ClientInfo response object
     * @param oAuthApplicationInfo original OAuthApplicationInfo object
     * @return OAuthApplicationInfo object with response information added
     */
    private OAuthApplicationInfo buildDTOFromClientInfo(ClientInfo appResponse,
                                                        OAuthApplicationInfo oAuthApplicationInfo) {

        oAuthApplicationInfo.setClientName(appResponse.getClientName());
        oAuthApplicationInfo.setClientId(appResponse.getClientId());
        if (appResponse.getRedirectUris() != null) {
            oAuthApplicationInfo.setCallBackURL(String.join(",", appResponse.getRedirectUris()));
            oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_REDIRECT_URIS,
                    String.join(",", appResponse.getRedirectUris()));
        }
        oAuthApplicationInfo.setClientSecret(appResponse.getClientSecret());
        if (appResponse.getGrantTypes() != null) {
            oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_GRANT,
                    String.join(" ", appResponse.getGrantTypes()));
        } else if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT) instanceof String) {
            oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_GRANT, ((String) oAuthApplicationInfo.
                    getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT)).replace(",", " "));
        }
        oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, appResponse.getClientName());
        Map<String, Object> additionalProperties = new HashMap<>();
        additionalProperties.put(APIConstants.KeyManager.APPLICATION_ACCESS_TOKEN_EXPIRY_TIME,
                appResponse.getApplicationAccessTokenLifeTime());
        additionalProperties.put(APIConstants.KeyManager.USER_ACCESS_TOKEN_EXPIRY_TIME,
                appResponse.getUserAccessTokenLifeTime());
        additionalProperties.put(APIConstants.KeyManager.REFRESH_TOKEN_EXPIRY_TIME,
                appResponse.getRefreshTokenLifeTime());
        additionalProperties.put(APIConstants.KeyManager.ID_TOKEN_EXPIRY_TIME, appResponse.getIdTokenLifeTime());
        additionalProperties.put(APIConstants.KeyManager.PKCE_MANDATORY, appResponse.getPkceMandatory());
        additionalProperties.put(APIConstants.KeyManager.PKCE_SUPPORT_PLAIN, appResponse.getPkceSupportPlain());
        additionalProperties.put(APIConstants.KeyManager.BYPASS_CLIENT_CREDENTIALS,
                appResponse.getBypassClientCredentials());

        oAuthApplicationInfo.addParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES, additionalProperties);
        return oAuthApplicationInfo;
    }

    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {
log.error("--------------------------------------------------------------- loadConfiguration");
log.error("loadConfiguration\n\tCarica la configurazione del Service Provider esterno");
log.error("loadConfiguration\n\tKeyManagerConfiguration configuration: " + new Gson().toJson(configuration));
//{"name":"PDND","type":"weModI","enabled":true,"tenantDomain":"carbon.super","tokenType":"DIRECT","configuration":{"claim_mappings":[],"grant_types":[],"enable_oauth_app_creation":true,"introspection_endpoint":"https://localhost:9443/oauth2/introspect","scope_endpoint":"https://localhost:9443/oauth2/scope","certificate_value":"","enable_token_generation":true,"issuer":"https://localhost:9443/oauth2/token","enable_map_oauth_consumer_apps":true,"enable_token_hash":false,"userinfo_endpoint":"https://localhost:9443/oauth2/userInfo","revoke_endpoint":"https://localhost:9443/oauth2/revoke","self_validate_jwt":true,"enable_token_encryption":false,"client_registration_endpoint":"https://localhost:9443/keymanager-operations/dcr/register","certificate_type":"PEM","token_endpoint":"https://localhost:9443/oauth2/token"}}

		if (IS_WEMODI) {
log.error("loadConfiguration\n\tImplementare le funzioni per il recupero dei dati dalla configurazione PDND.");
log.error("loadConfiguration\n\tAttualmente il portale PDND non eroga servizi di verifica del JWT, questo viene quindi effettuato off-line solo dal GW.");
			this.configuration = configuration;
log.error("loadConfiguration\n\tKey Manager configuration: " + new Gson().toJson(configuration));
			return;
		}


        this.configuration = configuration;

        String username = (String) configuration.getParameter(APIConstants.KEY_MANAGER_USERNAME);
        String password = (String) configuration.getParameter(APIConstants.KEY_MANAGER_PASSWORD);
        String keyManagerServiceUrl = (String) configuration.getParameter(APIConstants.AUTHSERVER_URL);

        String dcrEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT) != null) {
            dcrEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT);
        } else {
            dcrEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat
                            (APIConstants.KeyManager.KEY_MANAGER_OPERATIONS_DCR_ENDPOINT);
        }
        String tokenEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT) != null) {
            tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        } else {
            tokenEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0].concat(
                    "/oauth2/token");
        }
        addKeyManagerConfigsAsSystemProperties(tokenEndpoint);
        String revokeEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.REVOKE_ENDPOINT) != null) {
            revokeEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.REVOKE_ENDPOINT);
        } else {
            revokeEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0].concat(
                    "/oauth2/revoke");
        }
        String scopeEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT) != null) {
            scopeEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT);
        } else {
            scopeEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim())
                    .concat(APIConstants.KEY_MANAGER_OAUTH2_SCOPES_REST_API_BASE_PATH);
        }
        String introspectionEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT) != null) {
            introspectionEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT);
        } else {
            introspectionEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat("/oauth2/introspect");
        }

        String userInfoEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.USERINFO_ENDPOINT) != null) {
            userInfoEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.USERINFO_ENDPOINT);
        } else {
            userInfoEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat
                            (APIConstants.KeyManager.KEY_MANAGER_OPERATIONS_USERINFO_ENDPOINT);
        }

        dcrClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(dcrEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor("admin"/*username*/, "admin"/*password*/))
                .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                .errorDecoder(new KMClientErrorDecoder())
                .target(DCRClient.class, "https://localhost:9443/keymanager-operations/dcr/register"/*dcrEndpoint*/);
        authClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(tokenEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .errorDecoder(new KMClientErrorDecoder())
                .encoder(new FormEncoder())
                .target(AuthClient.class, tokenEndpoint);

        introspectionClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(introspectionEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor("admin"/*username*/, "admin"/*password*/))
                .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                .errorDecoder(new KMClientErrorDecoder())
                .encoder(new FormEncoder())
                .target(IntrospectionClient.class, introspectionEndpoint);
        scopeClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(scopeEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor("admin"/*username*/, "admin"/*password*/))
                .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                .errorDecoder(new KMClientErrorDecoder())
                .target(ScopeClient.class, scopeEndpoint);
        userClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(userInfoEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor("admin"/*username*/, "admin"/*password*/))
                .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                .errorDecoder(new KMClientErrorDecoder())
                .target(UserClient.class, userInfoEndpoint);

        if (APIConstants.KeyManager.DEFAULT_KEY_MANAGER_TYPE.equals(configuration.getType())) {
            String revokeOneTimeTokenEndpoint;
            if (configuration.getParameter(APIConstants.KeyManager.REVOKE_TOKEN_ENDPOINT) != null) {
                revokeOneTimeTokenEndpoint = (String) configuration
                        .getParameter(APIConstants.KeyManager.REVOKE_TOKEN_ENDPOINT);
            } else {
                revokeOneTimeTokenEndpoint = keyManagerServiceUrl
                        .split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0].concat(getTenantAwareContext().trim())
                        .concat(APIConstants.KeyManager.KEY_MANAGER_OPERATIONS_REVOKE_TOKEN_ENDPOINT);
            }

            revokeClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(revokeOneTimeTokenEndpoint)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BasicAuthRequestInterceptor(username, password))
                    .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(RevokeClient.class, revokeOneTimeTokenEndpoint);
        }
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
//        //Register new resource means create new API with given Scopes.
        //todo commented below code because of blocker due to API publish fail. need to find a better way of doing this
//        ApiMgtDAO apiMgtDAO = new ApiMgtDAO();
//        apiMgtDAO.addAPI(api, CarbonContext.getThreadLocalCarbonContext().getTenantId());

        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {

        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {

        return false;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {
    	log.info("deleteRegisteredResourceByAPIId");
    }

    @Override
    public void deleteMappedApplication(String consumerKey) throws APIManagementException {
    	log.info("deleteMappedApplication");
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws APIManagementException {

        return new HashSet<>();
    }

    /**
     * Returns the access token information of the provided consumer key.
     *
     * @param consumerKey The consumer key.
     * @return AccessTokenInfo The access token information.
     * @throws APIManagementException
     */
    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String consumerKey) throws APIManagementException {

        return new AccessTokenInfo();
    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String apiIdsString)
            throws APIManagementException {

        return null;
    }

    /**
     * This method will be used to register a Scope in the authorization server.
     *
     * @param scope Scope to register
     * @throws APIManagementException if there is an error while registering a new scope.
     */
    @Override
    public void registerScope(Scope scope) throws APIManagementException {

        String scopeKey = scope.getKey();
        ScopeDTO scopeDTO = new ScopeDTO();
        scopeDTO.setName(scopeKey);
        scopeDTO.setDisplayName(scope.getName());
        scopeDTO.setDescription(scope.getDescription());
        if (StringUtils.isNotBlank(scope.getRoles()) && scope.getRoles().trim().split(",").length > 0) {
            scopeDTO.setBindings(Arrays.asList(scope.getRoles().trim().split(",")));
        }
        try (Response response = scopeClient.registerScope(scopeDTO)) {
            if (response.status() != HttpStatus.SC_CREATED) {
                String responseString = readHttpResponseAsString(response.body());
                throw new APIManagementException("Error occurred while registering scope: " + scopeKey + ". Error" +
                        " Status: " + response.status() + " . Error Response: " + responseString);
            }
        } catch (KeyManagerClientException e) {
            handleException("Cannot register scope : " + scopeKey, e);
        }
    }

    /**
     * Read response body for HTTPResponse as a string.
     *
     * @param httpResponse HTTPResponse
     * @return Response Body String
     * @throws APIManagementException If an error occurs while reading the response
     */
    protected String readHttpResponseAsString(Response.Body httpResponse) throws APIManagementException {

        try (InputStream inputStream = httpResponse.asInputStream()) {
            return IOUtils.toString(inputStream);
        } catch (IOException e) {
            String errorMessage = "Error occurred while reading response body as string";
            throw new APIManagementException(errorMessage, e);
        }
    }

    /**
     * This method will be used to retrieve details of a Scope in the authorization server.
     *
     * @param name Scope Name to retrieve
     * @return Scope object
     * @throws APIManagementException if an error while retrieving scope
     */
    @Override
    public Scope getScopeByName(String name) throws APIManagementException {

        ScopeDTO scopeDTO;
        try {
            scopeDTO = scopeClient.getScopeByName(name);
            return fromDTOToScope(scopeDTO);
        } catch (KeyManagerClientException ex) {
            handleException("Cannot read scope : " + name, ex);
        }
        return null;
    }

    /**
     * Get Scope object from ScopeDTO response received from authorization server.
     *
     * @param scopeDTO ScopeDTO response
     * @return Scope model object
     */
    private Scope fromDTOToScope(ScopeDTO scopeDTO) {

        Scope scope = new Scope();
        scope.setName(scopeDTO.getDisplayName());
        scope.setKey(scopeDTO.getName());
        scope.setDescription(scopeDTO.getDescription());
        scope.setRoles((scopeDTO.getBindings() != null && !scopeDTO.getBindings().isEmpty())
                ? String.join(",", scopeDTO.getBindings()) : StringUtils.EMPTY);
        return scope;
    }

    /**
     * Get Scope object list from ScopeDTO List response received from authorization server.
     *
     * @param scopeDTOS Scope DTO Array
     * @return Scope Object to Scope Name Mappings
     */
    private Map<String, Scope> fromDTOListToScopeListMapping(ScopeDTO[] scopeDTOS) {

        Map<String, Scope> scopeListMapping = new HashMap<>();
        for (ScopeDTO scopeDTO : scopeDTOS) {
            scopeListMapping.put(scopeDTO.getName(), fromDTOToScope(scopeDTO));
        }
        return scopeListMapping;
    }

    /**
     * This method will be used to retrieve all the scopes available in the authorization server for the given tenant
     * domain.
     *
     * @return Mapping of Scope object to scope key
     * @throws APIManagementException if an error occurs while getting scopes list
     */
    @Override
    public Map<String, Scope> getAllScopes() throws APIManagementException {

        ScopeDTO[] scopes = new ScopeDTO[0];
        try {
            scopes = scopeClient.getScopes();
        } catch (KeyManagerClientException ex) {
            handleException("Error while retrieving scopes", ex);
        }
        return fromDTOListToScopeListMapping(scopes);
    }

    /**
     * This method will be used to attach a Scope in the authorization server to a API resource.
     *
     * @param api          API
     * @param uriTemplates URITemplate set with attached scopes
     * @throws APIManagementException if an error occurs while attaching scope to resource
     */
    @Override
    public void attachResourceScopes(API api, Set<URITemplate> uriTemplates)
            throws APIManagementException {
    	log.info("attachResourceScopes");
        //TODO: Nothing to do here
    }

    /**
     * This method will be used to update the local scopes and resource to scope attachments of an API in the
     * authorization server.
     *
     * @param api               API
     * @param oldLocalScopeKeys Old local scopes of the API before update (excluding the versioned local scopes
     * @param newLocalScopes    New local scopes of the API after update
     * @param oldURITemplates   Old URI templates of the API before update
     * @param newURITemplates   New URI templates of the API after update
     * @throws APIManagementException if fails to update resources scopes
     */
    @Override
    public void updateResourceScopes(API api, Set<String> oldLocalScopeKeys, Set<Scope> newLocalScopes,
                                     Set<URITemplate> oldURITemplates, Set<URITemplate> newURITemplates)
            throws APIManagementException {

        detachResourceScopes(api, oldURITemplates);
        // remove the old local scopes from the KM
        for (String oldScope : oldLocalScopeKeys) {
            deleteScope(oldScope);
        }
        //Register scopes
        for (Scope scope : newLocalScopes) {
            String scopeKey = scope.getKey();
            // Check if key already registered in KM. Scope Key may be already registered for a different version.
            if (!isScopeExists(scopeKey)) {
                //register scope in KM
                registerScope(scope);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Scope: " + scopeKey + " already registered in KM. Skipping registering scope.");
                }
            }
        }
        attachResourceScopes(api, newURITemplates);
    }

    /**
     * This method will be used to detach the resource scopes of an API and delete the local scopes of that API from
     * the authorization server.
     *
     * @param api          API   API
     * @param uriTemplates URITemplate Set with attach scopes to detach
     * @throws APIManagementException if an error occurs while detaching resource scopes of the API.
     */
    @Override
    public void detachResourceScopes(API api, Set<URITemplate> uriTemplates)
            throws APIManagementException {
    	log.info("detachResourceScopes");
        //TODO: Nothing to do here
    }

    /**
     * This method will be used to delete a Scope in the authorization server.
     *
     * @param scopeName Scope name
     * @throws APIManagementException if an error occurs while deleting the scope
     */
    @Override
    public void deleteScope(String scopeName) throws APIManagementException {

        try {
            Response response = scopeClient.deleteScope(scopeName);
            if (response.status() != HttpStatus.SC_OK) {
                String responseString = readHttpResponseAsString(response.body());
                String errorMessage =
                        "Error occurred while deleting scope: " + scopeName + ". Error Status: " + response.status() +
                                " . Error Response: " + responseString;
                throw new APIManagementException(errorMessage);
            }
        } catch (KeyManagerClientException ex) {
            handleException("Error occurred while deleting scope", ex);
        }
    }

    /**
     * This method will be used to update a Scope in the authorization server.
     *
     * @param scope Scope object
     * @throws APIManagementException if an error occurs while updating the scope
     */
    @Override
    public void updateScope(Scope scope) throws APIManagementException {

        String scopeKey = scope.getKey();
        try {
            ScopeDTO scopeDTO = new ScopeDTO();
            scopeDTO.setDisplayName(scope.getName());
            scopeDTO.setDescription(scope.getDescription());
            if (StringUtils.isNotBlank(scope.getRoles()) && scope.getRoles().trim().split(",").length > 0) {
                scopeDTO.setBindings(Arrays.asList(scope.getRoles().trim().split(",")));
            }
            scopeClient.updateScope(scopeDTO, scope.getKey());
        } catch (KeyManagerClientException e) {
            String errorMessage = "Error occurred while updating scope: " + scopeKey;
            handleException(errorMessage, e);
        }
    }

    /**
     * This method will be used to check whether the a Scope exists for the given scope name in the authorization
     * server.
     *
     * @param scopeName Scope Name
     * @return whether scope exists or not
     * @throws APIManagementException if an error occurs while checking the existence of the scope
     */
    @Override
    public boolean isScopeExists(String scopeName) throws APIManagementException {

        try (Response response = scopeClient.isScopeExist(scopeName)) {
            if (response.status() == HttpStatus.SC_OK) {
                return true;
            } else if (response.status() != HttpStatus.SC_NOT_FOUND) {
                String responseString = readHttpResponseAsString(response.body());
                String errorMessage = "Error occurred while checking existence of scope: " + scopeName + ". Error " +
                        "Status: " + response.status() + " . Error Response: " + responseString;
                throw new APIManagementException(errorMessage);
            }
        } catch (KeyManagerClientException e) {
            handleException("Error while check scope exist", e);
        }
        return false;
    }

    /**
     * This method will be used to validate the scope set provided and populate the additional parameters
     * (description and bindings) for each Scope object.
     *
     * @param scopes Scope set to validate
     * @throws APIManagementException if an error occurs while validating and populating
     */
    @Override
    public void validateScopes(Set<Scope> scopes) throws APIManagementException {

        for (Scope scope : scopes) {
            Scope sharedScope = getScopeByName(scope.getKey());
            scope.setName(sharedScope.getName());
            scope.setDescription(sharedScope.getDescription());
            scope.setRoles(sharedScope.getRoles());
        }
    }

    /**
     * Return the value of the provided configuration parameter.
     *
     * @param parameter Parameter name
     * @return Parameter value
     */
    protected String getConfigurationParamValue(String parameter) {

        return (String) configuration.getParameter(parameter);
    }

    /**
     * Check whether Token partitioning is enabled.
     *
     * @return true/false
     */
    protected boolean checkAccessTokenPartitioningEnabled() {

        return APIUtil.checkAccessTokenPartitioningEnabled();
    }

    /**
     * Check whether user name assertion is enabled.
     *
     * @return true/false
     */
    protected boolean checkUserNameAssertionEnabled() {

        return APIUtil.checkUserNameAssertionEnabled();
    }

    private String getTenantAwareContext() {

        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return "/t/".concat(tenantDomain);
        }
        return "";
    }

    private void addKeyManagerConfigsAsSystemProperties(String serviceUrl) {

        URL keyManagerURL;
        try {
            keyManagerURL = new URL(serviceUrl);
            String hostname = keyManagerURL.getHost();

            int port = keyManagerURL.getPort();
            if (port == -1) {
                if (APIConstants.HTTPS_PROTOCOL.equals(keyManagerURL.getProtocol())) {
                    port = APIConstants.HTTPS_PROTOCOL_PORT;
                } else {
                    port = APIConstants.HTTP_PROTOCOL_PORT;
                }
            }
            System.setProperty(APIConstants.KEYMANAGER_PORT, String.valueOf(port));

            if (hostname.equals(System.getProperty(APIConstants.CARBON_LOCALIP))) {
                System.setProperty(APIConstants.KEYMANAGER_HOSTNAME, "localhost");
            } else {
                System.setProperty(APIConstants.KEYMANAGER_HOSTNAME, hostname);
            }
            //Since this is the server startup.Ignore the exceptions,invoked at the server startup
        } catch (MalformedURLException e) {
            log.error("Exception While resolving KeyManager Server URL or Port " + e.getMessage(), e);
        }
    }

    @Override
    public Map<String, String> getUserClaims(String username, Map<String, Object> properties)
            throws APIManagementException {

        Map<String, String> map = new HashMap<String, String>();
        String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
        UserInfoDTO userinfo = new UserInfoDTO();
        userinfo.setUsername(tenantAwareUserName);
        if (tenantAwareUserName.contains(CarbonConstants.DOMAIN_SEPARATOR)) {
            userinfo.setDomain(tenantAwareUserName.split(CarbonConstants.DOMAIN_SEPARATOR)[0]);
        }
        if (properties.containsKey(APIConstants.KeyManager.ACCESS_TOKEN)) {
            userinfo.setAccessToken(properties.get(APIConstants.KeyManager.ACCESS_TOKEN).toString());
        }
        if (properties.containsKey(APIConstants.KeyManager.CLAIM_DIALECT)) {
            userinfo.setDialectURI(properties.get(APIConstants.KeyManager.CLAIM_DIALECT).toString());
        }
        if (properties.containsKey(APIConstants.KeyManager.BINDING_FEDERATED_USER_CLAIMS)) {
            userinfo.setBindFederatedUserClaims(Boolean.valueOf(properties.
                    get(APIConstants.KeyManager.BINDING_FEDERATED_USER_CLAIMS).toString()));
        }

        try {
            ClaimsList claims = userClient.generateClaims(userinfo);
            if (claims != null && claims.getList() != null) {
                for (Claim claim : claims.getList()) {
                    map.put(claim.getUri(), claim.getValue());
                }
            }
        } catch (KeyManagerClientException e) {
            handleException("Error while getting user info", e);
        }
        return map;
    }

    @Override
    public void revokeOneTimeToken(String token, String consumerKey) {

        RevokeTokenInfoDTO revokeTokenDTO = new RevokeTokenInfoDTO();
        revokeTokenDTO.setToken(token);
        revokeTokenDTO.setConsumerKey(consumerKey);
        try {
            Response response = revokeClient.revokeToken(revokeTokenDTO);
            if (log.isDebugEnabled()) {
                if (response.status() == HttpStatus.SC_OK) {
                    log.debug("Successfully revoked the token " + APIUtil.getMaskedToken(token) +
                            " with consumer key " + consumerKey);
                } else {
                    log.error("Error occurred while revoking one time token " + APIUtil.getMaskedToken(token) +
                            " with consumer key " + consumerKey + ". Status: " + response.status());
                }
            }
        } catch (KeyManagerClientException e) {
            log.error("Could not reach the key manager resource for one time token revocation of the token "
                    + APIUtil.getMaskedToken(token) + " with consumer key " + consumerKey + ". Error: " + e);
        }
    }

    @Override
    protected void validateOAuthAppCreationProperties(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {

        super.validateOAuthAppCreationProperties(oAuthApplicationInfo);
    }

    @Override
    public String getType() {

        return PDNDConstants.TYPE;
    }
}