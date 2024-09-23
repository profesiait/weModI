/**
 * 
 */
package it.profesia.wemodi.handlers.security;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.cache.Cache;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.gateway.MethodStats;
import org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler;
import org.wso2.carbon.apimgt.gateway.utils.GatewayUtils;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.EventHubConfigurationDto;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.keymgt.model.exception.DataLoadingException;

import com.google.gson.Gson;

import org.wso2.carbon.apimgt.keymgt.model.entity.API;

import it.profesia.carbon.apimgt.gateway.handlers.logging.ModiLogUtils;
import it.profesia.carbon.apimgt.gateway.handlers.utils.CacheProviderWeModi;
import it.profesia.wemodi.ApiConfig;

/**
 * Authentication handler per l'autorizzazione delle API ModI/PDND, richiede l'implementazione
 * weModI as Key Manager per la validazione del voucher PDND
 */
public class WeModIAPIAuthenticationHandler extends APIAuthenticationHandler {

    private static final Log log = LogFactory.getLog(WeModIAPIAuthenticationHandler.class);

    private EventHubConfigurationDto getEventHubConfigurationDto;
    private SynapseEnvironment synapseEnvironment;

    public WeModIAPIAuthenticationHandler() {
        this.getEventHubConfigurationDto = ServiceReferenceHolder.getInstance()
                .getAPIManagerConfigurationService().getAPIManagerConfiguration()
                .getEventHubConfigurationDto();
    }

    public void init(SynapseEnvironment synapseEnvironment) {
        this.synapseEnvironment = synapseEnvironment;
        super.init(synapseEnvironment);
    }

    @Override
    @edu.umd.cs.findbugs.annotations.SuppressWarnings(value = "LEST_LOST_EXCEPTION_STACK_TRACE", justification = "The exception needs to thrown for fault sequence invocation")
    protected void initializeAuthenticators() {
        WeModiAuthenticator authenticator = new WeModiAuthenticator();
        authenticator.init(synapseEnvironment);
        authenticators.add(authenticator);
        super.initializeAuthenticators();
    }

    @MethodStats
    @edu.umd.cs.findbugs.annotations.SuppressWarnings(value = "EXS_EXCEPTION_SOFTENING_RETURN_FALSE",
            justification = "Error is sent through payload")
    public boolean handleRequest(MessageContext messageContext) {
        ModiLogUtils.initialize(messageContext);
        log.info(ModiLogUtils.EROGAZIONE_START);
        try {
            API retrievedApi = GatewayUtils.getAPI(messageContext);
            ApiConfig api = retrieveAPIInformations(retrievedApi.getUuid() , (String) messageContext.getProperty("tenant.info.domain"));

            org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
            Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));
            String weModiApiConfig = new Gson().toJson(api);
            headers.put("weModI_API_Config", weModiApiConfig);

            if (super.handleRequest(messageContext) == true) {
                //TODO: Validare gli header con i claim JWT
            }
        } catch (DataLoadingException | IOException e) {
            log.error("Si è verificato un errore durante l'autorizzazione weModI dell'API: " + ExceptionUtils.getStackTrace(e));
        }

        log.info(ModiLogUtils.EROGAZIONE_FINISH);
        return false;
    }

    /**
     * Recupera le informazioni dell'API invocata per ottenere le properties impostate in modo
     * da effettuare le opportune validazioni dei JWT ModI/PDND
     * 
     * @param apiID UUID dell'API
     * @param tenantDomain Tenant di riferimento
     * @throws MalformedURLException
     */
    private ApiConfig retrieveAPIInformations(String apiID, String tenantDomain) throws DataLoadingException, IOException {
        //String path = "/apis/{apiId}";
        String path = "/apis/" + apiID;
        String serviceURLStr = getEventHubConfigurationDto.getServiceUrl().concat("/api/am/publisher/v4");
        HttpGet method = new HttpGet(serviceURLStr + path);
        ApiConfig apiConfig = null;
        String apiConfigKey = "apiConfig:" + apiID + "@" + tenantDomain;

        if (getWeModiCacheEnable()) {
            Object cache = getWeModiCache().get(apiConfigKey);
            if (cache != null) {
                apiConfig = (ApiConfig) cache;
            }
        }
        if (apiConfig == null) {
            URL serviceURL = new URL(serviceURLStr + path);
            byte[] credentials = Base64.encodeBase64(("admin" + ":" + "admin").getBytes(StandardCharsets.UTF_8)); //getServiceCredentials(getEventHubConfigurationDto);
            int servicePort = serviceURL.getPort();
            String serviceProtocol = serviceURL.getProtocol();
            method.setHeader(APIConstants.AUTHORIZATION_HEADER_DEFAULT,
                    APIConstants.AUTHORIZATION_BASIC +
                            new String(credentials, StandardCharsets.UTF_8));
            if (tenantDomain != null) {
                method.setHeader(APIConstants.HEADER_TENANT, tenantDomain);
            }
            HttpClient httpClient = APIUtil.getHttpClient(servicePort, serviceProtocol);

            HttpResponse httpResponse = null;

            int retryCount = 0;
            boolean retry = false;
            do {
                try {
                    httpResponse = httpClient.execute(method);
                    if (HttpStatus.SC_OK != httpResponse.getStatusLine().getStatusCode()) {
                        log.error("Could not retrieve subscriptions for tenantDomain: " + tenantDomain
                                + ". Received response with status code "
                                + httpResponse.getStatusLine().getStatusCode());
                        throw new DataLoadingException("Error while retrieving subscription");
                    }
                    retry = false;
                } catch (IOException | DataLoadingException ex) {
                    retryCount++;
                    if (retryCount < 15/*retrievalRetries*/) {
                        retry = true;
                        log.warn("Failed retrieving " + path + " from remote endpoint: " + ex.getMessage()
                                + ". Retrying after " + 15/*retrievalTimeoutInSeconds*/ +
                                " seconds.");
                        try {
                            Thread.sleep(15/*retrievalTimeoutInSeconds*/ * 1000);
                        } catch (InterruptedException e) {
                            // Ignore
                        }
                    } else {
                        throw ex;
                    }
                }
            } while (retry);
            if (HttpStatus.SC_OK != httpResponse.getStatusLine().getStatusCode()) {
                log.error("Could not retrieve subscriptions for tenantDomain : " + tenantDomain);
                throw new DataLoadingException("Error while retrieving subscription from " + path);
            }
            String responseString = EntityUtils.toString(httpResponse.getEntity(), "UTF-8"/*UTF8*/);
            if (log.isDebugEnabled()) {
                log.debug("Response : " + responseString);
            }
            JSONObject responseJson = new JSONObject(responseString);
            JSONObject propertiesJson = responseJson.getJSONObject("additionalPropertiesMap");

            apiConfig = new ApiConfig(propertiesJson);
            getWeModiCache().put(apiConfigKey, apiConfig);
        }

        log.info("Patterns per l'API: " + apiConfig.getPatterns());

        return apiConfig;       
    }

    private static Cache getWeModiCache() {
        return CacheProviderWeModi.getWeModiCache();
    }

    private static boolean getWeModiCacheEnable() {
        return CacheProviderWeModi.isEnabledCache();
    }

}
