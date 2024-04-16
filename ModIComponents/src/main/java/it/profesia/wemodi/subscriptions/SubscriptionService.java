package it.profesia.wemodi.subscriptions;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.EventHubConfigurationDto;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.SubscriptionDataHolder;
import org.wso2.carbon.apimgt.keymgt.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.keymgt.model.SubscriptionDataStore;
import org.wso2.carbon.apimgt.keymgt.model.entity.Subscription;
import org.wso2.carbon.apimgt.keymgt.model.exception.DataLoadingException;
import org.wso2.carbon.apimgt.keymgt.model.entity.API;
import org.wso2.carbon.apimgt.keymgt.model.entity.Application;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import it.profesia.wemodi.subscriptions.dao.CertAppMapping;
import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;

public class SubscriptionService {

	private static final Log log = LogFactory.getLog(SubscriptionService.class);
	private EventHubConfigurationDto getEventHubConfigurationDto;
	public static final int retrievalTimeoutInSeconds = 15;
	//public static final int retrievalRetries = 15;
	public static final int retrievalRetries = 4;
	public static final String UTF8 = "UTF-8";
	public static final String INTERNAL_MODI_API = "/api/am/modi";

	public SubscriptionService() {

		this.getEventHubConfigurationDto = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService()
				.getAPIManagerConfiguration().getEventHubConfigurationDto();
	}

	private String invokeService(String path, Pair<String, String> parameter, List<Pair<String, String>> parameterList)
			throws DataLoadingException, IOException, URISyntaxException {

		String serviceURLStr = getEventHubConfigurationDto.getServiceUrl().concat(INTERNAL_MODI_API);
		HttpGet method = new HttpGet(serviceURLStr + path);

		URL serviceURL = new URL(serviceURLStr + path);
		log.debug("Recupero informazioni weModI dal path: " + serviceURLStr + path);
		byte[] credentials = getServiceCredentials(getEventHubConfigurationDto);
		int servicePort = serviceURL.getPort();
		String serviceProtocol = serviceURL.getProtocol();
		method.setHeader(APIConstants.AUTHORIZATION_HEADER_DEFAULT,
				APIConstants.AUTHORIZATION_BASIC + new String(credentials, StandardCharsets.UTF_8));
		URIBuilder uriBuilder = new URIBuilder(method.getURI());
		//Handled more than one query paramter
		if(parameter != null)
			uriBuilder.addParameter(parameter.getKey(), parameter.getValue());
		else if(parameterList != null)
			for(Pair<String, String> parameterPair : parameterList)
				uriBuilder.addParameter(parameterPair.getKey(), parameterPair.getValue());
		
		URI uri = uriBuilder.build();
		method.setURI(uri);
		HttpClient httpClient = APIUtil.getHttpClient(servicePort, serviceProtocol);

		HttpResponse httpResponse = null;
		int retryCount = 0;
		boolean retry = false;
		int responseStatusCode = 0;
		String responseString = null;
		do {
			try {
				httpResponse = httpClient.execute(method);
				responseStatusCode = httpResponse.getStatusLine().getStatusCode();
				if(HttpStatus.SC_NOT_FOUND == responseStatusCode)
				{
					log.info("Received response with status code " + responseStatusCode + ". No retry is needed");
					return responseString;
				}
				else if (HttpStatus.SC_OK != responseStatusCode) {
					log.error("Could not call modi subscription api: "
							+ ". Received response with status code " + responseStatusCode);
					throw new DataLoadingException("Error while invoking modi subscription api");
				}
				retry = false;
			}
			catch (IOException | DataLoadingException ex) {
				retryCount++;
				if (retryCount < retrievalRetries) {
					retry = true;
					log.warn("Failed retrieving " + path + " from remote endpoint: " + ex.getMessage()
							+ ". Retrying after " + retrievalTimeoutInSeconds + " seconds.");
					try {
						Thread.sleep(retrievalTimeoutInSeconds * 1000);
					} catch (InterruptedException e) {
						log.error("Errore durante il recupero del certificato [" + parameter.toString() + "]: " + e.getMessage());
					}
				} else {
					throw ex;
				}
			}
		} while (retry);
		if (HttpStatus.SC_OK != responseStatusCode) {
			log.error("Could not call modi subscription api");
			throw new DataLoadingException("Error while invoking modi subscription api " + path);
		}
		responseString = EntityUtils.toString(httpResponse.getEntity(), UTF8);
		log.debug("Response invoke service : " + responseString);
		return responseString;

	}

	private byte[] getServiceCredentials(EventHubConfigurationDto eventHubConfigurationDto) {

		String username = eventHubConfigurationDto.getUsername();
		String pw = eventHubConfigurationDto.getPassword();
		return Base64.encodeBase64((username + APIConstants.DELEM_COLON + pw).getBytes(StandardCharsets.UTF_8));
	}

	public PdndPKMapping getPrivateKeyByConsumerKeyForPdnd(String consumerKey)
			throws DataLoadingException, URISyntaxException {
		String path = "/subscriptionservice/privateKeyByConsumerKeyForPdnd";
		String responseString = null;
		PdndPKMapping pdndPKMapping = null;
		Pair<String, String> consumerKeyPair = Pair.of("consumerKey", consumerKey);
		try {
			responseString = invokeService(path, consumerKeyPair, null);
		} catch (IOException e) {
			String msg = "Error while executing the http client " + INTERNAL_MODI_API + path;
			log.error(msg, e);
			throw new DataLoadingException(msg, e);
		}
		if (responseString != null && !responseString.isEmpty()) {
			pdndPKMapping = new Gson().fromJson(responseString, PdndPKMapping.class);
		}
		return pdndPKMapping;
	}

    /**
     * Restituisce la configurazione weModI per la sottoscrizione dell'API
     * 
     * @param subscriptionUUID UUID della sottoscrizione
     * @return Configurazione weModI
     */
	public PdndPKMapping getSubscriptionDetails(String subscriptionUUID) {
        log.debug(String.format("Recupero della configurazione weModI: {subscriptionUUID: %s}.", subscriptionUUID));

		String path = "/subscriptionservice/subscriptionDetails";
		String responseString = null;
		PdndPKMapping pdndPKMapping = null;
		Pair<String, String> subscriptionUUIDPair = Pair.of("subscriptionUUID", subscriptionUUID);
		try {
			responseString = invokeService(path, subscriptionUUIDPair, null);
		} catch (IOException | DataLoadingException | URISyntaxException  e) {
			String msg = "Error while executing the http client " + path;
			log.error(msg, e);
			return null;
		}
		if (responseString != null && !responseString.isEmpty()) {
			pdndPKMapping = new Gson().fromJson(responseString, PdndPKMapping.class);
		}
		return pdndPKMapping;
	}

    /**
     * Restituisce la configurazione weModI per la sottoscrizione dell'API
     * 
     * @param appId Id della Oauth application di sottoscrizione
     * @param apiId Id dell'API sottoscritta
     * @param apiTenantDomain Dominio del tenant
     * @return Configurazione weModI
     */
    public PdndPKMapping getSubscriptionDetails(int appId, int apiId, String apiTenantDomain) {
        log.debug(String.format("Recupero della configurazione weModI: {appId: %s, apiId: %s, apiTenantDomain: %s}.", appId, apiId, apiTenantDomain));

        PdndPKMapping pdndPK = null;
        Subscription subscription = SubscriptionDataHolder.getInstance().getTenantSubscriptionStore(apiTenantDomain).getSubscriptionById(appId, apiId);
        String subscriptionUUID = subscription.getSubscriptionUUId();
        log.debug("subscriptionUUID: "+subscriptionUUID);
        pdndPK = getSubscriptionDetails(subscriptionUUID);
        return pdndPK;
    }

    /**
     * Restituisce la configurazione weModI per la sottoscrizione dell'API
     * 
     * @param apiContext Context dell'API
     * @param apiVersion Versione dell'API
     * @param apiTenantDomain Dominio del tenant
     * @param applicationUUID UUID della Oauth application di sottoscrizione
     * @return Configurazione weModI
     */
    public PdndPKMapping getSubscriptionDetails(String apiContext, String apiVersion, String apiTenantDomain, String applicationUUID) {
        log.debug(String.format("Recupero della configurazione weModI: {apiContext: %s, apiVersion: %s, apiTenantDomain: %s, applicationUUID: %s}.", apiContext, apiVersion, apiTenantDomain, applicationUUID));
        PdndPKMapping pdndPK = null;
        SubscriptionDataStore datastore = SubscriptionDataHolder.getInstance().getTenantSubscriptionStore(apiTenantDomain);
		if (datastore != null) {
        	Application app = datastore.getApplicationByUUID(applicationUUID);
        	if(app != null) {
        		int appId = app.getId();
        		if(appId != 0) {
        			API api = datastore.getApiByContextAndVersion(apiContext, apiVersion);
        			if(api != null) {
        				int apiId = api.getApiId();
                        pdndPK = getSubscriptionDetails(appId, apiId, apiTenantDomain);
        			}
        			else {
                        if (log.isDebugEnabled()) {
                            log.warn("API not found in the datastore for " + apiContext + ":" + apiVersion);
                        }
                    }
    			}
        		else {
                    if (log.isDebugEnabled()) {
                    	log.warn("appId: " + appId + " not found");
                    }
                }
        	}
        	else {
                if (log.isDebugEnabled()) {
                	log.warn("Application not found for " + applicationUUID);
                }
            }
        }
        else {
            log.error("Subscription datastore is not initialized for tenant domain " + apiTenantDomain);
        }
        return pdndPK;
	}

	public ModiPKMapping getPrivateKeyByConsumerKeySOAP(String consumerKey)
			throws DataLoadingException, URISyntaxException {
		String path = "/subscriptionservice/privateKeyByConsumerKeyForSOAP";
		String responseString = null;
		ModiPKMapping modiPKMapping = null;
		Pair<String, String> consumerKeyPair = Pair.of("consumerKey", consumerKey);
		try {
			responseString = invokeService(path, consumerKeyPair, null);
		} catch (IOException e) {
			String msg = "Error while executing the http client " + INTERNAL_MODI_API + path;
			log.error(msg, e);
			throw new DataLoadingException(msg, e);
		}
		if (responseString != null && !responseString.isEmpty()) {
			modiPKMapping = new Gson().fromJson(responseString, ModiPKMapping.class);
		}
		return modiPKMapping;
	}
	
	public ModiPKMapping getPrivateKeyByConsumerKeyForModi(String consumerKey)
			throws DataLoadingException, URISyntaxException {
		String path = "/subscriptionservice/privateKeyByConsumerKeyForModi";
		String responseString = null;
		ModiPKMapping modiPKMapping = null;
		Pair<String, String> consumerKeyPair = Pair.of("consumerKey", consumerKey);
		try {
			responseString = invokeService(path, consumerKeyPair, null);
		} catch (IOException e) {
			String msg = "Error while executing the http client " + INTERNAL_MODI_API + path;
			log.error(msg, e);
			throw new DataLoadingException(msg, e);
		}
		if (responseString != null && !responseString.isEmpty()) {
			modiPKMapping = new Gson().fromJson(responseString, ModiPKMapping.class);
		}
		return modiPKMapping;
	}
	
	public CertAppMapping getAliasWithThumbprint(String thumbprint)
			throws DataLoadingException, URISyntaxException {
		String path = "/subscriptionservice/aliasWithThumbprint";
		String responseString = null;
		CertAppMapping cam = null;
		Pair<String, String> thumbprintPair = Pair.of("thumbprint", thumbprint);
		try {
			responseString = invokeService(path, thumbprintPair, null);
		} catch (IOException e) {
			String msg = "Error while executing the http client " + INTERNAL_MODI_API + path;
			log.error(msg, e);
			throw new DataLoadingException(msg, e);
		}
		if (responseString != null && !responseString.isEmpty()) {
			cam = new Gson().fromJson(responseString, CertAppMapping.class);
		}
		return cam;
	}
	
	public CertAppMapping getCertificatesInboundModi(String applicationUUID) {
		String path = "/subscriptionservice/certificatesInbound";
		String responseString = null;
		CertAppMapping cam = null;
		Pair<String, String> applicationUUIDPair = Pair.of("applicationUUID", applicationUUID);
		try {
			responseString = invokeService(path, applicationUUIDPair, null);
		} catch (IOException | DataLoadingException | URISyntaxException e) {
			String msg = "Errore durante la chiamata al client http " + path;
			log.error(msg, e);
			return null;
		}
		if (responseString != null && !responseString.isEmpty()) {
			cam = new Gson().fromJson(responseString, CertAppMapping.class);
		}
		return cam;
	}
	
	public CertAppMapping getCertificateSOAP(String firstKeyIdentifier, String secondKeyIdentifier) {
		String path = "/subscriptionservice/certificateSOAP";
		String responseString = null;
		CertAppMapping cam = null;
		Pair<String, String> firstPair = Pair.of("firstKeyIdentifier", firstKeyIdentifier);
		Pair<String, String> secondPair = Pair.of("secondKeyIdentifier", secondKeyIdentifier);
		List<Pair<String, String>> keyIdentifierList = new ArrayList<Pair<String, String>>();
		keyIdentifierList.add(firstPair);
		keyIdentifierList.add(secondPair);
		try {
			responseString = invokeService(path, null, keyIdentifierList);
		} catch (IOException | DataLoadingException | URISyntaxException  e) {
			String msg = "Errore durante la chiamata al client http " + path;
			log.error(msg, e);
			return null;
		}
		if (responseString != null && !responseString.isEmpty()) {
			cam = new Gson().fromJson(responseString, CertAppMapping.class);
		}
		return cam;
	}
	
	public CertAppMapping getCertificatesSOAPInboundModi(String applicationUUID) {
		String path = "/subscriptionservice/certificatesSOAPInbound";
		String responseString = null;
		CertAppMapping cam = null;
		Pair<String, String> applicationUUIDPair = Pair.of("applicationUUID", applicationUUID);
		try {
			responseString = invokeService(path, applicationUUIDPair, null);
		} catch (IOException | DataLoadingException | URISyntaxException e) {
			String msg = "Errore durante la chiamata al client http " + path;
			log.error(msg, e);
			return null;
		}
		if (responseString != null && !responseString.isEmpty()) {
			cam = new Gson().fromJson(responseString, CertAppMapping.class);
		}
		return cam;
	}
	
	public String getApplicationUUIDByKid(String kidPdndApi)
			throws DataLoadingException, URISyntaxException {
		String path = "/subscriptionservice/applicationUUIDByKid";
		String responseString = null;
		String applicationUUID = "";
		Pair<String, String> kidPdndApiPair = Pair.of("kidPdndApi", kidPdndApi);
		try {
			responseString = invokeService(path, kidPdndApiPair, null);
		} catch (IOException e) {
			String msg = "Error while executing the http client " + INTERNAL_MODI_API + path;
			log.error(msg, e);
			throw new DataLoadingException(msg, e);
		}
		if (responseString != null && !responseString.isEmpty()) {
			applicationUUID = new Gson().fromJson(responseString, String.class);
		}
		return applicationUUID;
	}
	
	public PdndPKMapping getCertificatesOutboundPdnd(String applicationUUID)
			throws DataLoadingException, URISyntaxException {
		String path = "/subscriptionservice/certificatesOutboundPdnd";
		String responseString = null;
		PdndPKMapping pdndPKMapping = null;
		Pair<String, String> applicationUUIDPair = Pair.of("applicationUUID", applicationUUID);
		try {
			responseString = invokeService(path, applicationUUIDPair, null);
		} catch (IOException e) {
			String msg = "Error while executing the http client " + INTERNAL_MODI_API + path;
			log.error(msg, e);
			throw new DataLoadingException(msg, e);
		}
		if (responseString != null && !responseString.isEmpty()) {
			pdndPKMapping = new Gson().fromJson(responseString, PdndPKMapping.class);
		}
		return pdndPKMapping;
	}
	
	public JsonObject getCacheConfigurations()
			throws DataLoadingException, URISyntaxException {
		String path = "/subscriptionservice/cacheConfigurations";
		String responseString = null;
		JsonObject cacheConfigurations = null;
		try {
			responseString = invokeService(path, null, null);
		} catch (IOException e) {
			String msg = "Error while executing the http client " + INTERNAL_MODI_API + path;
			log.error(msg, e);
			throw new DataLoadingException(msg, e);
		}
		if (responseString != null && !responseString.isEmpty()) {
			cacheConfigurations = new Gson().fromJson(responseString, JsonObject.class);
		}
		return cacheConfigurations;
	}

}
