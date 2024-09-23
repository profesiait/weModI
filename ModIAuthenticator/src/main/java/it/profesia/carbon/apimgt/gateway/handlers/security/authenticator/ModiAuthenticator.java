package it.profesia.carbon.apimgt.gateway.handlers.security.authenticator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.cache.Cache;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.apache.axis2.Constants;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.RESTConstants;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.Pipe;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.apache.ws.security.WSSecurityException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APIKeyValidator;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationResponse;
import org.wso2.carbon.apimgt.gateway.handlers.security.Authenticator;
import org.wso2.carbon.apimgt.gateway.utils.GatewayUtils;
import org.wso2.carbon.apimgt.gateway.utils.OpenAPIUtils;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.caching.CacheProvider;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.SubscriptionDataHolder;
import org.wso2.carbon.apimgt.keymgt.model.SubscriptionDataStore;
import org.wso2.carbon.apimgt.keymgt.model.entity.API;
import org.wso2.carbon.apimgt.keymgt.model.entity.Application;
import org.wso2.carbon.apimgt.keymgt.model.entity.Subscription;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.SAXException;

import com.google.gson.Gson;
import com.nimbusds.jwt.SignedJWT;

import io.swagger.v3.oas.models.OpenAPI;
import it.profesia.carbon.apimgt.gateway.handlers.modi.soap.ValidateSOAPMessage;
import it.profesia.carbon.apimgt.gateway.handlers.security.JWTClaims;
import it.profesia.carbon.apimgt.gateway.handlers.security.JWTInfo;
import it.profesia.carbon.apimgt.gateway.handlers.security.JWTValidator;
import it.profesia.carbon.apimgt.gateway.handlers.utils.SOAPUtil;
import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.CertAppMapping;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;
import it.profesia.wemodi.subscriptions.utils.CertificateMetadata;

/**
 * This class used to authenticate InternalKey
 */
public class ModiAuthenticator implements Authenticator {
	
	protected APIKeyValidator apiKeyValidator = null;

	protected APIKeyValidator getApiKeyValidator() {
		 return this.apiKeyValidator;
	}
	

	private static final Log log = LogFactory.getLog(ModiAuthenticator.class);

    /**
     * These are the properties set in the API that identify the ModI pattern
     */
    public static final String ID_AUTH_REST_01 = "ID_AUTH_REST_01";
    public static final String ID_AUTH_REST_02 = "ID_AUTH_REST_02";
    public static final String INTEGRITY_REST_01 = "INTEGRITY_REST_01";
    public static final String PDND_AUTH = "PDND_AUTH";
    public static final String MODI_AUTH = "MODI_AUTH";
    public static final String PDND_JWKS_URL = "PDND_JWKS_URL";
    public static final String PDND_API_URL = "PDND_API_URL";
    public static final String AUDIT_REST_01_PDND = "AUDIT_REST_01_PDND";
    public static final String AUDIT_REST_01_MODI = "AUDIT_REST_01_MODI";
    public static final String AUDIT_REST_02 = "AUDIT_REST_02";
    public static final String INTEGRITY_REST_02 = "INTEGRITY_REST_02";
    public static final String API_AUD = "API_AUD";

    private String [] securityParams;
   

    public ModiAuthenticator(String... securityParams) {
        this.securityParams = securityParams;
    }
    
    

    @Override
    public void init(SynapseEnvironment env) {
        // Nothing to do in init phase.
    }

    @Override
    public void destroy() {
    	if (apiKeyValidator != null) {
            this.apiKeyValidator.cleanup();
        }
    }
    

    @Override
    public AuthenticationResponse authenticate(MessageContext synCtx) {
    	boolean isValid = false, isSubscriptionValid = false, isSubscriptionValidForPdnd = false, isValidSOAP = false;
        API retrievedApi = GatewayUtils.getAPI(synCtx);
        if (retrievedApi != null) {
            if (log.isDebugEnabled()) {
                log.info("ModI Authentication initialized");
            }
            
            //properties
            
            String id_auth_rest_01 = (String) synCtx.getProperty(ID_AUTH_REST_01);
            log.info("id_auth_rest_01: "+id_auth_rest_01);
            String id_auth_rest_02 = (String) synCtx.getProperty(ID_AUTH_REST_02);
            log.info("id_auth_rest_02: "+id_auth_rest_02);
            String integrity_rest_01 = (String) synCtx.getProperty(INTEGRITY_REST_01);
            log.info("integrity_rest_01: "+integrity_rest_01);
            String pdnd_auth = (String) synCtx.getProperty(PDND_AUTH);
            log.info("pdnd_auth: "+pdnd_auth);
            String modi_auth = (String) synCtx.getProperty(MODI_AUTH);
            log.info("modi_auth: "+modi_auth);
            String pdnd_jwks_url = (String) synCtx.getProperty(PDND_JWKS_URL);
            log.info("pdnd_jwks_url: "+pdnd_jwks_url);
            String pdnd_api_url = (String) synCtx.getProperty(PDND_API_URL);
            log.info("pdnd_api_url: "+pdnd_api_url);
            String audit_rest_01_pdnd = (String) synCtx.getProperty(AUDIT_REST_01_PDND);
            log.info("audit_rest_01_pdnd: "+audit_rest_01_pdnd);
            String audit_rest_01_modi = (String) synCtx.getProperty(AUDIT_REST_01_MODI);
            log.info("audit_rest_01_modi: "+audit_rest_01_modi);
            String audit_rest_02 = (String) synCtx.getProperty(AUDIT_REST_02);
            log.info("audit_rest_02: "+audit_rest_02);
            String integrity_rest_02 = (String) synCtx.getProperty(INTEGRITY_REST_02);
            log.info("integrity_rest_02: "+integrity_rest_02);
            String api_aud = (String) synCtx.getProperty(API_AUD);
            log.info("api_aud: "+api_aud);
            Properties modiPdndProps = new Properties();
            modiPdndProps.setProperty(ID_AUTH_REST_01, id_auth_rest_01);
            modiPdndProps.setProperty(ID_AUTH_REST_02, id_auth_rest_02);
            modiPdndProps.setProperty(INTEGRITY_REST_01, integrity_rest_01);
            modiPdndProps.setProperty(PDND_AUTH, pdnd_auth);
            modiPdndProps.setProperty(MODI_AUTH, modi_auth);
            modiPdndProps.setProperty(PDND_JWKS_URL, pdnd_jwks_url);
            modiPdndProps.setProperty(PDND_API_URL, pdnd_api_url);
            modiPdndProps.setProperty(INTEGRITY_REST_02, integrity_rest_02);
            modiPdndProps.setProperty(API_AUD, api_aud);
            //end properties
            
            //for throttling
            OpenAPI openAPI = (OpenAPI) synCtx.getProperty(APIMgtGatewayConstants.OPEN_API_OBJECT);
            if (openAPI == null && !APIConstants.GRAPHQL_API.equals(synCtx.getProperty(APIConstants.API_TYPE))) {
                log.error("Swagger is missing in the gateway. " +
                        "Therefore, ModI authentication cannot be performed.");
                return new AuthenticationResponse(false, true, false,
                        APISecurityConstants.API_AUTH_MISSING_OPEN_API_DEF,
                        APISecurityConstants.API_AUTH_MISSING_OPEN_API_DEF_ERROR_MESSAGE);
            }
            
            String apiName = (String) synCtx.getProperty(RESTConstants.SYNAPSE_REST_API);
            log.info("apiName: "+apiName);
            
            String apiContext = (String) synCtx.getProperty(RESTConstants.REST_API_CONTEXT);
            log.info("apiContext: "+apiContext);
            
            String apiVersion = (String) synCtx.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
            log.info("apiVersion: "+apiVersion);
           
            String httpMethod = (String) ((Axis2MessageContext) synCtx).getAxis2MessageContext().
                    getProperty(Constants.Configuration.HTTP_METHOD);
            log.info("httpMethod: "+httpMethod);
            String matchingResource = (String) synCtx.getProperty(APIConstants.API_ELECTED_RESOURCE);
            log.info("matchingResource: "+matchingResource);

            String resourceCacheKey = APIUtil.getResourceInfoDTOCacheKey(apiContext, apiVersion,
                    matchingResource, httpMethod);
            VerbInfoDTO verbInfoDTO = new VerbInfoDTO();
            verbInfoDTO.setHttpVerb(httpMethod);
            //Not doing resource level authentication
            verbInfoDTO.setAuthType(APIConstants.AUTH_NO_AUTHENTICATION);
            verbInfoDTO.setRequestKey(resourceCacheKey);
            verbInfoDTO.setThrottling(OpenAPIUtils.getResourceThrottlingTier(openAPI, synCtx));
            List<VerbInfoDTO> verbInfoList = new ArrayList<>();
            verbInfoList.add(verbInfoDTO);
            synCtx.setProperty(APIConstants.VERB_INFO_DTO, verbInfoList);
            //end
        
            try {
                // Extract internal from the request while removing it from the msg context.
                //String internalKey = extractInternalKey(synCtx);
            	
            	String contentType = "", digest = "", serverUrl = "", /*requestURI = "",*/ aud = "";
            	serverUrl = APIUtil.getServerURL();
            	log.info("serverUrl: "+serverUrl);
            	/*requestURI = (String) synCtx.getProperty(RESTConstants.REST_FULL_REQUEST_PATH);
            	log.info("requestURI: "+requestURI);
            	aud = serverUrl+requestURI;*/
            	aud = serverUrl+apiContext;
                log.info("aud: "+aud);
                
                org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) synCtx).
                        getAxis2MessageContext();
            	
            	//contentType = (String) axis2MC.getProperty(Constants.Configuration.CONTENT_TYPE);
            	//log.info("contentType: "+contentType);
            	
            	String modiJwt = "", pdndJwt = "", jwsAudit = "", digestFromHeader = "";
            	JWTInfo jwtInfo = new JWTInfo();
            	
                Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));
                if(headers != null)
                {
                	digestFromHeader = ((digestFromHeader = (String) headers.get("Digest")) != null) ? digestFromHeader : "";
                	log.info("digestFromHeader: "+digestFromHeader);
                	contentType = ((contentType = (String) headers.get(HttpHeaders.CONTENT_TYPE)) != null) ? contentType : "";
                	log.info("contentType: "+contentType);
                }
                
                //Erogazione SOAP
                String soapAction = (String) headers.get("SOAPAction");
                if(soapAction != null && !(soapAction.equals("")))
                {
                	boolean isValidPDNDwithSOAP = true;
                	synCtx.setProperty("SOAPValidation", true);
                	if(pdnd_auth.equals("true"))
                    {
                		log.info("SOAP with PDND");
                		pdndJwt = extractPdndJWT(synCtx, securityParams[1], headers);
                    	log.info("pdndJwt: "+pdndJwt);
                    	if (StringUtils.isEmpty(pdndJwt)) {
                            return new AuthenticationResponse(false, false,
                                    true, APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
                        }
                    	
                    	isValidPDNDwithSOAP = JWTValidator.pdndJwtValidation(pdndJwt, jwtInfo, modiPdndProps, null);
                    		
                    }
                	//Disabled default WS-Addressing to avoid exceptions for mandatory headers
                	axis2MC.setProperty(org.apache.axis2.addressing.AddressingConstants.DISABLE_ADDRESSING_FOR_IN_MESSAGES, Boolean.TRUE);
                	return SOAPValidation(synCtx, headers, soapAction, axis2MC, apiContext, apiVersion, isValidPDNDwithSOAP, jwtInfo);
                }
					
				else
				{
					JWTClaims jwtClaims = null;
					digest = retrieveDigestFromPayload(axis2MC);
	            	log.info("digest: "+digest);
	            	if(audit_rest_01_pdnd.equals("true"))
                	{
                		jwtInfo.setJwtType("JWS_Audit");
                		jwsAudit = extractJWT(synCtx, securityParams[2], headers);
                		//jwsAudit = CertificateMetadata.decodeFromBase64(jwsAudit);
                		log.info("jwsAudit: "+jwsAudit);
                		if (StringUtils.isEmpty(jwsAudit)) {
                			throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
                        }
                		jwtClaims = new JWTClaims(contentType, digest, aud, digestFromHeader);
                		isValid = JWTValidator.pdndJwtValidation(jwsAudit, jwtInfo, modiPdndProps, jwtClaims);
                		log.info("isValid audit_rest_01_pdnd: "+isValid);
                	}
	            	if(audit_rest_01_modi.equals("true"))
                	{
                		jwtInfo.setJwtType("JWS_Audit");
                		jwtInfo.setAuditModI(true);
                		jwsAudit = extractJWT(synCtx, securityParams[2], headers);
                		//jwsAudit = CertificateMetadata.decodeFromBase64(jwsAudit);
                		log.info("jwsAudit: "+jwsAudit);
                		if (StringUtils.isEmpty(jwsAudit)) {
                			throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
                        }
                		jwtClaims = new JWTClaims(contentType, digest, aud, digestFromHeader);
    	                isValid = JWTValidator.JWTValidation(jwsAudit, pdndJwt, jwtInfo, modiPdndProps, jwtClaims);
                		log.info("isValid audit_rest_01_modi: "+isValid);
                	}
            	if(pdnd_auth.equals("true"))
                {
            		pdndJwt = extractPdndJWT(synCtx, securityParams[1], headers);
                	log.info("pdndJwt: "+pdndJwt);
                	if (StringUtils.isEmpty(pdndJwt)) {
                        return new AuthenticationResponse(false, false,
                                true, APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
                    }
                	if(audit_rest_02.equals("true"))
                	{
                		jwtInfo.setJwtType("JWS_Audit");
                		jwsAudit = extractJWT(synCtx, securityParams[2], headers);
                		//jwsAudit = CertificateMetadata.decodeFromBase64(jwsAudit);
                		log.info("jwsAudit: "+jwsAudit);
                		if (StringUtils.isEmpty(jwsAudit)) {
                            return new AuthenticationResponse(false, false,
                                    true, APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
                        }
                		byte[] digestBytes = convertToDigestBytes(jwsAudit);
        				String digestValue = CertificateMetadata.hexify(digestBytes);
        				log.info("digestValue audit_rest_02: "+digestValue);
        				jwtInfo.setDigest(digestValue);
                		isValid = JWTValidator.pdndJwtValidation(jwsAudit, jwtInfo, modiPdndProps, null);
                		log.info("isValid audit_rest_02: "+isValid);
                	}
                	if(!(modi_auth.equals("true")))
                	{
                		log.info("Only PDND");
                		jwtInfo.setJwtType("PDND_JWT");
                		isValid = JWTValidator.pdndJwtValidation(pdndJwt, jwtInfo, modiPdndProps, null);
                		log.info("isValid only pdnd: "+isValid);
                	}
                		
                }
            	if(modi_auth.equals("true"))
                {
            		jwtInfo.setJwtType("");
            		jwtInfo.setPdndKid("");
            		modiJwt = extractModiJWT(synCtx, securityParams[0], headers);
            		log.info("modiJwt: "+modiJwt);
	                if (StringUtils.isEmpty(modiJwt)) {
	                    return new AuthenticationResponse(false, false,
	                            true, APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
	                            APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
	                }
	                if(jwtClaims == null)
	                	jwtClaims = new JWTClaims(contentType, digest, aud, digestFromHeader);
	                isValid = JWTValidator.JWTValidation(modiJwt, pdndJwt, jwtInfo, modiPdndProps, jwtClaims);
	                log.info("isValid modi: "+isValid);
                
                }                
                if(jwtInfo.getThumbprint() != null)
                {
                	RSAPublicKey publicKey = null;
                	SignedJWT jwtSigned = SignedJWT.parse(modiJwt);                	
                	CertAppMapping cam = new SubscriptionService().getAliasWithThumbprint(jwtInfo.getThumbprint());
	                if(cam != null)
	                {
	                	String alias = cam.getAlias();
		                log.info("alias from thumbprint: "+alias);
		                Certificate cert = getCertificateFromAlias(alias);
		                if(cert != null)
		                {
		                	jwtInfo.setCertificateX509((X509Certificate) cert);
			                publicKey = (RSAPublicKey) cert.getPublicKey();
		                }
		                
	                }
	                isValid = JWTValidator.verifyTokenSignature(jwtSigned, publicKey);
	                
                }
                
                if(isValid)
                {
                	//only for testing purpose
                	/*try {
						retrieveAndSetParentTrustStore(); 
					} catch (APIManagementException e) {
						log.error("Error setting truststore", e);
					}*/
                	String subUUID = "";
            		
            		APIKeyValidationInfoDTO apiKeyValidationInfoDTO = null;
            		if (apiKeyValidator == null) {
                        this.apiKeyValidator = new APIKeyValidator();
                    }
                    String apiTenantDomain = MultitenantUtils.getTenantDomainFromRequestURL(apiContext);
                    if (apiTenantDomain == null) {
                        apiTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                    }
                    
                    int appId = 0;
                    SubscriptionDataStore datastore = SubscriptionDataHolder.getInstance()
                            .getTenantSubscriptionStore(apiTenantDomain);
            		
                    if(jwtInfo.getSub() != null && !(jwtInfo.getSub().equals("")))
                		{
                			log.info("Il claim sub è valorizzato: " + jwtInfo.getSub());
                			subUUID = jwtInfo.getSub();
                			
                			if (datastore != null) {
                                
                            	Application app = datastore.getApplicationByUUID(subUUID);
                            	if(app != null)
                            	{
                            		log.info("Recuperata l'application: " + app.toString());
                            		appId = app.getId();
                            		if(appId != 0)
                        			{
                        			//validate subscription
                            		apiKeyValidationInfoDTO = getApiKeyValidator().validateSubscription(apiContext, apiVersion, appId, apiTenantDomain);
                            		//end validate
                            		if(apiKeyValidationInfoDTO != null && apiKeyValidationInfoDTO.isAuthorized())
                            		{                            			
                            			CertAppMapping cam = new SubscriptionService().getCertificatesInboundModi(subUUID);
                            			
                                    	if (log.isTraceEnabled()) {
                                    		final String dLog = "Certificati associati all'application: " + app.getName() + ", organization: " + app.getOrganization() + "\n";
                                    		dLog.concat(cam.toString() + "\n");
                                    		log.trace(dLog);
                                    	}
                                    	if(pdnd_auth.equals("true"))
                                    		apiKeyValidationInfoDTO = validateCertAppMappingPdnd(cam, jwtInfo, apiKeyValidationInfoDTO, datastore, apiContext, apiVersion, appId, null);
                                		isSubscriptionValidForPdnd = apiKeyValidationInfoDTO.isAuthorized();
                                		if(modi_auth.equals("true") || audit_rest_01_modi.equals("true"))
                                    		apiKeyValidationInfoDTO = validateCertAppMapping(cam, jwtInfo, apiKeyValidationInfoDTO);
                            			isSubscriptionValid = apiKeyValidationInfoDTO.isAuthorized() && isSubscriptionValidForPdnd;
                            		}
                        			}
                            	}
                            	else {
                                    if (log.isDebugEnabled()) {
                                    	log.debug("Valid subscription not found for appId " + appId);
                                    }
                                }
                            } else {
                                log.error("Subscription datastore is not initialized for tenant domain " + apiTenantDomain);
                            }
                			
                			
                		}
            		else {
            			log.info("Il claim sub non è valorizzato");
            			
                        API api = null;
                        if (datastore != null) {
                            
                        	api = datastore.getApiByContextAndVersion(apiContext, apiVersion);
                            
                            if (api != null) {
                            	log.info("Verifica sulle sottoscrizioni dell'API: " + api.getApiName() + ", ID: " + api.getApiId());
                            	List<Subscription> subscriptions = datastore.getSubscriptionsByAPIId(api.getApiId());
                                for(Subscription subscription : subscriptions) {
                                	subUUID = subscription.getApplicationUUID();
                                	log.info("API " + api.getApiName() + "(" + api.getApiVersion() + ") sottoscritta da appUUID: " + subUUID);
                                	appId = subscription.getAppId();
                                	if(appId != 0) {
	                            		//validate subscription
	                            		apiKeyValidationInfoDTO = getApiKeyValidator().validateSubscription(apiContext, apiVersion, appId, apiTenantDomain);
	                            		//end validate
	                            		if(apiKeyValidationInfoDTO != null && apiKeyValidationInfoDTO.isAuthorized()) {
	                            			CertAppMapping cam = new SubscriptionService().getCertificatesInboundModi(subUUID);
	                            			log.debug("Post getCertificatesInboundModi(" + subUUID +") " + (cam != null ? new Gson().toJson(cam) : "null"));
	                            			
	                                    	if (log.isDebugEnabled()) {
	                                    		final String dLog = "Certificati associati all'API: " + api.getApiName() + " (" + api.getApiVersion() + ")\n";
	                                    		dLog.concat((cam != null ? cam.toString() : "nessuno") + "\n");
	                                    		log.debug(dLog);
	                                    	}
	                                    	if(pdnd_auth.equals("true"))
	                                    		apiKeyValidationInfoDTO = validateCertAppMappingPdnd(cam, jwtInfo, apiKeyValidationInfoDTO, datastore, apiContext, apiVersion, appId, subscription);
	                                    	log.debug("Post validateCertAppMappingPdnd " + apiKeyValidationInfoDTO.isAuthorized());	                                    	isSubscriptionValidForPdnd = apiKeyValidationInfoDTO.isAuthorized();
	                                    	if(modi_auth.equals("true") || audit_rest_01_modi.equals("true"))
	                                    		apiKeyValidationInfoDTO = validateCertAppMapping(cam, jwtInfo, apiKeyValidationInfoDTO);
	                                    	log.debug("Post validateCertAppMapping " + apiKeyValidationInfoDTO.isAuthorized());	
	                                    	if(isSubscriptionValid = (apiKeyValidationInfoDTO.isAuthorized() && isSubscriptionValidForPdnd)) {
	                                    		log.debug("Esito autorizzazione: " + isSubscriptionValid);
	                                    		break;
	                                    	}
	                            		}
                        			}
                                }
                                
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("API not found in the datastore for " + apiContext + ":" + apiVersion);
                                }
                            }
                        } else {
                            log.error("Subscription datastore is not initialized for tenant domain " + apiTenantDomain);
                        }
            		}
            		
            		if(isSubscriptionValid)
            		{
            			AuthenticationContext authenticationContext = null;
            			if(modi_auth.equals("true"))
            				authenticationContext = generateAuthenticationContext(apiKeyValidationInfoDTO, modiJwt);
            			else if(pdnd_auth.equals("true"))
            				authenticationContext = generateAuthenticationContext(apiKeyValidationInfoDTO, pdndJwt);
                        APISecurityUtils.setAuthenticationContext(synCtx, authenticationContext);
                        log.info("applicationName: "+apiKeyValidationInfoDTO.getApplicationName());
                        log.info("Valid JWT token. Authentication successful");
                        return new AuthenticationResponse(true, true, false, 0, null);
            		}
            		else if(apiKeyValidationInfoDTO == null || (apiKeyValidationInfoDTO.getValidationStatus() == APIConstants.KeyValidationStatus.SUBSCRIPTION_INACTIVE))
            		{
            			log.info("Subscription validation failed: it could be an automatic authorization");
            			if(jwtInfo.getPdndAud() != null && jwtInfo.getPdndAud().equals(aud))
            			{
            				automaticAuthentication(synCtx, retrievedApi.getApiTier());
            				log.info("Erogazione autorizzata in base al valore del campo AUD");
                            return new AuthenticationResponse(true, true, false, 0, null);
            			}
            			else if(jwtInfo.getPdndAud() != null && jwtInfo.getPdndAud().equals(api_aud))
            			{
            				automaticAuthentication(synCtx, retrievedApi.getApiTier());
            				log.info("Erogazione autorizzata in base al valore del campo API_AUD");
                            return new AuthenticationResponse(true, true, false, 0, null);	
            			}
            			else
            			{
            				log.info("aud from PDND voucher is not valid: " + jwtInfo.getPdndAud());
            				return new AuthenticationResponse(false, true,
                                    false, APISecurityConstants.SUBSCRIPTION_INACTIVE,
                                    APISecurityConstants.SUBSCRIPTION_INACTIVE_MESSAGE);
            			}
            			
            		}
            		else if(apiKeyValidationInfoDTO != null && (apiKeyValidationInfoDTO.getValidationStatus() == APIConstants.KeyValidationStatus.API_BLOCKED))
            		{
            			log.info("Subscription validation failed");
            			return new AuthenticationResponse(false, true,
                                false, APISecurityConstants.API_BLOCKED,
                                APISecurityConstants.API_BLOCKED_MESSAGE);
            		}
            		else
            		{
            			log.error("Cert app mapping validation failed");
                        throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
            		}
            		
            		
                }
                else
                {
                	log.error("Something wrong with jwt validation");
                    throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                            APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
                }
                
				}

            } catch (APISecurityException e) {
                return new AuthenticationResponse(false, true, false, e.getErrorCode(), e.getMessage());
            }
            catch (KeyStoreException | WSSecurityException | SAXException | ParserConfigurationException | XMLStreamException e) {
                log.error("Error while validating SOAP signature", e);
                return new AuthenticationResponse(false, true, false, APISecurityConstants.API_AUTH_INVALID_CREDENTIALS, e.getMessage());
            }
            catch(URISyntaxException | APIManagementException | IOException e)
            {
            	log.error(e);
            	return new AuthenticationResponse(false, true, false, APISecurityConstants.API_AUTH_GENERAL_ERROR,
                        APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE);
            }
            catch (ParseException e) {
                log.error("Error while parsing JWT", e);
                return new AuthenticationResponse(false, true, false, APISecurityConstants.API_AUTH_GENERAL_ERROR,
                        APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE);
            }
        }
        log.info("Authentication failed. Invalid JWT token.");
        return new AuthenticationResponse(false, true, false, APISecurityConstants.API_AUTH_GENERAL_ERROR,
                APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE);
    }
    
	private String convertToDigest(String payload) {
		String digestAlgorithm = "SHA-256";
		String sha256Base64 = "";
		try {
			MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
			byte[] encodedhash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
			sha256Base64 = new String(Base64.getEncoder().encode(encodedhash));
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
		}
		return digestAlgorithm + "=" + sha256Base64;
	}

	private byte[] convertToDigestBytes(String payload) {
		String digestAlgorithm = "SHA-256";
		byte[] encodedhash = null;
		try {
			MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
			encodedhash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
		}
		return encodedhash;
	}
    
    private String retrieveDigestFromPayload(org.apache.axis2.context.MessageContext axis2MC) throws IOException
    {
    	String digest = "";
    	ByteArrayOutputStream byteArrayOutputStream = null;
    	final Pipe pipe = (Pipe) axis2MC.getProperty(PassThroughConstants.PASS_THROUGH_PIPE);
    	if (pipe != null)
    	{
    		InputStream in = pipe.getInputStream();
    		if(in != null)
    		{
    		byteArrayOutputStream = new ByteArrayOutputStream();
            IOUtils.copy(in, byteArrayOutputStream);
            byteArrayOutputStream.flush();
            String originalPayload = byteArrayOutputStream.toString();
            log.debug("originalPayload: "+originalPayload);
            in =  new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            RelayUtils.buildMessage(axis2MC, false, in);
            digest = convertToDigest(originalPayload);
    		}
    	}
    	return digest;
    }
    
    private APIKeyValidationInfoDTO validateCertAppMapping(CertAppMapping cam, JWTInfo jwtInfo, APIKeyValidationInfoDTO apiKeyValidationInfoDTO) throws APISecurityException
    {
    	String uniqueIdentifier = "";
    	
    	if(jwtInfo.getPdndKid() != null && !(jwtInfo.getPdndKid().equals("")) && jwtInfo.isKidForModI() && !(jwtInfo.isAuditModI()))
    	{
    		log.info("INTEGRITY_REST_02 is enabled. Validation done by PDND");
    		return apiKeyValidationInfoDTO;
    	}
    	
    	apiKeyValidationInfoDTO.setAuthorized(false);
    	log.debug("In validateCertAppMapping " + (cam != null ? new Gson().toJson(cam) : "null"));
    	if (cam == null)
    		return apiKeyValidationInfoDTO;
    	
    		log.debug("Verfica del certificato: " + cam.toString());
    		Certificate cert = null;
    		if((cam.getAlias() != null && jwtInfo.getPublicKeyFromJWK() != null) || jwtInfo.getCertificateX509() != null)
    		{
    			if(jwtInfo.getCertificateX509() != null)
    				cert = jwtInfo.getCertificateX509();
    			else
    				cert = getCertificateFromAlias(cam.getAlias());
    			if(cert.getPublicKey().equals(jwtInfo.getPublicKeyFromJWK()) || jwtInfo.getCertificateX509() != null)
    			{
    				uniqueIdentifier = formatUniqueIdentifier(cam);
    				log.info("uniqueIdentifier if: "+uniqueIdentifier);
    				if(CertificateMetadata.getUniqueIdentifierOfCertificate((X509Certificate)cert).equals(uniqueIdentifier))
    				{
    					apiKeyValidationInfoDTO.setAuthorized(true);
    					log.info("Verificata l'associazione con il certificato: " + cam.toString());
    				}
    			}
    			
    		}
    		else
    		{
			uniqueIdentifier = formatUniqueIdentifier(cam);
			log.info("uniqueIdentifier else: "+uniqueIdentifier);
			if(jwtInfo.getCertificate() != null && CertificateMetadata.getUniqueIdentifierOfCertificate(CertificateMetadata.getX509Certificate(jwtInfo.getCertificate())).equals(uniqueIdentifier))
			{
				apiKeyValidationInfoDTO.setAuthorized(true);
				log.info("Verificata l'associazione con il certificato: " + cam.toString());
			}
    		}
    	return apiKeyValidationInfoDTO;
    }
    
    private APIKeyValidationInfoDTO validateCertAppMappingPdnd(CertAppMapping cam, JWTInfo jwtInfo, APIKeyValidationInfoDTO apiKeyValidationInfoDTO, SubscriptionDataStore datastore, String apiContext, String apiVersion, int appId, Subscription subscriptionParam) throws APISecurityException, APIManagementException, URISyntaxException
    {
    	if(jwtInfo.getPdndPublicKey() == null)
    	{
    		log.info("pdnd is not enabled");
    		return apiKeyValidationInfoDTO;
    	}
    	
    	log.debug("In validateCertAppMappingPdnd " + (cam != null ? new Gson().toJson(cam) : "null"));
    	apiKeyValidationInfoDTO.setAuthorized(false);
    	if (cam == null)
    		return apiKeyValidationInfoDTO;
    	
    	PdndPKMapping pdndPK = null;
    	if(jwtInfo.getSub() != null && !(jwtInfo.getSub().equals("")))
    	{
    		int apiId = 0;
			API api = datastore.getApiByContextAndVersion(apiContext, apiVersion);
			if(api != null)
			{
				apiId = api.getApiId();
				Subscription subscription = datastore.getSubscriptionById(appId, apiId);
				String subscriptionUUID = subscription.getSubscriptionUUId();
				log.info("subscriptionUUID: "+subscriptionUUID);
				pdndPK = new SubscriptionService().getSubscriptionDetails(subscriptionUUID);
				if (pdndPK == null)
		    		return apiKeyValidationInfoDTO;
				log.info("purposeId: "+pdndPK.getPurposeId());
			}	
			else {
                if (log.isDebugEnabled()) {
                    log.debug("API not found in the datastore for " + apiContext + ":" + apiVersion);
                }
            }
    	}
    	else
    	{
    		String subscriptionUUID = subscriptionParam.getSubscriptionUUId();
			log.info("subscriptionUUID: "+subscriptionUUID);
			pdndPK = new SubscriptionService().getSubscriptionDetails(subscriptionUUID);
			if (pdndPK == null)
	    		return apiKeyValidationInfoDTO;
			log.info("purposeId: "+pdndPK.getPurposeId());
    	}
    		log.debug("Verifica dell'associazione appId: " + appId + " tra API " + apiContext + "(" + apiVersion + ") e certificato: " + cam.toString());

    		if(cam.getPdndClientId() != null) {
    			if (cam.getPdndClientId().equals(jwtInfo.getPdndClientId())) {
    				if (pdndPK.getPurposeId().equals(jwtInfo.getPdndPurposeId())) {
    					if (pdndPK.getAud().equals(jwtInfo.getPdndAud())) {
    						if (pdndPK.getIss().equals(jwtInfo.getPdndIss())) {
				    			log.info("Verificata l'associazione per appId: " + appId + ", API " + apiContext + " (" + apiVersion + "), certificato: " + cam.toString());
				    			apiKeyValidationInfoDTO.setAuthorized(true);
    						} else {
    							log.info("ISS configurato (" + pdndPK.getIss() + ") non corrisponde al voucher PDND (" + jwtInfo.getPdndIss() + ").");
    							apiKeyValidationInfoDTO.setAuthorized(false);
    						}
    					} else {
    						log.info("AUD configurato (" + pdndPK.getAud() + ") non corrisponde al voucher PDND (" + jwtInfo.getPdndAud() + ").");
    						apiKeyValidationInfoDTO.setAuthorized(false);
    					}
    				} else {
    					log.info("Purpose ID configurato (" + pdndPK.getPurposeId() + ") non corrisponde al voucher PDND (" + jwtInfo.getPdndPurposeId() + ").");
    					apiKeyValidationInfoDTO.setAuthorized(false);
    				}
    			} else {
    				log.info("Client ID configurato (" + cam.getPdndClientId() + ") non corrisponde al voucher PDND (" + jwtInfo.getPdndClientId() + ").");
    				apiKeyValidationInfoDTO.setAuthorized(false);
    			}
    		} else {
    			log.info("Client ID non impostato.");
    			apiKeyValidationInfoDTO.setAuthorized(false);
    		}
    	return apiKeyValidationInfoDTO;
    }
    
    private APIKeyValidationInfoDTO validateCertAppMappingSOAP(CertAppMapping cam, APIKeyValidationInfoDTO apiKeyValidationInfoDTO, X509Certificate x509certificate) throws APISecurityException
    {
    	apiKeyValidationInfoDTO.setAuthorized(false);
    	if(x509certificate != null)
    	{
	    		String uniqueIdentifier = formatUniqueIdentifier(cam);
				log.info("uniqueIdentifier SOAP: "+uniqueIdentifier);
				if(CertificateMetadata.getUniqueIdentifierOfCertificate(x509certificate).equals(uniqueIdentifier))
				{
					apiKeyValidationInfoDTO.setAuthorized(true);
				}
    	}
    	return apiKeyValidationInfoDTO;
    }
    
    
    //to delete. Used just for testing purpose to avoid server restart if changed truststore
    private void retrieveAndSetParentTrustStore() throws APIManagementException {

        char[] trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword").toCharArray();
        String trustStoreLocation = System.getProperty("javax.net.ssl.trustStore");
        File trustStoreFile = new File(trustStoreLocation);
        try (InputStream localTrustStoreStream = new FileInputStream(trustStoreFile)) {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(localTrustStoreStream, trustStorePassword);
            ServiceReferenceHolder.getInstance().setTrustStore(trustStore);
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new APIManagementException("Error while Reading and set truststore", e);
        }
    }
    
    private String getAliasFromCertificate(String certificate)
    {
        String alias = "";
        try {
            KeyStore trustStore = ServiceReferenceHolder.getInstance().getTrustStore();
            log.info("trustStore type: "+trustStore.getType());
            Certificate cert = JWTValidator.getX509Certificate(certificate);
            log.info("certificate type: "+cert.getType());
            
            if (trustStore != null) {
                // Read alias from trust store
                alias = trustStore.getCertificateAlias(cert);
                log.info("alias: "+alias);
            }
        } catch (KeyStoreException e) {
            String msg = "Error in retrieving alias from the trust store";
            log.error(msg, e);
        }
        return alias;
    }
    
    private Certificate getCertificateFromAlias(String alias)
    {
    	Certificate cert = null;
        try {
            KeyStore trustStore = ServiceReferenceHolder.getInstance().getTrustStore();
            log.info("trustStore type: "+trustStore.getType());
            if (trustStore != null) {
                // Read certificate from trust store
                cert = trustStore.getCertificate(alias);
                if(cert != null)
                	log.info("cert type: "+cert.getType());
            }
        } catch (KeyStoreException e) {
            String msg = "Error in retrieving certificate from the trust store";
            log.error(msg, e);
        }
        return cert;
    }

    private String formatUniqueIdentifier(CertAppMapping cam)
    {
    	String uniqueIdentifier = "";
    	uniqueIdentifier = cam.getSerialNumber() + "_" + cam.getIssuerDN();
        uniqueIdentifier = uniqueIdentifier.replaceAll(",", "#").replaceAll("\"", "'");
        return uniqueIdentifier;
    }
    
    private boolean validateSubscription(MessageContext synCtx, String subUUID)
    {
    	boolean isValid = false;
    	String apiContext = (String) synCtx.getProperty(RESTConstants.REST_API_CONTEXT);
        log.info("apiContext: "+apiContext);
        String apiVersion = (String) synCtx.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
        log.info("apiVersion: "+apiVersion);
        String apiTenantDomain = MultitenantUtils.getTenantDomainFromRequestURL(apiContext);
        if (apiTenantDomain == null) {
            apiTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        log.info("apiTenantDomain: "+apiTenantDomain);
        int appId = 0;
        API api = null;
        Subscription sub = null;
        Application app = null;
        SubscriptionDataStore datastore = SubscriptionDataHolder.getInstance()
                .getTenantSubscriptionStore(apiTenantDomain);
        //TODO add a check to see whether datastore is initialized an load data using rest api if it is not loaded
        if (datastore != null) {
        	app = datastore.getApplicationByUUID(subUUID);
        	if(app != null)
        	{
        	appId = app.getId();
        	log.info("appId: "+appId);
            api = datastore.getApiByContextAndVersion(apiContext, apiVersion);
            
            if (api != null) {
                sub = datastore.getSubscriptionById(appId, api.getApiId());
                log.info("apiId: "+api.getApiId());
                
                if (sub != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("All information is retrieved from the inmemory data store.");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Valid subscription not found for appId " + appId + " and apiId "
                                + api.getApiId());
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("API not found in the datastore for " + apiContext + ":" + apiVersion);
                }
            }
            
        	} else {
                if (log.isDebugEnabled()) {
                	log.debug("Valid subscription not found for appId " + appId);
                }
            }
            
        } else {
            log.error("Subscription datastore is not initialized for tenant domain " + apiTenantDomain);
        }

        if (app != null && sub != null) {
        	isValid = validate(app, sub);
        	log.info("Subscription validation result: "+isValid);
      }
        return isValid;
    }
   
    
	private AuthenticationContext generateAuthenticationContext(APIKeyValidationInfoDTO apiKeyValidationInfoDTO, String endUserToken) {

		AuthenticationContext authContext = new AuthenticationContext();
		authContext.setAuthenticated(true);
		authContext.setApiKey(endUserToken);

		if (apiKeyValidationInfoDTO != null) {
			
			//None consumer key to distinguish between production and sandbox, so a fixed value has been set
			if(apiKeyValidationInfoDTO.getType().equals("JWT"))
				apiKeyValidationInfoDTO.setType(APIConstants.API_KEY_TYPE_PRODUCTION);
			
			
			authContext.setApiTier(apiKeyValidationInfoDTO.getApiTier());
			authContext.setKeyType(apiKeyValidationInfoDTO.getType());
			authContext.setApplicationId(apiKeyValidationInfoDTO.getApplicationId());
			authContext.setApplicationUUID(apiKeyValidationInfoDTO.getApplicationUUID());
			authContext.setApplicationGroupIds(apiKeyValidationInfoDTO.getApplicationGroupIds());
			authContext.setApplicationName(apiKeyValidationInfoDTO.getApplicationName());
			authContext.setApplicationTier(apiKeyValidationInfoDTO.getApplicationTier());
			authContext.setSubscriber(apiKeyValidationInfoDTO.getSubscriber());
			authContext.setTier(apiKeyValidationInfoDTO.getTier());
			authContext.setSubscriberTenantDomain(apiKeyValidationInfoDTO.getSubscriberTenantDomain());
			authContext.setApiName(apiKeyValidationInfoDTO.getApiName());
			authContext.setApiPublisher(apiKeyValidationInfoDTO.getApiPublisher());
			authContext.setStopOnQuotaReach(apiKeyValidationInfoDTO.isStopOnQuotaReach());
			authContext.setSpikeArrestLimit(apiKeyValidationInfoDTO.getSpikeArrestLimit());
			authContext.setSpikeArrestUnit(apiKeyValidationInfoDTO.getSpikeArrestUnit());
			authContext.setConsumerKey(apiKeyValidationInfoDTO.getConsumerKey());
			authContext.setIsContentAware(apiKeyValidationInfoDTO.isContentAware());
			authContext.setGraphQLMaxDepth(apiKeyValidationInfoDTO.getGraphQLMaxDepth());
			authContext.setGraphQLMaxComplexity(apiKeyValidationInfoDTO.getGraphQLMaxComplexity());
		}
		// Set JWT token sent to the backend
		if (StringUtils.isNotEmpty(endUserToken)) {
			authContext.setCallerToken(endUserToken);
		}

		return authContext;
	}
	
	
    
    private String extractModiJWT(MessageContext mCtx, String modiHeader, Map headers) {
	        String modiJwt;
	        //check headers to get ModI JWT
	        if (headers != null) {
	        	modiJwt = (String) headers.get(modiHeader);
	            if (modiJwt != null) {
	                //Remove modi header from the request
	                headers.remove(modiHeader);
	                return modiJwt.trim();
	            }
	        }
	        return null;
	    }
    
    private String extractPdndJWT(MessageContext mCtx, String pdndHeader, Map headers) {
        String pdndJwt;
        //check headers to get ModI JWT
        if (headers != null) {
        	pdndJwt = (String) headers.get(pdndHeader);
            if (pdndJwt != null) {
                //Remove pdnd header from the request
                headers.remove(pdndHeader);
                if(pdndJwt.contains("Bearer"))
                {
                	pdndJwt = pdndJwt.replace("Bearer", "");
                	return pdndJwt.trim();
                }
            }
        }
        return null;
    }
    
    private String extractJWT(MessageContext mCtx, String headerName, Map headers) {
		 
        String jwt;

        if (headers != null) {
        	jwt = (String) headers.get(headerName);
            if (jwt != null) {
                //Remove header from the request
                headers.remove(headerName);
                return jwt.trim();
            }
        }
        return null;
    }
    
    private AuthenticationResponse SOAPValidation(MessageContext synCtx, Map headers, String soapAction, org.apache.axis2.context.MessageContext axis2MC, String apiContext, String apiVersion, boolean isValidPDNDwithSOAP, JWTInfo jwtInfo) throws WSSecurityException, KeyStoreException, IOException, SAXException, ParserConfigurationException, XMLStreamException, APISecurityException, APIManagementException, URISyntaxException
    {
    	
    	log.info("Modi Erogazione SOAP start");
    	boolean isValidSOAP = false, isSubscriptionValidForPdnd = false;
		if(!isValidPDNDwithSOAP)
    	{
    		log.error("PDND enabled but jwt validation failed");
			throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
    	}
		String originalContentType = (String) headers.get("OriginalContentType");
		log.info("soapAction: "+soapAction);
		String originalPayload = SOAPUtil.getOriginalPayload(axis2MC);
		
		int index = 0;
		String certificate = "", referenceType = "";
		String[] keyIdentifiersList = new String[] {"", ""};
		X509Certificate x509certificate = null;
		List<Pair<String, String>> certificateReference = SOAPUtil.getCertificateReference(originalPayload);
		for(Pair<String, String> ref : certificateReference)
		{
			certificate = ref.getValue();
			keyIdentifiersList[index] = certificate;
			referenceType = ref.getKey();
			log.info("Certificate reference: " + referenceType + " " + certificate);
			index++;
		}
		if(referenceType.equals("BinarySecurityToken") || referenceType.equals("X509KeyIdentifier"))
			x509certificate = ValidateSOAPMessage.validate(originalPayload, certificate);
		else
		{	
			CertAppMapping cam = new SubscriptionService().getCertificateSOAP(keyIdentifiersList[0].replaceAll("\\s", ""), keyIdentifiersList[1].replaceAll("\\s", ""));
			x509certificate = ValidateSOAPMessage.validate(originalPayload, SOAPUtil.extractCertificateAsLinearizedString(cam.getCertificate()));
		}
		
		 if (originalContentType != null && originalContentType.indexOf("application/soap+xml") > -1)
		 {
			axis2MC.setProperty(Constants.Configuration.CONTENT_TYPE, "application/soap+xml" + "; action=\"" + soapAction+ "\"");
			axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml" + "; action=\"" + soapAction+ "\"");
			log.info("SOAP 1.2");
		 }
		 else if (originalContentType != null && originalContentType.indexOf("text/xml") > -1)
		 {
			axis2MC.setProperty(Constants.Configuration.CONTENT_TYPE, "text/xml" + "; action=\"" + soapAction+ "\"");
			axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "text/xml" + "; action=\"" + soapAction+ "\"");
			log.info("SOAP 1.1");
		 }
		 else
		 {
			axis2MC.setProperty(Constants.Configuration.CONTENT_TYPE, "text/xml" + "; action=\"" + soapAction+ "\"");
			axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "text/xml" + "; action=\"" + soapAction+ "\"");
			log.info("Default SOAP version");
		 }
		
		
		APIKeyValidationInfoDTO apiKeyValidationInfoDTO = null;
		if (apiKeyValidator == null) {
            this.apiKeyValidator = new APIKeyValidator();
        }
        String apiTenantDomain = MultitenantUtils.getTenantDomainFromRequestURL(apiContext);
        if (apiTenantDomain == null) {
            apiTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        
        int appId = 0;
        API api = null;
        String subUUID = "";
        SubscriptionDataStore datastore = SubscriptionDataHolder.getInstance()
                .getTenantSubscriptionStore(apiTenantDomain);
        if (datastore != null) {
        	api = datastore.getApiByContextAndVersion(apiContext, apiVersion);
        	if (api != null) {
        		List<Subscription> subscriptions = datastore.getSubscriptionsByAPIId(api.getApiId());
        		for(Subscription s : subscriptions)
                {
                	subUUID = s.getApplicationUUID();
                	log.info("appUUID: "+subUUID);
                	appId = s.getAppId();
                	if(appId != 0)
        			{
            		//validate subscription
            		apiKeyValidationInfoDTO = getApiKeyValidator().validateSubscription(apiContext, apiVersion, appId, apiTenantDomain);
            		//end validate
            		if(apiKeyValidationInfoDTO != null && apiKeyValidationInfoDTO.isAuthorized())
            		{
            			CertAppMapping camForPDND = null, cam = null;
							cam = new SubscriptionService().getCertificatesSOAPInboundModi(subUUID);
							if(jwtInfo.getPdndPublicKey() != null)
								camForPDND = new SubscriptionService().getCertificatesInboundModi(subUUID);
            			
                		apiKeyValidationInfoDTO = validateCertAppMappingPdnd(camForPDND, jwtInfo, apiKeyValidationInfoDTO, datastore, apiContext, apiVersion, appId, s);
                		isSubscriptionValidForPdnd = apiKeyValidationInfoDTO.isAuthorized();
                    	apiKeyValidationInfoDTO = validateCertAppMappingSOAP(cam, apiKeyValidationInfoDTO, x509certificate);
                    	if(isValidSOAP = (apiKeyValidationInfoDTO.isAuthorized() && isSubscriptionValidForPdnd))
                    		break;
            		}
        			}
                }
        	}
        	else
        	{
        		if (log.isDebugEnabled()) {
                    log.debug("API not found in the datastore for " + apiContext + ":" + apiVersion);
                }
        	}
        	
        }
        else {
            log.error("Subscription datastore is not initialized for tenant domain " + apiTenantDomain);
        }
		log.info("Modi Erogazione SOAP end");
		if(isValidSOAP)
		{
			AuthenticationContext authenticationContext = null;
			authenticationContext = generateAuthenticationContext(apiKeyValidationInfoDTO, "");
            APISecurityUtils.setAuthenticationContext(synCtx, authenticationContext);
			log.info("Valid SOAP signature. Authentication successful");
			return new AuthenticationResponse(true, true, false, 0, null);
		}
		else if(apiKeyValidationInfoDTO == null || (apiKeyValidationInfoDTO.getValidationStatus() == APIConstants.KeyValidationStatus.SUBSCRIPTION_INACTIVE))
		{
			log.info("SOAP subscription validation failed");
			return new AuthenticationResponse(false, true,
                    false, APISecurityConstants.SUBSCRIPTION_INACTIVE,
                    APISecurityConstants.SUBSCRIPTION_INACTIVE_MESSAGE);
		}
		else if(apiKeyValidationInfoDTO != null && (apiKeyValidationInfoDTO.getValidationStatus() == APIConstants.KeyValidationStatus.API_BLOCKED))
		{
			log.info("SOAP subscription validation failed");
			return new AuthenticationResponse(false, true,
                    false, APISecurityConstants.API_BLOCKED,
                    APISecurityConstants.API_BLOCKED_MESSAGE);
		}
		else
		{
			log.error("SOAP cert app mapping validation failed");
			throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
		}
    }
    
    
    private String printFields(Object classObject)
    {
    	return ToStringBuilder.reflectionToString(classObject);
    }
    
	private boolean validate(Application app, Subscription sub) {
		boolean isValid = false;
		String subscriptionStatus = sub.getSubscriptionState();
		String type = app.getTokenType();
		log.info("Token type: "+type);
		if (APIConstants.SubscriptionStatus.BLOCKED.equals(subscriptionStatus)) {
			isValid = false;
			/*infoDTO.setValidationStatus(APIConstants.KeyValidationStatus.API_BLOCKED);
			infoDTO.setAuthorized(false);
			return infoDTO;*/
		} else if (APIConstants.SubscriptionStatus.ON_HOLD.equals(subscriptionStatus)
				|| APIConstants.SubscriptionStatus.REJECTED.equals(subscriptionStatus)) {
			isValid = false;
			/*infoDTO.setValidationStatus(APIConstants.KeyValidationStatus.SUBSCRIPTION_INACTIVE);
			infoDTO.setAuthorized(false);
			return infoDTO;*/
		} else if (APIConstants.SubscriptionStatus.PROD_ONLY_BLOCKED.equals(subscriptionStatus)
				&& !APIConstants.API_KEY_TYPE_SANDBOX.equals(type)) {
			isValid = false;
			/*infoDTO.setValidationStatus(APIConstants.KeyValidationStatus.API_BLOCKED);
			infoDTO.setType(type);
			infoDTO.setAuthorized(false);
			return infoDTO;*/
		}
		else
			isValid = true;
		return isValid;
		/*infoDTO.setTier(sub.getPolicyId());
		infoDTO.setSubscriber(app.getSubName());
		infoDTO.setApplicationId(app.getId().toString());
		infoDTO.setApiName(api.getApiName());
		infoDTO.setApiVersion(api.getApiVersion());
		infoDTO.setApiPublisher(api.getApiProvider());
		infoDTO.setApplicationName(app.getName());
		infoDTO.setApplicationTier(app.getPolicy());
		infoDTO.setApplicationUUID(app.getUUID());
		infoDTO.setApplicationGroupIds(app.getGroupIds().stream().map(GroupId::getGroupId).collect(Collectors.toSet()));
		infoDTO.setAppAttributes(app.getAttributes());
		infoDTO.setType(type);

		// Advanced Level Throttling Related Properties
		String apiTier = api.getApiTier();

		String subscriberTenant = MultitenantUtils.getTenantDomain(app.getSubName());

		ApplicationPolicy appPolicy = datastore.getApplicationPolicyByName(app.getPolicy(), tenantId);
		if (appPolicy == null) {
			try {
				appPolicy = new SubscriptionDataLoaderImpl().getApplicationPolicy(app.getPolicy(), apiTenantDomain);
				datastore.addOrUpdateApplicationPolicy(appPolicy);
			} catch (DataLoadingException e) {
				log.error("Error while loading ApplicationPolicy");
			}
		}
		SubscriptionPolicy subPolicy = datastore.getSubscriptionPolicyByName(sub.getPolicyId(), tenantId);
		if (subPolicy == null) {
			try {
				subPolicy = new SubscriptionDataLoaderImpl().getSubscriptionPolicy(sub.getPolicyId(), apiTenantDomain);
				datastore.addOrUpdateSubscriptionPolicy(subPolicy);
			} catch (DataLoadingException e) {
				log.error("Error while loading SubscriptionPolicy");
			}
		}
		ApiPolicy apiPolicy = datastore.getApiPolicyByName(api.getApiTier(), tenantId);

		boolean isContentAware = false;
		int spikeArrest = 0;
		String spikeArrestUnit = null;
		boolean stopOnQuotaReach = false;
		int graphQLMaxDepth = 0;
		int graphQLMaxComplexity = 0;

		if (appPolicy != null && subPolicy != null) {
			if (appPolicy.isContentAware() || subPolicy.isContentAware()
					|| (apiPolicy != null && apiPolicy.isContentAware())) {
				isContentAware = true;
			}
			if (subPolicy.getRateLimitCount() > 0) {
				spikeArrest = subPolicy.getRateLimitCount();
			}
			if (subPolicy.getRateLimitTimeUnit() != null) {
				spikeArrestUnit = subPolicy.getRateLimitTimeUnit();
			}
			stopOnQuotaReach = subPolicy.isStopOnQuotaReach();
			if (subPolicy.getGraphQLMaxDepth() > 0) {
				graphQLMaxDepth = subPolicy.getGraphQLMaxDepth();
			}
			if (subPolicy.getGraphQLMaxComplexity() > 0) {
				graphQLMaxComplexity = subPolicy.getGraphQLMaxComplexity();
			}
		}
		infoDTO.setContentAware(isContentAware);

		// TODO this must implement as a part of throttling implementation.
		String apiLevelThrottlingKey = "api_level_throttling_key";

		List<String> list = new ArrayList<>();
		list.add(apiLevelThrottlingKey);
		infoDTO.setSpikeArrestLimit(spikeArrest);
		infoDTO.setSpikeArrestUnit(spikeArrestUnit);
		infoDTO.setStopOnQuotaReach(stopOnQuotaReach);
		infoDTO.setSubscriberTenantDomain(subscriberTenant);
		infoDTO.setGraphQLMaxDepth(graphQLMaxDepth);
		infoDTO.setGraphQLMaxComplexity(graphQLMaxComplexity);
		if (apiTier != null && apiTier.trim().length() > 0) {
			infoDTO.setApiTier(apiTier);
		}
		// We also need to set throttling data list associated with given API. This need
		// to have
		// policy id and
		// condition id list for all throttling tiers associated with this API.
		infoDTO.setThrottlingDataList(list);
		infoDTO.setAuthorized(true);
		return infoDTO;*/
	}
	
	private void automaticAuthentication(MessageContext messageContext, String apiTier){

        //Using existing constant in Message context removing the additional constant in API Constants
        String clientIP = null;
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        Map<String, String> transportHeaderMap = (Map<String, String>)
                axis2MessageContext.getProperty
                        (org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        if (transportHeaderMap != null) {
            clientIP = transportHeaderMap.get(APIMgtGatewayConstants.X_FORWARDED_FOR);
        }

        //Setting IP of the client
        if (clientIP != null && !clientIP.isEmpty()) {
            if (clientIP.indexOf(",") > 0) {
                clientIP = clientIP.substring(0, clientIP.indexOf(","));
            }
        } else {
            clientIP = (String) axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        }

        //Create a dummy AuthenticationContext object with hard coded values for Tier and KeyType. This is because we cannot determine the Tier nor Key Type without subscription information..
        AuthenticationContext authContext = new AuthenticationContext();
        authContext.setAuthenticated(true);
        authContext.setTier(APIConstants.UNAUTHENTICATED_TIER);
        //Since we don't have details on unauthenticated tier we setting stop on quota reach true
        authContext.setStopOnQuotaReach(true);
        //Requests are throttled by the ApiKey that is set here. In an unauthenticated scenario, we will use the client's IP address for throttling.
        authContext.setApiKey(clientIP);
        authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
        //This name is hardcoded as anonymous because there is no associated user token
        authContext.setUsername(APIConstants.END_USER_ANONYMOUS);
        authContext.setCallerToken(null);
        authContext.setApplicationName(null);
        authContext.setApplicationId(clientIP); //Set clientIp as application ID in unauthenticated scenario
        authContext.setConsumerKey(null);
        authContext.setApiTier(apiTier);
        APISecurityUtils.setAuthenticationContext(messageContext, authContext);
    }



    //first level cache
    private Cache getGatewayInternalKeyCache() {

        return CacheProvider.getGatewayInternalKeyCache();
    }

    private Cache getInvalidGatewayInternalKeyCache() {

        return CacheProvider.getInvalidGatewayInternalKeyCache();
    }

    //second level cache
    private Cache getGatewayInternalKeyDataCache() {

        return CacheProvider.getGatewayInternalKeyDataCache();
    }


    @Override
    public String getChallengeString() {

        return "Internal API Key realm=\"WSO2 API Manager\"";
    }

    @Override
    public String getRequestOrigin() {

        return null;
    }

    @Override
    public int getPriority() {

        return -10;
    }
    
}
