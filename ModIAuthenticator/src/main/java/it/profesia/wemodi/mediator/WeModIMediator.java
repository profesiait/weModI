package it.profesia.wemodi.mediator;

import java.net.URISyntaxException;
import java.util.Map;

import javax.cache.Cache;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.Constants;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.keymgt.model.entity.API;
import org.wso2.carbon.base.MultitenantConstants;

import it.profesia.carbon.apimgt.gateway.handlers.logging.ModiLogUtils;
import it.profesia.carbon.apimgt.gateway.handlers.modi.soap.CustomSOAPBuilder;
import it.profesia.carbon.apimgt.gateway.handlers.utils.CacheProviderWeModi;
import it.profesia.wemodi.ApiConfig;
import it.profesia.wemodi.providers.jwt.JWSAuditProvider;
import it.profesia.wemodi.providers.jwt.JWTTokenModIProvider;
import it.profesia.wemodi.providers.jwt.JWTTokenPDNDProvider;
import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;
import it.profesia.wemodi.utils.WeModIContextHelper;
import net.minidev.json.JSONObject;

/**
 * Mediatore per l'autenticazione degli endpoint ModI/PDND in fase di fruizione
 */
public class WeModIMediator extends AbstractMediator implements ManagedLifecycle {

	private String customParameters;
	private ApiConfig apiConfig;

	@Override
	public boolean mediate(MessageContext synCtx) {
		ModiLogUtils.initialize(synCtx);
		log.info(ModiLogUtils.FRUIZIONE_START);
		log.info("Mediate method");
		JSONObject customClaims = null;
		String apiTenantDomain, jwsAuditToken = null, purposeId = "", digest;

		try {
            org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) synCtx).getAxis2MessageContext();
            Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));
            WeModIContextHelper weModIContextHelper = new WeModIContextHelper(axis2MC);
            customClaims = weModIContextHelper.getAdditionalData();

            apiTenantDomain = (String) synCtx.getProperty("tenant.info.domain");
            if (apiTenantDomain == null || apiTenantDomain.equals("")) {
                apiTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            String consumerKey = (String) synCtx.getProperty("api.ut.consumerKey");
            log.debug("consumerKey: " + consumerKey);
            
            int applicationIdFromContext = Integer.parseInt((String)synCtx.getProperty("api.ut.application.id"));
    		log.info("applicationIdFromContext: " + applicationIdFromContext);
    		API apiFromContext = (API)synCtx.getProperty("API");
    		int apiIdFromContext = apiFromContext.getApiId();
    		log.info("apiIdFromContext: " + apiIdFromContext);

            PdndPKMapping pdndPK = null;
            String pdndPKCacheKey = new String(applicationIdFromContext + ":").concat(apiIdFromContext + "@").concat(apiTenantDomain);
            if (getWeModiCacheEnable()) {
                Object cached = getWeModiCache().get(pdndPKCacheKey);
                if (cached != null) {
                    pdndPK = (PdndPKMapping)cached;
                }
            }

            if (pdndPK == null) {
                pdndPK = new SubscriptionService().getSubscriptionDetails(applicationIdFromContext, apiIdFromContext, apiTenantDomain);
                if (getWeModiCacheEnable()) {
                    getWeModiCache().put(pdndPKCacheKey, pdndPK);
                }
            }

            if (headers.containsKey("PDND-purpose-Id")) {
                purposeId = (String) headers.get("PDND-purpose-Id");
                log.info("Purpose ID nell'header della richiesta: " + purposeId);
            } else if (pdndPK != null) {
                purposeId = pdndPK.getPurposeId();
            }
            log.debug("purposeId: "+purposeId);
            
            //Retrieve subscription for aud
            String subscriptionAud = "";
            if(pdndPK != null)
                subscriptionAud = pdndPK.getAud();
            log.info("subscriptionAud: "+subscriptionAud);
            //end

            if (apiConfig.isJwsAudit()) {
                JWSAuditProvider jwsAuditProvider = null;
                String cacheKey = "jwsAuditProvider:" + consumerKey;
                if (getWeModiCacheEnable()) {
                    Object cached = getWeModiCache().get(cacheKey);
                    if (cached != null) {
                        jwsAuditProvider = (JWSAuditProvider)cached;
                    }
                }
                if (jwsAuditProvider == null) {
                    jwsAuditProvider = JWSAuditProvider.FromConsumerKey(consumerKey);
                    if (getWeModiCacheEnable()) {
                        getWeModiCache().put(cacheKey, jwsAuditProvider);
                    }
                }
                jwsAuditProvider.setIsAuditRest02(apiConfig.isAuditRest02());
                jwsAuditProvider.setIsAuditRest01Modi(apiConfig.isAuditRest01Modi());
                jwsAuditProvider.setIsAuditRest01Pdnd(apiConfig.isAuditRest01Pdnd());
                jwsAuditProvider.setCustomClaims(customClaims);
                jwsAuditProvider.setCertificateReference(apiConfig.getCertificateReference());
                jwsAuditProvider.setPurposeId(purposeId);
                
                if(StringUtils.isNotBlank(subscriptionAud))
                	jwsAuditProvider.getModiPKMapping().setAud(subscriptionAud);
                
                jwsAuditToken = jwsAuditProvider.provideJWSAudit();
                headers.put(apiConfig.getTrackingEvidenceTokenName(), jwsAuditToken);
            }

            if (apiConfig.isPdndAuth()) {
                // Richiesta del voucher PDND
                try {
                    JWTTokenPDNDProvider jwtTokenPDNDProvider = null;
                    String cacheKey = "jwtTokenPDNDProvider:" + consumerKey;

                    if (getWeModiCacheEnable()) {
                        Object cached = getWeModiCache().get(cacheKey);
                        if (cached != null) {
                            jwtTokenPDNDProvider = (JWTTokenPDNDProvider)cached;
                        }
                    }
                    if (jwtTokenPDNDProvider == null) {
                        jwtTokenPDNDProvider = JWTTokenPDNDProvider.FromConsumerKey(consumerKey);
                        if (getWeModiCacheEnable()) {
                            getWeModiCache().put(cacheKey, jwtTokenPDNDProvider);
                        }
                    }

                    if(apiConfig.isAuditRest02())
                        jwtTokenPDNDProvider.setJwsAudit(jwsAuditToken);

                    jwtTokenPDNDProvider.setPurposeId(purposeId);
                    String pdndAccessToken = jwtTokenPDNDProvider.PDNDJwtAssertion();
                    headers.put("Authorization", "Bearer " + pdndAccessToken);
				
                } catch (APIManagementException | OAuthSystemException | URISyntaxException e) {
                    log.error("Impossibile recuperare le informazioni per il token PDND.", e);
                    return false;
                }
		    }
            if (apiConfig.isIdAuthRest01() || apiConfig.isIdAuthRest02() ||
                    apiConfig.isIntegrityRest01() || apiConfig.isIntegrityRest02()) {
                try {
                    JWTTokenModIProvider jwtTokenModIProvider = null;
                    String cacheKey = "jwtTokenModIProvider:" + consumerKey;
                    if (getWeModiCacheEnable()) {
                        Object cached = getWeModiCache().get(cacheKey);
                        if (cached != null) {
                            jwtTokenModIProvider = (JWTTokenModIProvider)cached;
                        }
                    }
                    if (jwtTokenModIProvider == null) {
                    	jwtTokenModIProvider = JWTTokenModIProvider.FromConsumerKey(consumerKey);
                        if (getWeModiCacheEnable()) {
                            getWeModiCache().put(cacheKey, jwtTokenModIProvider);
                        }
                    }
                    jwtTokenModIProvider.setIsIdAuthRest02(apiConfig.isIdAuthRest02());
                    jwtTokenModIProvider.setIsIntegrityRest01(apiConfig.isIntegrityRest01());
                    jwtTokenModIProvider.setIsIntegrityRest02(apiConfig.isIntegrityRest02());
                    jwtTokenModIProvider.setCertificateReference(apiConfig.getCertificateReference());
                    
                    if(StringUtils.isNotBlank(subscriptionAud))
                        jwtTokenModIProvider.getModiPKMapping().setAud(subscriptionAud);
                    
                    if (apiConfig.isIntegrityRest01() || apiConfig.isIntegrityRest02()) {
                        digest = weModIContextHelper.digestPayload();
                        jwtTokenModIProvider.setSha256Base64Digest(digest);
                        jwtTokenModIProvider.setHeaders(headers);
                    }
                    String modiToken = jwtTokenModIProvider.provideModi();
                    String modiTokenHeaderName = apiConfig.getModiTokenName();
                    headers.put(modiTokenHeaderName, modiToken);
				
                } catch (APIManagementException | OAuthSystemException | URISyntaxException e) {
                    log.error("Impossibile recuperare le informazioni per il token ModI.", e);
                    return false;
                }
            }
            if (apiConfig.isIdAuthSoap01() || apiConfig.isIdAuthSoap02()) {
                ModiPKMapping modiPkMappingSOAP = new SubscriptionService().getPrivateKeyByConsumerKeySOAP(consumerKey);
                
                CustomSOAPBuilder customSOAPBuilder = new CustomSOAPBuilder();
                String contentType = ((contentType = (String) headers.get(HttpHeaders.CONTENT_TYPE)) != null) ? contentType : "text/xml";
                // TODO: valutare l'utilizzo della classe org.apache.axis2.builder.SOAPBuilder
                SOAPEnvelope soapEnvelope = (SOAPEnvelope) customSOAPBuilder.processDocument(weModIContextHelper.createSoapPayloadAsStream(modiPkMappingSOAP, apiConfig), contentType, axis2MC);
                axis2MC.setEnvelope(soapEnvelope);
                axis2MC.setProperty(Constants.Configuration.CONTENT_TYPE, "application/xml");
                axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/xml");

            }
		} catch (Exception e) {
			log.error("Mediation failed", e);
			return false;
		}
		finally {
			log.info(ModiLogUtils.FRUIZIONE_FINISH);
			ModiLogUtils.release();
		}

		return true;
	}

	@Override
	public void init(SynapseEnvironment se) {
		log.info("Init method - " + customParameters);
		if (StringUtils.isNotEmpty(customParameters)) {
			apiConfig = new ApiConfig(customParameters);
		}
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

	public String getCustomParameters() {
		return customParameters;
	}

	public void setCustomParameters(String customParameters) {
		this.customParameters = customParameters;
	}

    private static Cache getWeModiCache() {
        return CacheProviderWeModi.getWeModiCache();
    }

    private static boolean getWeModiCacheEnable() {
        return CacheProviderWeModi.isEnabledCache();
    }

}
