package it.profesia.carbon.apimgt.gateway.handlers.modi;

import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Map;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.rest.RESTConstants;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.keymgt.SubscriptionDataHolder;
import org.wso2.carbon.apimgt.keymgt.model.SubscriptionDataStore;
import org.wso2.carbon.apimgt.keymgt.model.entity.API;
import org.wso2.carbon.apimgt.keymgt.model.entity.Application;
import org.wso2.carbon.apimgt.keymgt.model.entity.Subscription;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import com.nimbusds.jwt.SignedJWT;

import it.profesia.carbon.apimgt.gateway.handlers.logging.ModiLogUtils;
import it.profesia.carbon.apimgt.gateway.handlers.utils.SOAPUtil;
import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;
import net.minidev.json.JSONObject;

public class InitializeModiHandler extends AbstractHandler {

	private static final Log log = LogFactory.getLog(InitializeModiHandler.class);

    private String modi_fruizione;
    private String pdnd_fruizione;
    private String audit_rest_01_pdnd;
    private String audit_rest_01_modi;
    private String audit_rest_02;

	public String getAudit_rest_02() {
		return audit_rest_02;
	}

	public void setAudit_rest_02(String audit_rest_02) {
		this.audit_rest_02 = audit_rest_02;
	}
    
    public String getAudit_rest_01_pdnd() {
		return audit_rest_01_pdnd;
	}

	public void setAudit_rest_01_pdnd(String audit_rest_01_pdnd) {
		this.audit_rest_01_pdnd = audit_rest_01_pdnd;
	}

	public String getAudit_rest_01_modi() {
		return audit_rest_01_modi;
	}

	public void setAudit_rest_01_modi(String audit_rest_01_modi) {
		this.audit_rest_01_modi = audit_rest_01_modi;
	}

	public String getModi_fruizione() {
		return modi_fruizione;
	}

	public void setModi_fruizione(String modi_fruizione) {
		this.modi_fruizione = modi_fruizione;
	}

	public String getPdnd_fruizione() {
		return pdnd_fruizione;
	}

	public void setPdnd_fruizione(String pdnd_fruizione) {
		this.pdnd_fruizione = pdnd_fruizione;
	}

	@Override
	public boolean handleRequest(MessageContext messageContext) {
		boolean handleReturn = true;

		ModiLogUtils.initialize(messageContext);
		log.info(ModiLogUtils.FRUIZIONE_INIT_START);

		try {
			String appUUID = "", apiContext = "", apiVersion = "", apiTenantDomain = "";
			SubscriptionDataStore datastore = null;
			PdndPKMapping pdndPK = null;
			org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
			Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));
			log.debug("InitializeModi\n  PDND Fruizione: " + getPdnd_fruizione() + "\n  ModI Fruizione: " + getModi_fruizione());
			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getPdnd_fruizione())) || BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getModi_fruizione()))) {
				log.trace("weModI context: " + axis2MC);
	
				String authorization = (String)headers.get("Authorization");
                if (StringUtils.isBlank(authorization)) {
                    log.error("Non è stato fornito un header Authroization valido.");
                    return false;
                }
				SignedJWT jwt = SignedJWT.parse(authorization.replace("Bearer ", ""));
				appUUID = jwt.getPayload().toJSONObject().get("azp").toString();
				log.debug("weModI subscription: " + appUUID);
				
				apiContext = (String) messageContext.getProperty(RESTConstants.REST_API_CONTEXT);
	            log.info("apiContext: "+apiContext);
	            apiVersion = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
	            log.info("apiVersion: "+apiVersion);
	            apiTenantDomain = MultitenantUtils.getTenantDomainFromRequestURL(apiContext);
                if (apiTenantDomain == null) {
                    apiTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                }
                datastore = SubscriptionDataHolder.getInstance()
                        .getTenantSubscriptionStore(apiTenantDomain);
			}

			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getPdnd_fruizione()))
					|| BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_pdnd()))) {
				log.info(ModiLogUtils.PDND_INIT_METADATA_START);
				PdndPKMapping pdndPKMapping = new SubscriptionService().getPrivateKeyByConsumerKeyForPdnd(appUUID);
				String applicationUUID = pdndPKMapping.getApplicationUUID();
				log.info("applicationUUID: "+applicationUUID);
				
				//Retrieve subscription for purpose id
				String purposeId = "";
				pdndPK = retrieveSubscription(apiContext, apiVersion, apiTenantDomain, datastore, applicationUUID);
				purposeId = pdndPK.getPurposeId();
				log.info("purposeId: "+purposeId);
				//end

				JSONObject pdndMetadata = new JSONObject();

				pdndMetadata.put("alg", pdndPKMapping.getAlg());
				pdndMetadata.put("aud", pdndPKMapping.getAud());
				pdndMetadata.put("iss", pdndPKMapping.getIss());
				pdndMetadata.put("kid", pdndPKMapping.getKid());
				pdndMetadata.put("privateKey", pdndPKMapping.getPrivkey());
				pdndMetadata.put("purposeId", purposeId);
				pdndMetadata.put("sub", pdndPKMapping.getSub());
				pdndMetadata.put("typ", pdndPKMapping.getTyp());
				pdndMetadata.put("uri", pdndPKMapping.getUri());
				pdndMetadata.put("clientId", pdndPKMapping.getClientId());
				pdndMetadata.put("scope", pdndPKMapping.getScope());

				messageContext.setProperty("pdndMetadata", pdndMetadata.toJSONString());
				if (log.isDebugEnabled())
					log.debug(ModiLogUtils.PDND_INIT_METADATA_FINISH + "\n\t" + pdndMetadata.toJSONString());
				else
					log.info(ModiLogUtils.PDND_INIT_METADATA_FINISH);
			}

			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getModi_fruizione()))
					|| BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_pdnd()))
					|| BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_modi()))
					|| BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_02()))) {
				log.info(ModiLogUtils.MODI_INIT_METADATA_START);
				
				//Initialize SOAP
				String contentType = ((contentType = (String) headers.get(HttpHeaders.CONTENT_TYPE)) != null) ? contentType : "text/xml";
				log.info("contentType: "+contentType);
				String actionFromContentType = SOAPUtil.extractSOAPAction(contentType);
				String soapAction = (String) headers.get("SOAPAction");
				if((actionFromContentType != null && !(actionFromContentType.equals(""))) || (soapAction != null && !(soapAction.equals(""))))
				{
					log.info("actionFromContentType: "+actionFromContentType);
					if(!(actionFromContentType.equals("")))
						headers.put("SOAPAction", actionFromContentType);
					log.info("soapAction: "+soapAction);
					headers.put("OriginalContentType", contentType);
					ModiPKMapping modiPkMappingSOAP = new SubscriptionService().getPrivateKeyByConsumerKeySOAP(appUUID);
					JSONObject modiMetadata = new JSONObject();
					modiMetadata.put("certificate", modiPkMappingSOAP.getCertificate());
					modiMetadata.put("privkey", modiPkMappingSOAP.getPrivkey());
					modiMetadata.put("enabled", modiPkMappingSOAP.isEnabled());
					modiMetadata.put("To", modiPkMappingSOAP.getWsaddressingTo());
					messageContext.setProperty("modiMetadataSOAP", modiMetadata.toJSONString());
				}
				else
				{					
					ModiPKMapping modiPkMapping = new SubscriptionService().getPrivateKeyByConsumerKeyForModi(appUUID);
					//Retrieve subscription for aud
					String subscriptionAud = "";
					if(pdndPK == null)
					{
						String applicationUUID = modiPkMapping.getApplicationUUID();
						log.info("applicationUUID: "+applicationUUID);
		    			pdndPK = retrieveSubscription(apiContext, apiVersion, apiTenantDomain, datastore, applicationUUID);
					}
					if(pdndPK != null)
						subscriptionAud = pdndPK.getAud();
	    			log.info("subscriptionAud: "+subscriptionAud);
			        //end
					
					JSONObject modiMetadata = new JSONObject();
					modiMetadata.put("alg", modiPkMapping.getAlg());
					if(subscriptionAud != null && !(subscriptionAud.equals("")))
						modiMetadata.put("aud", subscriptionAud);
					else
						modiMetadata.put("aud", modiPkMapping.getAud());
					modiMetadata.put("certificate", modiPkMapping.getCertificate());
					modiMetadata.put("iss", modiPkMapping.getIss());
					modiMetadata.put("kid", modiPkMapping.getKid());
					modiMetadata.put("privkey", modiPkMapping.getPrivkey());
					modiMetadata.put("publickey", modiPkMapping.getPublickey());
					modiMetadata.put("sub", modiPkMapping.getSub());
					modiMetadata.put("typ", modiPkMapping.getTyp());
					modiMetadata.put("enabled", modiPkMapping.isEnabled());

					messageContext.setProperty("modiMetadata", modiMetadata.toJSONString());
					if (log.isDebugEnabled())
						log.debug(ModiLogUtils.MODI_INIT_METADATA_FINISH + "\n\t" + modiMetadata.toJSONString());
					else
						log.info(ModiLogUtils.MODI_INIT_METADATA_FINISH);
				}
			}
		} catch (ParseException | URISyntaxException e) {
			log.error("Impossibile recuperare la subscription weModI: " + ExceptionUtils.getStackTrace(e));
			handleReturn = false;
		} catch (APIManagementException e) {
			log.error("Impossibile recuperare il Purpose Id " + ExceptionUtils.getStackTrace(e));
			handleReturn = false;
		} catch (Exception e) {
			log.error("Errore generico: " + ExceptionUtils.getStackTrace(e));
			handleReturn = false;
		}
		finally {
			log.info(ModiLogUtils.FRUIZIONE_INIT_FINISH);
			ModiLogUtils.release();
		}
		return handleReturn;
	}

	@Override
	public boolean handleResponse(MessageContext messageContext) {
		// TODO Auto-generated method stub
		return true;
	}
	
	private PdndPKMapping retrieveSubscription(String apiContext, String apiVersion, String apiTenantDomain, SubscriptionDataStore datastore, String applicationUUID) throws APIManagementException, URISyntaxException
	{
		int appId = 0, apiId = 0;
		PdndPKMapping pdndPK = null;
		if (datastore != null) {
        	Application app = datastore.getApplicationByUUID(applicationUUID);
        	if(app != null)
        	{
        		appId = app.getId();
        		if(appId != 0)
    			{
        			API api = datastore.getApiByContextAndVersion(apiContext, apiVersion);
        			if(api != null)
        			{
        				apiId = api.getApiId();
        				Subscription subscription = datastore.getSubscriptionById(appId, apiId);
        				String subscriptionUUID = subscription.getSubscriptionUUId();
        				log.info("subscriptionUUID: "+subscriptionUUID);
        				pdndPK = new SubscriptionService().getSubscriptionDetails(subscriptionUUID);
        			}
        			else {
                        if (log.isDebugEnabled()) {
                            log.debug("API not found in the datastore for " + apiContext + ":" + apiVersion);
                        }
                    }
    			}
        		else {
                    if (log.isDebugEnabled()) {
                    	log.debug("appId: " + appId + " not found");
                    }
                }
        	}
        	else {
                if (log.isDebugEnabled()) {
                	log.debug("Application not found for " + applicationUUID);
                }
            }
        }
        else {
            log.error("Subscription datastore is not initialized for tenant domain " + apiTenantDomain);
        }
        return pdndPK;
	}

}
