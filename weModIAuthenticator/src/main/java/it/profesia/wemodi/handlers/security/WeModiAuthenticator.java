package it.profesia.wemodi.handlers.security;

import java.text.ParseException;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.RESTConstants;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationResponse;
import org.wso2.carbon.apimgt.gateway.handlers.security.Authenticator;
import org.wso2.carbon.apimgt.gateway.utils.GatewayUtils;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.model.entity.API;

import com.google.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.profesia.wemodi.ApiConfig;
import net.minidev.json.JSONObject;

/**
 * Authenticator per la validazione dei JWT e Voucher ModI/PDND, richiede
 * l'implementazione
 * weModI as Key Manager per la validazione del voucher PDND
 */
public class WeModiAuthenticator implements Authenticator {
    private static final Log log = LogFactory.getLog(WeModiAuthenticator.class);

    public WeModiAuthenticator() {
    }

    @Override
    public void init(SynapseEnvironment env) {
        // TODO Auto-generated method stub

    }

    @Override
    public void destroy() {

    }


    @Override
    public AuthenticationResponse authenticate(MessageContext synCtx) throws APIManagementException {
        boolean isMandatory = true;
        boolean pdndAuth = false, modiAuth = false, jwsAuditAuth = false;
        String trackingEvidenceToken = "", pdndToken = "", modiToken = "";
        JWTClaimsSet payload;
        SignedJWT signedJWT;
        String tokenIdentifier = "";
        
        API retrievedApi = GatewayUtils.getAPI(synCtx);
        
        String apiContext = (String) synCtx.getProperty(RESTConstants.REST_API_CONTEXT);
        log.info("apiContext: "+apiContext);
    
        try {
        	String serverUrl = "", aud = "";
        	serverUrl = APIUtil.getServerURL();
        	log.info("serverUrl: "+serverUrl);
        	aud = serverUrl+apiContext;
            log.info("aud: "+aud);
            
            org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) synCtx).getAxis2MessageContext();
            Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));
            ApiConfig weModiApiConfig = new Gson().fromJson((String) headers.get("weModI_API_Config"), ApiConfig.class);
            
            if(StringUtils.isBlank(weModiApiConfig.getAud()))
            	weModiApiConfig.setAud(aud);
            
            WeModiJWTValidator weModiJWTValidator = new WeModiJWTValidator(weModiApiConfig);
            
            if (weModiApiConfig.isAuditRest01Modi() || weModiApiConfig.isAuditRest01Pdnd() || weModiApiConfig.isAuditRest02()) {
                trackingEvidenceToken = extractJWT(weModiApiConfig.getTrackingEvidenceTokenName(), headers);
                jwsAuditAuth = weModiJWTValidator.validateModIJWTTrackingEvidence(trackingEvidenceToken, headers);
            }
            else
            	jwsAuditAuth = true;
            
            if (weModiApiConfig.isIdAuthRest01() || weModiApiConfig.isIdAuthRest02() ||
            		weModiApiConfig.isIntegrityRest01() || weModiApiConfig.isIntegrityRest02())
            {
            	modiToken = extractJWT(weModiApiConfig.getModiTokenName(), headers);
            	modiAuth = weModiJWTValidator.validateModIJWT(modiToken, headers);
            }
            else
            	modiAuth = true;

            if (weModiApiConfig.isPdndAuth())
            {
            	pdndToken = extractPdndJWT(HttpHeaders.AUTHORIZATION, headers);
            	pdndAuth = weModiJWTValidator.validatePDNDJWT(pdndToken, trackingEvidenceToken, headers);
            }
            else
            	pdndAuth = true;

            if (modiAuth && pdndAuth && jwsAuditAuth)
            {
            	String tokenResult = !(pdndToken.equals("")) ? pdndToken : modiToken;
            	signedJWT = SignedJWT.parse(tokenResult);
                payload = signedJWT.getJWTClaimsSet();
                tokenIdentifier = payload.getJWTID();
                JSONObject api = new net.minidev.json.JSONObject();
        		api.put("name", retrievedApi.getApiName());
        		api.put("publisher", retrievedApi.getApiProvider());
        		log.info("api details: " + api.toJSONString());
				AuthenticationContext authenticationContext = GatewayUtils
                        .generateAuthenticationContext(tokenIdentifier, payload, api, retrievedApi.getApiTier());
				log.info("username: " + authenticationContext.getUsername());
				synCtx.setProperty(APIMgtGatewayConstants.END_USER_NAME, authenticationContext.getUsername());
                APISecurityUtils.setAuthenticationContext(synCtx, authenticationContext);
            	log.info("Autenticazione riuscita");
            	return new AuthenticationResponse(true, isMandatory, false, 0, null);
            }
          } catch (APISecurityException | ParseException e) {
            String msg = "Errore durante l'autenticazione dell'API in base al token ModI.";
            log.error(msg, e);
            return new AuthenticationResponse(false, isMandatory, false, 10040, msg + e.getMessage());
        }

        return new AuthenticationResponse(false, isMandatory, false, 10040, "Impossibile autenticare l'API in base al token ModI");
    }

    @Override
    public String getChallengeString() {
        return "ModI realm=\"Profesia weModI\"";
    }

    @Override
    public String getRequestOrigin() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getPriority() {
        return -20;
    }
    
    private String extractPdndJWT(String headerName, Map headers) {
        String pdndJwt;
        //check headers to get PDND JWT
        if (headers != null) {
        	pdndJwt = (String) headers.get(headerName);
            if (pdndJwt != null) {
                //Remove PDND header from the request
                //headers.remove(headerName);
                if(pdndJwt.contains("Bearer"))
                {
                	pdndJwt = pdndJwt.replace("Bearer", "");
                	return pdndJwt.trim();
                }
            }
        }
        return null;
    }
    
    private String extractJWT(String headerName, Map headers) {
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

}
