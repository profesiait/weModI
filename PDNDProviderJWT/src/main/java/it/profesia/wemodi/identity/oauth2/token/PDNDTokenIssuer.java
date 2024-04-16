package it.profesia.wemodi.identity.oauth2.token;

import java.net.URISyntaxException;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;

import it.profesia.wemodi.providers.jwt.JWTTokenPDNDProvider;
import net.minidev.json.parser.ParseException;

public class PDNDTokenIssuer extends OauthTokenIssuerImpl {

    private static final Log log = LogFactory.getLog(PDNDTokenIssuer.class);

    @Override 
    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String accessToken = "";
        log.info("PDND - richiesta access token");
        try {
        	String clientId = "", purposeId = "", customClaims = "";
            OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
            RequestParameter[] requestParameters = oauth2AccessTokenReqDTO.getRequestParameters();
            for (RequestParameter requestParameter : requestParameters) {
                switch (requestParameter.getKey().toUpperCase()) {
                	case "WSO2_CLIENT_ID":
                		clientId = requestParameter.getValue()[0];
	                    log.info("clientId: " + clientId);
	                    break;
                    case "WEMODI_PURPOSEID":
                        purposeId = requestParameter.getValue()[0];
                        log.info("purposeId: " + purposeId);
                        break;
                    case "MODI_JWT_CLAIMS":
                    	customClaims = requestParameter.getValue()[0];
                        break;
                }
            }
            String consumerKey = !(clientId.equals("")) ? clientId : oauth2AccessTokenReqDTO.getClientId();
            log.info("consumerKey: " + consumerKey);
            JWTTokenPDNDProvider jwtTokenPDNDProvider = JWTTokenPDNDProvider.FromConsumerKey(consumerKey);
            Arrays.asList(oauth2AccessTokenReqDTO.getRequestParameters());
            jwtTokenPDNDProvider.setPurposeId(purposeId);
            jwtTokenPDNDProvider.setCustomClaims(customClaims);
            /*RequestParameter[] requestParameters = oauth2AccessTokenReqDTO.getRequestParameters();
            for (RequestParameter requestParameter : requestParameters) {
                switch (requestParameter.getKey().toUpperCase()) {
                    case "WEMODI_PURPOSEID":
                        jwtTokenPDNDProvider.setPurposeId(requestParameter.getValue()[0]);
                        break;
                    case "MODI_JWT_CLAIMS":
                        jwtTokenPDNDProvider.setCustomClaims(requestParameter.getValue()[0]);
                        break;
                }
            }*/

            accessToken = jwtTokenPDNDProvider.PDNDJwtAssertion();
        } catch (APIManagementException | ParseException | URISyntaxException e) {
            String msg = "Impossibile richiedere il Voucher PDND.";
            log.error(String .format("%s %s", msg, e.getLocalizedMessage()));
            throw new OAuthSystemException(msg, e);
        }
        return accessToken;
    }
}
