package it.profesia.wemodi.identity.oauth2.token;

import java.net.URISyntaxException;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import it.profesia.wemodi.providers.jwt.JWSAuditProvider;
import net.minidev.json.parser.ParseException;

  public class IdAuditRest01Grant extends AbstractAuthorizationGrantHandler {

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        OAuth2AccessTokenRespDTO oauth2AccessTokenReqDTO = super.issue(tokReqMsgCtx);

        String jwsAudit = "";
        try {
            JWSAuditProvider jwsAuditProvider = JWSAuditProvider.FromConsumerKey(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            RequestParameter[] requestParameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
            for (RequestParameter requestParameter : requestParameters) {
                switch (requestParameter.getKey().toUpperCase()) {
                    case "WEMODI_PURPOSEID":
                        jwsAuditProvider.setPurposeId(requestParameter.getValue()[0]);
                        break;
                    case "MODI_JWT_CLAIMS":
                        jwsAuditProvider.setCustomClaims(requestParameter.getValue()[0]);
                        break;
                }
            }

            jwsAudit = jwsAuditProvider.provideJWSAudit();
        } catch (OAuthSystemException | ParseException | APIManagementException | URISyntaxException e) {
            throw new IdentityOAuth2Exception(e.getLocalizedMessage(), e);
        }
        oauth2AccessTokenReqDTO.addParameter("JwsAudit", jwsAudit);

        return oauth2AccessTokenReqDTO;
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {
        oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());

        return true;
    }

    @Override
    public boolean isOfTypeApplicationUser() throws IdentityOAuth2Exception {
        return false;
    }

}
