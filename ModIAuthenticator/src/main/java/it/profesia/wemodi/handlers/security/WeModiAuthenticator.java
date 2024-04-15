package it.profesia.wemodi.handlers.security;

import java.text.ParseException;
import java.util.Map;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationResponse;
import org.wso2.carbon.apimgt.gateway.handlers.security.Authenticator;
import com.google.gson.Gson;
import it.profesia.wemodi.ApiConfig;

/**
 * Authenticator per la validazione dei JWT e Voucher ModI/PDND, richiede
 * l'implementazione
 * weModI as Key Manager per la validazione del voucher PDND
 */
public class WeModiAuthenticator implements Authenticator {
    private static final Log log = LogFactory.getLog(WeModiAuthenticator.class);

    private boolean isMandatory = false;
    private boolean pdndAuth = false;

    public WeModiAuthenticator() {
    }

    @Override
    public void init(SynapseEnvironment env) {
        // TODO Auto-generated method stub

    }

    @Override
    public void destroy() {
        // TODO Auto-generated method stub

    }

    @Override
    public AuthenticationResponse authenticate(MessageContext synCtx) throws APIManagementException {
        try {
            org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) synCtx).getAxis2MessageContext();
            Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));
            ApiConfig weModiApiConfig = new Gson().fromJson((String) headers.get("weModI_API_Config"), ApiConfig.class);

            if (weModiApiConfig.isIdAuthRest01() || weModiApiConfig.isIdAuthRest02() ||
                    weModiApiConfig.isIntegrityRest01() || weModiApiConfig.isIntegrityRest02() ||
                    weModiApiConfig.isAuditRest01() || weModiApiConfig.isAuditRest02())
                isMandatory = true;

            if (weModiApiConfig.isPdndAuth())
                pdndAuth = true;

            String modiToken = (String) headers.get(weModiApiConfig.getModiTokenName());

            WeModiJWTValidatorUtils weModiJWTValidatorUtils = new WeModiJWTValidatorUtils(weModiApiConfig);
            
            boolean modiAuth;
            modiAuth = weModiJWTValidatorUtils.validateModIJWT(modiToken, headers);

            if (modiAuth)
                return new AuthenticationResponse(true, isMandatory, pdndAuth, 0, null);
          } catch (APISecurityException | ParseException e) {
            log.error("Impossibile autenticare l'API ModI/PDND: " + ExceptionUtils.getStackTrace(e));
            return new AuthenticationResponse(false, isMandatory, pdndAuth, 10040,
                    "Impossibile autenticare l'API ModI/PDND: " + e.getMessage());
        }

        return new AuthenticationResponse(false, isMandatory, pdndAuth, 10040,
                "Impossibile autenticare l'API ModI/PDND");
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
        return 5;
    }

}
