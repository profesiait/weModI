package it.profesia.wemodi.keymanager;


import java.text.ParseException;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.common.gateway.dto.JWTValidationInfo;
import org.wso2.carbon.apimgt.common.gateway.dto.TokenIssuerDto;
import org.wso2.carbon.apimgt.common.gateway.exception.JWTGeneratorException;
import org.wso2.carbon.apimgt.common.gateway.jwttransformer.DefaultJWTTransformer;
import org.wso2.carbon.apimgt.common.gateway.jwttransformer.JWTTransformer;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.jwt.JWTValidator;
import org.wso2.carbon.apimgt.impl.jwt.SignedJWTInfo;

import com.google.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;

public class PDNDJWTValidatorImpl implements JWTValidator {

    TokenIssuerDto tokenIssuer;
    JWTTransformer jwtTransformer;

	private static final Log log = LogFactory.getLog(PDNDJWTValidatorImpl.class);
	@Override
	public JWTValidationInfo validateToken(SignedJWTInfo signedJWTInfo) throws APIManagementException {
		JWTValidationInfo jwtValidationInfo = new JWTValidationInfo();
		String pdndJwt = signedJWTInfo.getToken();
		log.info("pdndJwt: " + pdndJwt);
        boolean state;
        try {
        	state = PDNDVoucherValidation.pdndJwtValidation(pdndJwt);
            if (state) {
                JWTClaimsSet jwtClaimsSet = signedJWTInfo.getJwtClaimsSet();
                if (state) {
                    if (state) {
                        jwtValidationInfo.setConsumerKey(getConsumerKey(jwtClaimsSet));
                        jwtValidationInfo.setScopes(getScopes(jwtClaimsSet));
                        jwtValidationInfo.setAppToken(getIsAppToken(jwtClaimsSet));
                        JWTClaimsSet transformedJWTClaimSet = transformJWTClaims(jwtClaimsSet);
                        createJWTValidationInfoFromJWT(jwtValidationInfo, transformedJWTClaimSet);
                        jwtValidationInfo.setRawPayload(signedJWTInfo.getToken());
                        return jwtValidationInfo;
                    } else {
                        jwtValidationInfo.setValid(false);
                        jwtValidationInfo.setValidationCode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                        return jwtValidationInfo;
                    }
                } else {
                    jwtValidationInfo.setValid(false);
                    jwtValidationInfo.setValidationCode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                    return jwtValidationInfo;

                }
            } else {
                jwtValidationInfo.setValid(false);
                jwtValidationInfo.setValidationCode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                return jwtValidationInfo;
            }
        } catch (ParseException | JWTGeneratorException e) {
            throw new APIManagementException("Error while parsing JWT", e);
        }

	}


    protected JWTClaimsSet transformJWTClaims(JWTClaimsSet jwtClaimsSet) throws JWTGeneratorException {

        return jwtTransformer.transform(jwtClaimsSet);
    }

    protected String getConsumerKey(JWTClaimsSet jwtClaimsSet) throws JWTGeneratorException {

        return jwtTransformer.getTransformedConsumerKey(jwtClaimsSet);
    }

    protected List<String> getScopes(JWTClaimsSet jwtClaimsSet) throws JWTGeneratorException {

        return jwtTransformer.getTransformedScopes(jwtClaimsSet);
    }

    protected Boolean getIsAppToken(JWTClaimsSet jwtClaimsSet) throws JWTGeneratorException {

        return jwtTransformer.getTransformedIsAppTokenType(jwtClaimsSet);
    }

    private void createJWTValidationInfoFromJWT(JWTValidationInfo jwtValidationInfo,
            JWTClaimsSet jwtClaimsSet) throws ParseException {

		jwtValidationInfo.setIssuer(jwtClaimsSet.getIssuer());
		jwtValidationInfo.setValid(true);
		jwtValidationInfo.setClaims(new HashMap<>(jwtClaimsSet.getClaims()));
		if (jwtClaimsSet.getExpirationTime() != null){
			jwtValidationInfo.setExpiryTime(jwtClaimsSet.getExpirationTime().getTime());
		}
		if (jwtClaimsSet.getIssueTime() != null){
			jwtValidationInfo.setIssuedTime(jwtClaimsSet.getIssueTime().getTime());
		}
		jwtValidationInfo.setUser(jwtClaimsSet.getSubject());
		jwtValidationInfo.setJti(jwtClaimsSet.getJWTID());
log.error("createJWTValidationInfoFromJWT\n\tjwtValidationInfo: " + new Gson().toJson(jwtValidationInfo));
    }


	@Override
	public void loadTokenIssuerConfiguration(TokenIssuerDto tokenIssuerConfigurations) {
		// TODO Auto-generated method stub
		
log.error("\n---------\n--------------------\n-----------------\n----------------------------------- loadTokenIssuerConfiguration  --------------------------------------------------\n-----------------------\n----------------------------\n---------------------\n");
		this.tokenIssuer = tokenIssuerConfigurations;
		JWTTransformer jwtTransformer = ServiceReferenceHolder.getInstance().getJWTTransformer(tokenIssuer.getIssuer());
		if (jwtTransformer != null) {
		    this.jwtTransformer = jwtTransformer;
		} else {
		    this.jwtTransformer = new DefaultJWTTransformer();
		}
		this.jwtTransformer.loadConfiguration(tokenIssuer);
	}

}
