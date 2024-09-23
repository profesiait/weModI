package it.profesia.wemodi.handlers.security;

import org.apache.commons.lang3.StringUtils;

public class IdAuthRest02 extends IdAuthRest01 {
    public static final String JTI = "jti";

    public IdAuthRest02() {
        super();
    }

    @Override
    protected void InitPayloadClaimsMap() {
        super.InitPayloadClaimsMap();
        InnerModiJWTValidator validatorObject = this;
        payloadClaimsMap.put(JTI, new ClaimValidator(true, validatorObject, "validateJti"));
    }

    protected Boolean validateJti(String claimName, String jti) {
    	return StringUtils.isNotBlank(jti);
    }
}
