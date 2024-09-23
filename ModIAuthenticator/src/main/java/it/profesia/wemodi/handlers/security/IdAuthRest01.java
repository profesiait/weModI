package it.profesia.wemodi.handlers.security;

import java.time.Instant;
import java.util.HashMap;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.jwt.util.DateUtils;

public class IdAuthRest01 extends IdAuthRest {
    public static final String CERTIFICATE_REFERENCE = "x5c|x5t|x5t#S256|x5u";
    public static final String TYP = "typ";
    public static final String ALG = "alg";
    public static final String IAT = "iat";
    public static final String EXP = "exp";
    public static final String NBF = "nbf";
    public static final String AUD = "aud";
    public static final String ISS = "iss";

    public IdAuthRest01() {
        super();
    }

    @Override
    protected void InitHeaderClaimsMap() {
        InnerModiJWTValidator validatorObject = this;
        headerClaimsMap = new HashMap<String, ClaimValidator>() {
            {
                // TODO: definire il metodo di validazione per il certificato
                put(CERTIFICATE_REFERENCE, new ClaimValidator(true, validatorObject, "checkCertificate"));
                put(TYP, new ClaimValidator(true, validatorObject, "checkTyp"));
                put(ALG, new ClaimValidator(true, validatorObject, "checkAlg"));
            }
        };
    }

    @Override
    protected void InitPayloadClaimsMap() {
        InnerModiJWTValidator validatorObject = this;
        payloadClaimsMap = new HashMap<String, ClaimValidator>() {
            {
                // TODO: definire il metodo di validazione per il certificato
                put(IAT, new ClaimValidator(true, validatorObject, "checkIat"));
                put(EXP, new ClaimValidator(true, validatorObject, "checkExp"));
                put(NBF, new ClaimValidator(true, validatorObject, "checkNbf"));
                put(AUD, new ClaimValidator(true, validatorObject, "checkAud"));
                put(ISS, new ClaimValidator(true, validatorObject, "checkIss"));
            }
        };
    }

    protected Boolean checkExp(String claimName, Long exp) {
        Boolean isValid = false;
        setExp(exp);
        log.debug(String.format("Validazione del claim exp: %d", exp));
        long now = Instant.now().getEpochSecond();
        
        if (DateUtils.isAfter(DateUtils.fromSecondsSinceEpoch(exp), DateUtils.fromSecondsSinceEpoch(now), timestampSkew)) {
            isValid = true;
            log.debug("Valore del claim exp rispetto al momento attuale: " + isValid);
        }
        return isValid;
    }

    protected Boolean checkIat(String claimName, Long iat) {
        Boolean isValid = false;
        setIat(iat);
        log.debug(String.format( "Validazione del claim iat: %d", iat));
        long now = Instant.now().getEpochSecond();


        if (DateUtils.isAfter(DateUtils.fromSecondsSinceEpoch(now), DateUtils.fromSecondsSinceEpoch(iat), timestampSkew)) {
            isValid = true;
            log.debug("Valore del claim iat rispetto al momento attuale: " + isValid);
        }
        return isValid;
    }
    
    protected Boolean checkNbf(String claimName, Long nbf) {
        Boolean isValid = false;
        setNbf(nbf);
        log.debug(String.format( "Validazione del claim nbf: %d", nbf));
        long now = Instant.now().getEpochSecond();


        if (DateUtils.isAfter(DateUtils.fromSecondsSinceEpoch(now), DateUtils.fromSecondsSinceEpoch(nbf), timestampSkew)) {
            isValid = true;
            log.debug("Valore del claim nbf rispetto al momento attuale: " + isValid);
        }
        return isValid;
    }
    
    protected boolean checkAud(String claimName, String audFromJWT)
    {
    	return (StringUtils.isNotBlank(audFromJWT) && this.getAud().equals(audFromJWT));
    }
    
    protected boolean checkIss(String claimName, String iss)
    {
    	return StringUtils.isNotBlank(iss);
    }
}
