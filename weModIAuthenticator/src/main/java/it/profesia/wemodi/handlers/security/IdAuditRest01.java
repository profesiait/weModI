package it.profesia.wemodi.handlers.security;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.HashMap;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.keymgt.model.exception.DataLoadingException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.util.DateUtils;

import it.profesia.carbon.apimgt.gateway.handlers.security.JWTValidator;
import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;

public class IdAuditRest01 extends AbstractInnerModiJWTValidator {
	
	/**
     * URI per ottenere la chiave pubblica in base al kid
     */
    private String uriApiInteropKeys = "/keys/";
    /**
     * URL delle API di Interoperabilità
     */
    private String urlApiInterop = "";
	
	private String aud = "";
	
	public static final String CERTIFICATE_REFERENCE = "x5c|x5t|x5t#S256|x5u";
	public static final String KID = "kid";
    public static final String TYP = "typ";
    public static final String ALG = "alg";
    public static final String IAT = "iat";
    public static final String EXP = "exp";
    public static final String NBF = "nbf";
    public static final String AUD = "aud";
    public static final String ISS = "iss";
    public static final String JTI = "jti";

    public IdAuditRest01() {
        super();
    }

    @Override
    protected void InitHeaderClaimsMap() {
    	InnerModiJWTValidator validatorObject = this;
        headerClaimsMap = new HashMap<String, ClaimValidator>() {
            {
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
                 put(JTI, new ClaimValidator(true, validatorObject, "checkJti"));
             }
         };
    }
    
    private Boolean checkCertificateReference(String claim, String value) {
        Boolean isValid = false;
        if (KID.equals(claim)) {
            log.info("Validazione del certificato in base al kid PDND: " + value);
            String pdndAccessToken;
            try {
                pdndAccessToken = retrieveAccessTokenPdndApiInterop(value);
                String content = JWTValidator.callExternalUrl(urlApiInterop + uriApiInteropKeys + value, pdndAccessToken);
                //String content = "{\"alg\": \"RS256\", \"e\": \"AQAB\", \"kid\": \"lss6Y7_SyDIkTvSaRtw4M5EJ45aJaey9h0bCI9oHNWI\", \"kty\": \"RSA\", \"n\": \"vGCdUzXM4sh0_x1IalPT_6FsFo7UjGxQPncXSBzT5fMZTMJJ89sE4BJiZq2vsoS4lCJxHsdoOCCJKBJEe_XrYD1WTzaz6aPR4tesQtv41st_FuxJtOoTDcZJ0hENV8bau2dE5C5iHC8aCgw_VkrIMkWFeA6T_y8vduBZ5YTICWqAcnDRxynNWsn71pn1yvTCLf1AJqG_a9sbD_5VkDusdCEgieg7quZAb2h9iinUJtOBCESAomJxgnstZy9fFLx0XbzLdwPrJcn5-euMNYpflBJNpeph0QCMwd3YiJo8FC9j0IBtFWKdd42Pecqh_7WRvyIHkJBO5_JQFdI-EuifkQ\", \"use\": \"sig\"}";
                PublicKey publicKey = JWTValidator.retrievePubKeyFromJWKS(content, "");
                setPublicKey(publicKey);
                isValid = true;
            } catch (DataLoadingException | URISyntaxException | InvalidKeySpecException | NoSuchAlgorithmException | MalformedURLException | JOSEException | APISecurityException e) {
                log.error("Errore durante il recupero dell'Access Token di interop per il recupero del certificato tramite kid.", e);
                return false;
            }
        }
        return isValid;
    }
    
    private String retrieveAccessTokenPdndApiInterop(String kid) throws DataLoadingException, URISyntaxException, InvalidKeySpecException, NoSuchAlgorithmException, MalformedURLException, JOSEException, APISecurityException {
        log.info("Richiesta del token PDND per invocare API di interoperabilità.");
		String pdndAccessToken = "";

        String applicationUUID = new SubscriptionService().getApplicationUUIDByKid(kid);
        log.debug("Recuperato applicationUUID: " + applicationUUID);
        if (!(applicationUUID.equals(""))) {
            PdndPKMapping pdndPKMapping = new SubscriptionService().getCertificatesOutboundPdnd(applicationUUID);
            pdndAccessToken = JWTValidator.providePdnd(pdndPKMapping);
            log.info("Ottenuto Access Token PDND: " + pdndAccessToken);
        }
		return pdndAccessToken;

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
    
    protected boolean checkJti(String claimName, String jti)
    {
    	return StringUtils.isNotBlank(jti);
    }
    
    protected boolean checkPurposeId(String claimName, String purposeid)
    {
    	return StringUtils.isNotBlank(purposeid);
    }
    
    protected boolean checkDnonce(String claimName, Long dnonce)
    {
    	return (dnonce > 0);
    }
    
    public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}
	
	public void setUriApiInteropKeys(String uriApiInteropKeys) {
        this.uriApiInteropKeys = uriApiInteropKeys;
    }

    public void setUrlApiInterop(String urlApiInterop) {
        this.urlApiInterop = urlApiInterop;
    }

}
