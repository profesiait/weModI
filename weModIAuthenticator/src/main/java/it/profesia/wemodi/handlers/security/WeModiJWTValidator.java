package it.profesia.wemodi.handlers.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.impl.jwt.SignedJWTInfo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.profesia.wemodi.ApiConfig;
import it.profesia.wemodi.subscriptions.utils.CertificateMetadata;

public class WeModiJWTValidator {
    private static final Log log = LogFactory.getLog(WeModiJWTValidator.class);
    private ApiConfig apiConfig;

    private WeModiJWTValidator() {
        throw new UnsupportedOperationException("Invocare il costruttore WeModiJWTValidator(ApiConfig)");
    }

    /**
     * 
     * @param apiConfig
     */
    public WeModiJWTValidator(ApiConfig apiConfig) {
        this.apiConfig = apiConfig;
    }

    /**
     * Valida il JWT ModI in base alle regole descritte nelle linee guida AgID
     * 
     * @param modToken JWT ModI da validare
     * @param headers Headers della request
     * @return
     * @throws APISecurityException 
     * @throws ParseException 
     */
    public Boolean validateModIJWT (String modiToken, Map headers) throws APISecurityException, ParseException {
        log.info("Validazione del JWT ModI: " + modiToken);
        if (StringUtils.isBlank(modiToken)){
            log.error("Non è stato forntio il token ModI.");
            return false;
        }
        String[] JWTElements = modiToken.split("\\.");
        if (JWTElements.length != 3) {
            log.error("Il formato del JWT non è nel formato previsto <header.payload.signature>: " + Arrays.toString(JWTElements));
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS, "JWT ModI non valido.");
        }

        if (log.isTraceEnabled()) {
            log.trace(String.format("Validazione del JWT ModI [header: %s, payload: %s, signature: %s]", JWTElements[0], JWTElements[1], JWTElements[2]));
        }

        SignedJWTInfo signedJWTInfo = getSignedJwt(modiToken);
        JWSHeader jwtHeader = signedJWTInfo.getSignedJWT().getHeader();
        Payload payload = signedJWTInfo.getSignedJWT().getPayload();

		InnerModiJWTValidator validator = null;

		IdAuthRest idAuthRest = null;
        if (apiConfig.isIdAuthRest01()) {
            idAuthRest = new IdAuthRest01();
            idAuthRest.setAud(apiConfig.getAud());
            validator = idAuthRest;
        }
        if (apiConfig.isIdAuthRest02()) {
            idAuthRest = new IdAuthRest02();
            idAuthRest.setAud(apiConfig.getAud());
            validator = idAuthRest;
        }
        if (apiConfig.isIntegrityRest01()) {
            IntegrityRest01 integrityRest01 = new IntegrityRest01(idAuthRest);
            integrityRest01.setHeaders(headers);
            validator = integrityRest01;
        }
        if (apiConfig.isIntegrityRest02()) {
            IntegrityRest02 integrityRest02 = new IntegrityRest02(idAuthRest);
            integrityRest02.setHeaders(headers);
            integrityRest02.setUrlApiInterop(apiConfig.getUrlApiInterop());
            validator = integrityRest02;
        }

		if (validator == null) {
			throw new APISecurityException(10040, "Nessun pattern valido per la verifica del token ModI: " + apiConfig.getPatterns());
        }
 
		if (!validator.validateHeader(jwtHeader)) {
			log.error(String.format("Header del JWT ModI [%s] non valido: %s", signedJWTInfo.getToken(), jwtHeader.toString()));
            return false;
        }

        if (!validator.validatePayload(payload)) {
            log.error(String.format("Payload del JWT ModI [%s] non valido: %s", signedJWTInfo.getToken(), payload.toString()));
            return false;
        }

        if (!verifySignature(signedJWTInfo.getSignedJWT(), validator.getPublicKey())) {
            log.debug(String.format("Firma del JWT ModI [%s] non valida rispetto alla chiave pubblica: %s", signedJWTInfo.getToken(), Base64.getEncoder().encodeToString(validator.getPublicKey().getEncoded())));
            return false;
        }

        return true;
    }

    public Boolean validateModIJWTTrackingEvidence (String modiToken, Map headers) throws APISecurityException, ParseException {
        log.info("Validazione del JWT Tracking Evidence: " + modiToken);
        if (StringUtils.isBlank(modiToken)){
            log.error("Non è stato forntio il token Tracking Evidence.");
            return false;
        }
        String[] JWTElements = modiToken.split("\\.");
        if (JWTElements.length != 3) {
            log.error("Il formato del JWT non è nel formato previsto <header.payload.signature>: " + Arrays.toString(JWTElements));
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS, "JWT Tracking Evidence non valido.");
        }

        if (log.isTraceEnabled()) {
            log.trace(String.format("Validazione del JWT Tracking Evidence [header: %s, payload: %s, signature: %s]", JWTElements[0], JWTElements[1], JWTElements[2]));
        }

        SignedJWTInfo signedJWTInfo = getSignedJwt(modiToken);
        JWSHeader jwtHeader = signedJWTInfo.getSignedJWT().getHeader();
        Payload payload = signedJWTInfo.getSignedJWT().getPayload();

        InnerModiJWTValidator validator = null;

        if (apiConfig.isAuditRest01Modi()) {
        	IdAuditRest01 idAuditRest01ModI = new IdAuditRest01_ModI();
        	idAuditRest01ModI.setAud(apiConfig.getAud());
            validator = idAuditRest01ModI;
        }
        if (apiConfig.isAuditRest01Pdnd()) {
        	IdAuditRest01 idAuditRest01Pdnd = new IdAuditRest01_Pdnd();
        	idAuditRest01Pdnd.setAud(apiConfig.getAud());
        	idAuditRest01Pdnd.setUrlApiInterop(apiConfig.getUrlApiInterop());
            validator = idAuditRest01Pdnd;
        }
        if (apiConfig.isAuditRest02()) {
        	IdAuditRest02 idAuditRest02 = new IdAuditRest02();
        	idAuditRest02.setAud(apiConfig.getAud());
        	idAuditRest02.setUrlApiInterop(apiConfig.getUrlApiInterop());
            validator = idAuditRest02;
        }

        if (validator == null) {
			throw new APISecurityException(10040, "Nessun pattern valido per la verifica del token Tracking Evidence: " + apiConfig.getPatterns());
        }

		if (!validator.validateHeader(jwtHeader)) {
			log.error(String.format("Header del JWT Tracking Evidence [%s] non valido: %s", signedJWTInfo.getToken(), jwtHeader.toString()));
            return false;
        }

        if (!validator.validatePayload(payload)) {
            log.error(String.format("Payload del JWT Tracking Evidence [%s] non valido: %s", signedJWTInfo.getToken(), payload.toString()));
            return false;
        }

        if (!verifySignature(signedJWTInfo.getSignedJWT(), validator.getPublicKey())) {
            log.debug(String.format("Firma del JWT Tracking Evidence [%s] non valida rispetto alla chiave pubblica: %s", signedJWTInfo.getToken(), Base64.getEncoder().encodeToString(validator.getPublicKey().getEncoded())));
            return false;
        }
        return true;
    }

    private boolean verifySignature(SignedJWT signedJWT, PublicKey publicKey) {
        log.debug(String.format("Verifica firma del JWT."));
        try {
            JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            return signedJWT.verify(jwsVerifier);
        } catch (JOSEException | IllegalArgumentException e) {
            log.error("Impossibile verificare la firma del JWT.", e);
            return false;
        }
    }

    /**
     * Effettua una validazione aggiuntiva sul Voucher PDND in base a quanto descritto nelle linee guida PDND
     * 
     * @param jwt
     * @return
     * @throws APISecurityException 
     * @throws ParseException 
     */
    public Boolean validatePDNDJWT(String pdndToken, String jwsAuditToken, Object headers) throws APISecurityException, ParseException {
    	log.info("Validazione del JWT PDND: " + pdndToken);
        if (StringUtils.isBlank(pdndToken)){
            log.error("Non è stato forntio il token PDND.");
            return false;
        }
        String[] JWTElements = pdndToken.split("\\.");
        if (JWTElements.length != 3) {
            log.error("Il formato del JWT non è nel formato previsto <header.payload.signature>: " + Arrays.toString(JWTElements));
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS, "JWT PDND non valido.");
        }

        if (log.isTraceEnabled()) {
            log.trace(String.format("Validazione del JWT PDND [header: %s, payload: %s, signature: %s]", JWTElements[0], JWTElements[1], JWTElements[2]));
        }

        SignedJWTInfo signedJWTInfo = getSignedJwt(pdndToken);
        JWSHeader jwtHeader = signedJWTInfo.getSignedJWT().getHeader();
        Payload payload = signedJWTInfo.getSignedJWT().getPayload();

		InnerModiJWTValidator validator = null;

		PdndAuth pdndAuth = null;
        if (apiConfig.isPdndAuth()) {
        	if(apiConfig.isAuditRest02())
        	{
        		byte[] digestBytes = convertToDigestBytes(jwsAuditToken);
        		String digestValue = CertificateMetadata.hexify(digestBytes);
        		pdndAuth = new PdndAuditRest02Auth(digestValue);
        	}
        	else
        		pdndAuth = new PdndAuth();
        	pdndAuth.setUrlPdndJwks(apiConfig.getUrlPdndJwks());
            validator = pdndAuth;
        }

		if (validator == null) {
			throw new APISecurityException(10040, "Nessun pattern valido per la verifica del token PDND: " + apiConfig.getPatterns());
        }
 
		if (!validator.validateHeader(jwtHeader)) {
			log.error(String.format("Header del JWT PDND [%s] non valido: %s", signedJWTInfo.getToken(), jwtHeader.toString()));
            return false;
        }

        if (!validator.validatePayload(payload)) {
            log.error(String.format("Payload del JWT PDND [%s] non valido: %s", signedJWTInfo.getToken(), payload.toString()));
            return false;
        }

        if (!verifySignature(signedJWTInfo.getSignedJWT(), validator.getPublicKey())) {
            log.debug(String.format("Firma del JWT PDND [%s] non valida rispetto alla chiave pubblica: %s", signedJWTInfo.getToken(), Base64.getEncoder().encodeToString(validator.getPublicKey().getEncoded())));
            return false;
        }

        return true;
    }

    private SignedJWTInfo getSignedJwt(String accessToken) throws ParseException {
        log.trace("Validazione della firma JWT ModI: " + accessToken);
        SignedJWTInfo signedJWTInfo = null;
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        signedJWTInfo = new SignedJWTInfo(accessToken, signedJWT, jwtClaimsSet);
        return signedJWTInfo;
    }
    
    private byte[] convertToDigestBytes(String payload) {
		String digestAlgorithm = "SHA-256";
		byte[] encodedhash = null;
		try {
			MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
			encodedhash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
		}
		return encodedhash;
	}

}
