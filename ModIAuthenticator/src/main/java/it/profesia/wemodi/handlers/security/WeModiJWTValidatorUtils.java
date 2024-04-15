package it.profesia.wemodi.handlers.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.cache.Cache;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.impl.caching.CacheProvider;
import org.wso2.carbon.apimgt.impl.jwt.SignedJWTInfo;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.profesia.carbon.apimgt.gateway.handlers.security.JWTClaims;
import it.profesia.carbon.apimgt.gateway.handlers.security.JWTInfo;
import it.profesia.carbon.apimgt.gateway.handlers.security.authenticator.ModiAuthenticator;
import it.profesia.wemodi.ApiConfig;
import net.minidev.json.JSONObject;

public class WeModiJWTValidatorUtils {
    private static final Log log = LogFactory.getLog(WeModiJWTValidatorUtils.class);
    private ApiConfig apiConfig;

    private WeModiJWTValidatorUtils() {
        
    }

    /**
     * 
     * @param apiConfig
     */
    public WeModiJWTValidatorUtils(ApiConfig apiConfig) {
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
        String[] JWTElements = modiToken.split("\\.");
        if (JWTElements.length != 3) {
            log.debug("Invalid JWT token. The expected token format is <header.payload.signature>");
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    "Invalid JWT token");
        }

        SignedJWTInfo signedJWTInfo = getSignedJwt(modiToken);
        JWSHeader jwtHeader = signedJWTInfo.getSignedJWT().getHeader();

        JSONArray certificateReferenceArray = null;
        List<String> certificateReferenceValues = new ArrayList<String>(Arrays.asList("x5t#S256", "x5t", "x5c", "x5u", "kid"));
        log.trace("Ricerca della referenza al certificato nell'header del JWT ModI: " + jwtHeader);

        String certificateReference = null;
        for(String value: certificateReferenceValues) {
            // Se l'header contiene un array di certificati prende il primo elemento, altrimenti lo recupera come stringa
            certificateReferenceArray = getIfJSONArrayExist(jwtHeader.toJSONObject(), value);

            if(certificateReferenceArray != null) {
				certificateReference = certificateReferenceArray.optString(0, "");
				//jwtInfo.setCertificateReference(certificateReference);
				break;
			}
			else {
				if(!((certificateReference = getIfStringExist(jwtHeader.toJSONObject(), value)).equals(""))) {
					//jwtInfo.setCertificateReference(certificateReference);
					break;
				}
			}
        }
/* TODO: Da completare
		org.json.JSONObject payloadJSON = new org.json.JSONObject(payload);
		Pair<String, Boolean> headerPair = validateHeaderModI(jwtHeader, certificateReference, jwtClaims, jwtInfo);
		boolean headerValidation = headerPair.getValue();
		List<Pair<String, Boolean>> list = validatePayload(payloadJSON, jwtInfo, modiPdndProps, jwtClaims);
		boolean payloadValidation = list.get(0).getValue() && list.get(1).getValue();
		Pair<String, Boolean> signaturePair = null;
		if(jwtInfo.getPdndKid() != null && !(jwtInfo.getPdndKid().equals("")))
		{
			log.info("kid: " + jwtInfo.getPdndKid());
			String pdndJwksUrl = modiPdndProps.getProperty(ModiAuthenticator.PDND_JWKS_URL);
			String pdnd_api_url = modiPdndProps.getProperty(ModiAuthenticator.PDND_API_URL);
			signaturePair = validatePdndSignature(modiJwt, pdndJwksUrl, pdnd_api_url, jwtInfo);
		}
		else
			signaturePair = validateSignature(modiJwt, jwtInfo);
 */
        return true;
    }

    /**
     * Effettua una validazione aggiuntiva sul Voucher PDND in base a quanto descritto nelle linee guida PDND
     * 
     * @param jwt
     * @return
     */
    public Boolean validatePDNDJWT (Object jwt, Object headers) {
        return true;
    }

    private SignedJWTInfo getSignedJwt(String accessToken) throws ParseException {
        log.trace("Validazione della firma JWT ModI: " + accessToken);
        String signature = accessToken.split("\\.")[2];
        SignedJWTInfo signedJWTInfo = null;
        Cache gatewaySignedJWTParseCache = CacheProvider.getGatewaySignedJWTParseCache();
        if (gatewaySignedJWTParseCache != null) {
            Object cachedEntry = gatewaySignedJWTParseCache.get(signature);
            if (cachedEntry != null) {
                signedJWTInfo = (SignedJWTInfo) cachedEntry;
            }
            if (signedJWTInfo == null || !signedJWTInfo.getToken().equals(accessToken)) {
                SignedJWT signedJWT = SignedJWT.parse(accessToken);
                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
                signedJWTInfo = new SignedJWTInfo(accessToken, signedJWT, jwtClaimsSet);
                gatewaySignedJWTParseCache.put(signature, signedJWTInfo);
            }
        } else {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            signedJWTInfo = new SignedJWTInfo(accessToken, signedJWT, jwtClaimsSet);
        }
        return signedJWTInfo;
    }

    private static JSONArray getIfJSONArrayExist(JSONObject jsonObject, String field) {
		JSONArray jsonArray = null;
        log.trace(String.format("Ricerca del claim [%s] in [%s]", field, jsonObject));
		if(jsonObject.containsKey(field) && jsonObject.get(field) instanceof JSONArray) {
			jsonArray = (JSONArray) jsonObject.get(field);
            log.trace(String.format("Trovato claim [%s] in [%s]: %s", field, jsonObject, jsonArray));
        }
		return jsonArray;
	}

    private String getIfStringExist(JSONObject jsonObject, String field) {
        String string = "";
        log.trace(String.format("Ricerca del claim [%s] in [%s]", field, jsonObject));
		if(jsonObject != null && jsonObject.containsKey(field)) {
			string = jsonObject.getAsString(field);
            log.trace(String.format("Trovato claim [%s] in [%s]: %s", field, jsonObject, string));
        }
		return string;
	}

    private static Pair<String, Boolean> validateSignature(String jwt, JWTInfo jwtInfo) {
		boolean isValid = false, pubKeyNotAvailable = false;
/* TODO: da rivedere
        PublicKey publicKey = null;
		if (jwtInfo.getCertificateReference() != null && !(jwtInfo.getCertificateReference().equals(""))) {
			try {
				javax.security.cert.X509Certificate x509certificate = retrieveCertificateFromContent(jwtInfo.getCertificateReference());
				if (x509certificate != null) {
					// Retrieve public key
					publicKey = (RSAPublicKey) x509certificate.getPublicKey();
					log.info("public key signature certificate: "
							+ Base64.getEncoder().encodeToString(publicKey.getEncoded()));
					jwtInfo.setCertificate(jwtInfo.getCertificateReference());
				} else {
					String content = callExternalUrl(jwtInfo.getCertificateReference(), "");
					X509Certificate certificate = com.nimbusds.jose.util.X509CertUtils.parse(content);
					if(certificate != null)
					{
						publicKey = (RSAPublicKey) certificate.getPublicKey();
						jwtInfo.setCertificateX509(certificate);
						log.info(
								"public key signature certificate from URL: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
					}
					else
					{
						publicKey = retrievePubKeyFromJWKS(content, "");
						jwtInfo.setPublicKeyFromJWK((RSAPublicKey) publicKey);
						if(publicKey != null)
							log.info("public key signature JWKS: " 
									+ Base64.getEncoder().encodeToString(publicKey.getEncoded()));
						else
							pubKeyNotAvailable = true;
					}
					
				}
				if(!pubKeyNotAvailable)
				{
					SignedJWT jwtSigned = SignedJWT.parse(jwt);
					isValid = verifyTokenSignature(jwtSigned, publicKey);
				}
				else
				{
					isValid = true;
					jwtInfo.setThumbprint(jwtInfo.getCertificateReference());
					log.info("it could be present the thumbprint. Signature validation continues in the authenticator");
				}
				if (isValid)
					return Pair.of("valid signature", isValid);
				else
					return Pair.of("signature not valid", false);
			} catch (Exception e) {
				log.error("Error while validating JWT signature", e);
			}
		} */
		return Pair.of("signature not valid", false);

	}

    private static javax.security.cert.X509Certificate retrieveCertificateFromContent(String base64EncodedCertificate)
			throws APIManagementException {

		if (base64EncodedCertificate != null) {
			byte[] bytes = org.apache.commons.codec.binary.Base64.decodeBase64(base64EncodedCertificate.getBytes(StandardCharsets.UTF_8));
			try (InputStream inputStream = new ByteArrayInputStream(bytes)) {
				return javax.security.cert.X509Certificate.getInstance(inputStream);
			} catch (IOException | javax.security.cert.CertificateException e) {
				String msg = "Error while converting into X509Certificate";
				if (log.isDebugEnabled())
                    log.error(msg, e);
                else
				    log.error(String.format("%s: %s", msg, e.getLocalizedMessage()));
			}
		}
		return null;
	}

    private Pair<String, Boolean> validateHeaderModI(JSONObject headerJSON, String certificateReference, JWTClaims jwtClaims, JWTInfo jwtInfo) {
    	String kid = getIfStringExist(headerJSON, "kid");
		if(!(kid.equals("")))
		{
			log.info("kid is present so it's integrity_rest_02");
			jwtInfo.setPdndKid(kid);
			jwtInfo.setKidForModI(true);
		}
    	String typ = getIfStringExistCheckValue(headerJSON, "typ", "JWT");
		String alg = getIfStringExist(headerJSON, "alg");
		String reference = "x5c|x5t|x5t#S256|x5u|kid";
		if (this.apiConfig.isIntegrityRest02())
			reference += "|kid";
		Map<String, String> map = Stream.of(new String[][] {
			  { reference, certificateReference }, 
			  { "typ", typ }, 
			  { "alg", alg }
			}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
		return validateString(map, headerJSON);
	}

    private String getIfStringExistCheckValue(JSONObject jsonObject, String field, String defaultValue) {
		String returnedValue = "";
		if(!(defaultValue.equals("")))
		{
			returnedValue = (returnedValue = getIfStringExist(jsonObject, field)).equals(defaultValue) ? returnedValue : ""; 
			return returnedValue;
		}
		return getIfStringExist(jsonObject, field);
	}

	private static Pair<String, Boolean> validateString(Map<String, String> map, JSONObject jwtClaims) {
    	 for (Map.Entry<String, String> entry : map.entrySet()) {
    		 if  (entry.getValue() == null || entry.getValue().equals(""))
				 return Pair.of(entry.getKey() + " dato obbligatorio non presente.", false);
			 switch (entry.getKey().toLowerCase()) {
                case "content-type":
                    break;
             }
    	 }
         /* TODO: da rivedere
    	 if(jwtClaims != null) {
	    	 if(map.containsKey("content-type") && !(jwtClaims.get("content-type").equals(""))) {
	    		 if(!(map.get("content-type").equals(jwtClaims.getContentType()))) {
	    			 return Pair.of("content-type different from the input one", false); 
	    		 }
	    	 }
	    	 if(map.containsKey("digest"))
	    	 {
	    		 if(!(jwtClaims.getDigest().equals("")) && !(map.get("digest").equals(jwtClaims.getDigest())))
	    		 {
	    			 return Pair.of("jwt digest different from the payload one", false); 
	    		 }
	    		 else if(!(jwtClaims.getDigestFromHeader().equals("")) && !(map.get("digest").equals(jwtClaims.getDigestFromHeader())))
	    		 {
	    			 return Pair.of("jwt digest different from the header one", false); 
	    		 }
	    	 }
	    	 if(map.containsKey("aud"))
	    	 {
	    		 if(!(map.get("aud").equals(jwtClaims.getAud())))
	    		 {
	    			 return Pair.of("aud different from the input one", false); 
	    		 }
	    	 }
    	 } */
    	 if(map.containsKey("jwsAuditDigest"))
    		 return Pair.of(map.get("jwsAuditDigest"), false); 
    	 return Pair.of("validateString successful", true);
	}

}
