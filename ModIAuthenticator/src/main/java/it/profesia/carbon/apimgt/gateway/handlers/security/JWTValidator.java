package it.profesia.carbon.apimgt.gateway.handlers.security;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.cache.Cache;

import org.apache.commons.httpclient.HttpClientError;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONArray;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.model.exception.DataLoadingException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.CloseableHttpResponse;

import java.net.URI;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.apache.commons.httpclient.HttpClientError;
import org.apache.commons.httpclient.HttpStatus;
import java.net.URISyntaxException;

import org.apache.commons.lang3.exception.ExceptionUtils;

import it.profesia.carbon.apimgt.gateway.handlers.security.authenticator.ModiAuthenticator;
import it.profesia.carbon.apimgt.gateway.handlers.utils.APIUtilCustom;
import it.profesia.carbon.apimgt.gateway.handlers.logging.ModiLogUtils;
import it.profesia.carbon.apimgt.gateway.handlers.security.authenticator.ModiAuthenticator;
import it.profesia.carbon.apimgt.gateway.handlers.utils.CacheProviderWeModi;
import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

public class JWTValidator {
	
	private static final Log log = LogFactory.getLog(JWTValidator.class);

	public static X509Certificate getX509Certificate(String certificate) {

    	X509Certificate x509Certificate = null;
        byte[] cert = (org.apache.commons.codec.binary.Base64.decodeBase64(certificate.getBytes(StandardCharsets.UTF_8)));
        try (ByteArrayInputStream serverCert = new ByteArrayInputStream(cert);){
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate generatedCertificate = cf.generateCertificate(serverCert);
                x509Certificate = (X509Certificate) generatedCertificate;
        } catch (CertificateException | IOException e) {
            log.error("Error while converting into X509Certificate.", e);
        }
        return x509Certificate;
    }
	
	public static boolean JWTValidation(String modiJwt, String pdndJwt, JWTInfo jwtInfo, Properties modiPdndProps, JWTClaims jwtClaims) throws APISecurityException
    {
		log.info("JWTValidation - start");
		String header = "", payload = "", certificateReference = "";
		Base64.Decoder decoder = Base64.getUrlDecoder();
    	try
		{
		String[] splitToken = modiJwt.split("\\.");
		if (splitToken.length != 3) {
			log.error("JWT token does not have the format {header}.{payload}.{signature}");
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE);
        }
		header = new String(decoder.decode(splitToken[0]));
		payload = new String(decoder.decode(splitToken[1]));
		org.json.JSONObject headerJSON = new org.json.JSONObject(header);
		
		org.json.JSONArray certificateReferenceObject = null;
		List<String> certificateReferenceValues = new ArrayList<String>(
				Arrays.asList("x5t#S256", "x5t", "x5c", "x5u", "kid"));
		for(String value: certificateReferenceValues)
		{
			certificateReferenceObject = getIfJSONArrayExist(headerJSON, value);
			if(certificateReferenceObject != null)
			{
				certificateReference = certificateReferenceObject.optString(0, "");
				jwtInfo.setCertificateReference(certificateReference);
				break;
			}
			else
			{
				if(!((certificateReference = getIfStringExist(headerJSON, value)).equals("")))
				{
					jwtInfo.setCertificateReference(certificateReference);
					break;
				}
			}
		}
		
		org.json.JSONObject payloadJSON = new org.json.JSONObject(payload);
		Pair<String, Boolean> headerPair = validateHeader(headerJSON, certificateReference, jwtClaims, jwtInfo);
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
		boolean signatureValidation = signaturePair.getValue();
		Pair<String, Boolean> pdndJwtPair = validatePdndJwt(pdndJwt, jwtInfo, modiPdndProps, jwtClaims);
		boolean pdndJwtValidation = pdndJwtPair.getValue();
		log.info("JWTValidation - end");
		if(headerValidation && payloadValidation && signatureValidation && pdndJwtValidation)
			return true;
		else
		{
			log.error("JWT token is invalid");
			String msg = "";
			if(!(headerPair.getValue()))
				msg = msg + " "+ headerPair.getKey();
			if(!(list.get(0).getValue()))
				msg = msg + " " +list.get(0).getKey();
			if(!(list.get(1).getValue()))
				msg = msg + " "+ list.get(1).getKey();
			if(!(signaturePair.getValue()))
				msg = msg + " "+ signaturePair.getKey();
			if(!(pdndJwtPair.getValue()))
				msg = msg + " "+ pdndJwtPair.getKey();
			log.info("JWTValidation - " + msg);
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE + msg);
		}
		}
		catch(APISecurityException e)
		{
			throw e;
		}
    }
	
	private static String getIfStringExist(org.json.JSONObject jsonObject, String field)
	{
		if(jsonObject != null && jsonObject.has(field))
			return jsonObject.getString(field);
		return "";
	}
	
	private static String getIfStringExistCheckValue(org.json.JSONObject jsonObject, String field, String defaultValue)
	{
		String returnedValue = "";
		if(!(defaultValue.equals("")))
		{
			returnedValue = (returnedValue = getIfStringExist(jsonObject, field)).equals(defaultValue) ? returnedValue : ""; 
			return returnedValue;
		}
		return getIfStringExist(jsonObject, field);
	}
	
	private static long getIfLongExist(org.json.JSONObject jsonObject, String field)
	{
		if(jsonObject != null && jsonObject.has(field))
			return jsonObject.getLong(field);
		return 0;
	}
	
	private static org.json.JSONArray getIfJSONArrayExist(org.json.JSONObject jsonObject, String field)
	{
		JSONArray jsonArray = null;
		if(jsonObject.has(field) && jsonObject.get(field) instanceof JSONArray)
			jsonArray = (JSONArray) jsonObject.get(field);
		return jsonArray;
	}
	
	private static org.json.JSONObject getIfJSONObjectExist(org.json.JSONObject jsonObject, String field)
	{
		if(jsonObject != null && jsonObject.has(field))
			return (org.json.JSONObject) jsonObject.get(field);
		return null;
	}
	
    
    private static List<Pair<String, Boolean>> validatePayload(org.json.JSONObject payloadJSON, JWTInfo jwtInfo, Properties modiPdndProps, JWTClaims jwtClaims)
	{
    	String digest = "", contentType = "";
		String aud = getIfStringExist(payloadJSON, "aud");
		String sub = getIfStringExist(payloadJSON, "sub");
		jwtInfo.setSub(sub);
		String iss = getIfStringExist(payloadJSON, "iss");
		String jti = getIfStringExist(payloadJSON, "jti");
		long nbf = getIfLongExist(payloadJSON, "nbf");
		long exp = getIfLongExist(payloadJSON, "exp");
		long iat = getIfLongExist(payloadJSON, "iat");
		org.json.JSONArray signed_headers = getIfJSONArrayExist(payloadJSON, "signed_headers");
		if(signed_headers != null)
		{
			digest = getIfStringExist(signed_headers.optJSONObject(0), "digest");
			contentType = getIfStringExist(signed_headers.optJSONObject(1), "content-type");
		}
		
		
		Map<String, String> mapString = null;
		Map<String, Long> mapLong = null;
		List<Pair<String, Boolean>> list = null;
		
		if((modiPdndProps.getProperty(ModiAuthenticator.INTEGRITY_REST_01).equals("true") && modiPdndProps.getProperty(ModiAuthenticator.ID_AUTH_REST_01).equals("true")) 
				|| modiPdndProps.getProperty(ModiAuthenticator.INTEGRITY_REST_02).equals("true"))
		{
			mapString = Stream.of(new String[][] {
				  { "aud", aud },
				  //sub is NOT mandatory
				  //{ "sub", sub }, 
				  { "content-type", contentType },
				  { "digest", digest }
				}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
			if(jwtInfo.getJwtType() != null && jwtInfo.getJwtType().equals("JWS_Audit"))
			{
				mapString.remove("content-type");
				mapString.remove("digest");
				log.info("contentType and digest are not mandatory for audit_rest_01");
			}
			mapLong = Stream.of(new Object[][] {
				  { "nbf", nbf }, 
				  { "exp", exp }, 
				  { "iat", iat }
				}).collect(Collectors.toMap(data -> (String)data[0], data -> (Long)data[1]));
			 list = new ArrayList<Pair<String, Boolean>>(
			            Arrays.asList(validateString(mapString, jwtClaims), validateLong(mapLong)));
		}
		else if((modiPdndProps.getProperty(ModiAuthenticator.INTEGRITY_REST_01).equals("true") && modiPdndProps.getProperty(ModiAuthenticator.ID_AUTH_REST_02).equals("true")) 
				|| modiPdndProps.getProperty(ModiAuthenticator.INTEGRITY_REST_02).equals("true"))
		{
			mapString = Stream.of(new String[][] {
				  { "aud", aud },
				  //sub is NOT mandatory
				  //{ "sub", sub }, 
				  { "jti", jti },
				  { "content-type", contentType },
				  { "digest", digest },
				}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
			if(jwtInfo.getJwtType() != null && jwtInfo.getJwtType().equals("JWS_Audit"))
			{
				mapString.remove("content-type");
				mapString.remove("digest");
				log.info("contentType and digest are not mandatory for audit_rest_01");
			}
			mapLong = Stream.of(new Object[][] {
				  { "nbf", nbf }, 
				  { "exp", exp }, 
				  { "iat", iat }
				}).collect(Collectors.toMap(data -> (String)data[0], data -> (Long)data[1]));
			 list = new ArrayList<Pair<String, Boolean>>(
			            Arrays.asList(validateString(mapString, jwtClaims), validateLong(mapLong)));
		}
		else if(modiPdndProps.getProperty(ModiAuthenticator.ID_AUTH_REST_01).equals("true"))
		{
			mapString = Stream.of(new String[][] {
				  { "aud", aud }
				  //sub is NOT mandatory
				  //{ "sub", sub }, 
				}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
			mapLong = Stream.of(new Object[][] {
				  { "nbf", nbf }, 
				  { "exp", exp }, 
				  { "iat", iat }
				}).collect(Collectors.toMap(data -> (String)data[0], data -> (Long)data[1]));
			 list = new ArrayList<Pair<String, Boolean>>(
			            Arrays.asList(validateString(mapString, jwtClaims), validateLong(mapLong)));
		}
		else if(modiPdndProps.getProperty(ModiAuthenticator.ID_AUTH_REST_02).equals("true"))
		{
			mapString = Stream.of(new String[][] {
				  { "aud", aud },
				  //sub is NOT mandatory
				  //{ "sub", sub }, 
				  { "jti", jti },
				}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
			mapLong = Stream.of(new Object[][] {
				  { "nbf", nbf }, 
				  { "exp", exp }, 
				  { "iat", iat }
				}).collect(Collectors.toMap(data -> (String)data[0], data -> (Long)data[1]));
			 list = new ArrayList<Pair<String, Boolean>>(
			            Arrays.asList(validateString(mapString, jwtClaims), validateLong(mapLong)));
		}
		else
		{
			mapString = Stream.of(new String[][] {
				  { "aud", aud }, 
				  //sub is NOT mandatory
				  //{ "sub", sub }, 
				  { "iss", iss },
				  { "jti", jti },
				  { "content-type", contentType },
				  { "digest", digest },
				}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
			if(jwtInfo.getJwtType() != null && jwtInfo.getJwtType().equals("JWS_Audit"))
			{
				mapString.remove("content-type");
				mapString.remove("digest");
				mapString.remove("iss");
				log.info("contentType, digest and iss are not mandatory for audit_rest_01");
			}
			mapLong = Stream.of(new Object[][] {
				  { "nbf", nbf }, 
				  { "exp", exp }, 
				  { "iat", iat }
				}).collect(Collectors.toMap(data -> (String)data[0], data -> (Long)data[1]));
			 list = new ArrayList<Pair<String, Boolean>>(
			            Arrays.asList(validateString(mapString, jwtClaims), validateLong(mapLong)));
		}
		return list;
	}
    
    private static Pair<String, Boolean> validateHeader(org.json.JSONObject headerJSON, String certificateReference, JWTClaims jwtClaims, JWTInfo jwtInfo)
	{
    	String kid = getIfStringExist(headerJSON, "kid");
		if(!(kid.equals("")))
		{
			log.info("kid is present so it's integrity_rest_02");
			jwtInfo.setPdndKid(kid);
			jwtInfo.setKidForModI(true);
		}
    	String typ = getIfStringExistCheckValue(headerJSON, "typ", "JWT");
		String alg = getIfStringExist(headerJSON, "alg");
		Map<String, String> map = Stream.of(new String[][] {
			  { "x5c|x5t|x5t#S256|x5u|kid", certificateReference }, 
			  { "typ", typ }, 
			  { "alg", alg }
			}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
		return validateString(map, jwtClaims);
	}
    
	private static Pair<String, Boolean> validateLong(Map<String, Long> map) {
		for (Map.Entry<String, Long> entry : map.entrySet()) {
			if (entry.getKey() == null || entry.getValue() == 0)
				return Pair.of(entry.getKey() + " not valid", false);
		}

		long nbf = map.get("nbf");
		long exp = map.get("exp");
		long iat = map.get("iat");
		
		if (!checkDateValidity(exp, nbf) || !checkDateValidity(iat, nbf))
			return Pair.of("nbf not valid", false);
		else if (!checkDateValidity(exp, Instant.now().getEpochSecond()))
			return Pair.of("exp not valid", false);
		else if (!checkDateValidity(exp, iat))
			return Pair.of("iat not valid", false);
		return Pair.of("validateLong successful", true);
	}
    
    private static Pair<String, Boolean> validateString(Map<String, String> map, JWTClaims jwtClaims)
	{
    	 for (Map.Entry<String, String> entry : map.entrySet()) {
    		 if  (entry.getValue() == null || entry.getValue().equals(""))
				 return Pair.of(entry.getKey()+" not valid", false);
    	 }
    	 if(jwtClaims != null)
    	 {
	    	 if(map.containsKey("content-type") && !(jwtClaims.getContentType().equals("")))
	    	 {
	    		 if(!(map.get("content-type").equals(jwtClaims.getContentType())))
	    		 {
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
    	 }
    	 if(map.containsKey("jwsAuditDigest"))
    		 return Pair.of(map.get("jwsAuditDigest"), false); 
    	 return Pair.of("validateString successful", true);
	}
    
    public static boolean pdndJwtValidation(String pdndJwt, JWTInfo jwtInfo, Properties modiPdndProps, JWTClaims jwtClaims) throws APISecurityException
    {
    	Pair<String, Boolean> pdndValidationPair = validatePdndJwt(pdndJwt, jwtInfo, modiPdndProps, jwtClaims);
    	if(pdndValidationPair.getValue())
    		return true;
    	else
    	{
    		String msg = " "+pdndValidationPair.getKey();
    		log.info("pdndJwtValidation - " + msg);
    		throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    APISecurityConstants.API_AUTH_INVALID_CREDENTIALS_MESSAGE + msg);
    	}
    	
    }
    
    private static Pair<String, Boolean> validatePdndJwt(String pdndJwt, JWTInfo jwtInfo, Properties modiPdndProps, JWTClaims jwtClaims)
    {
    	if (StringUtils.isEmpty(pdndJwt)) {
    		return Pair.of("pdndJwt not required", true);
    	}
    	
    	log.info("validatePdndJwt - start");
    	
    	String header = "", payload = "";
		Base64.Decoder decoder = Base64.getUrlDecoder();
    	
		String[] splitToken = pdndJwt.split("\\.");
		if (splitToken.length != 3) {
			log.error("Pdnd JWT token does not have the format {header}.{payload}.{signature}");
            return Pair.of("invalid pdndJwt", false);
        }
		header = new String(decoder.decode(splitToken[0]));
		payload = new String(decoder.decode(splitToken[1]));
		org.json.JSONObject headerJSON = new org.json.JSONObject(header);
		org.json.JSONObject payloadJSON = new org.json.JSONObject(payload);
		Pair<String, Boolean> headerPair = validatePdndJwtHeader(headerJSON, jwtInfo);
		//String kid = getIfStringExist(headerJSON, "kid");
		List<Pair<String, Boolean>> payloadPair = validatePdndJwtPayload(payloadJSON, jwtInfo, jwtClaims);
		//String pdndJwksUrl = getPdndJwksUrl();
		String pdndJwksUrl = modiPdndProps.getProperty(ModiAuthenticator.PDND_JWKS_URL);
		String pdnd_api_url = modiPdndProps.getProperty(ModiAuthenticator.PDND_API_URL);
		Pair<String, Boolean> signaturePair = validatePdndSignature(pdndJwt, pdndJwksUrl, pdnd_api_url, jwtInfo);
		log.info("validatePdndJwt - end");
		if(headerPair.getValue() && payloadPair.get(0).getValue() && payloadPair.get(1).getValue() && signaturePair.getValue())
			return Pair.of("validatePdndJwt successful", true);
		else
		{
			log.error("Pdnd jwt token is invalid");
			String msg = "";
			if(!(headerPair.getValue()))
				msg = msg + " "+ headerPair.getKey();
			if(!(payloadPair.get(0).getValue()))
				msg = msg + " " +payloadPair.get(0).getKey();
			if(!(payloadPair.get(1).getValue()))
				msg = msg + " "+ payloadPair.get(1).getKey();
			if(!(signaturePair.getValue()))
				msg = msg + " "+ signaturePair.getKey();
			return Pair.of("pdnd jwt"+msg, false);
		}
    	
    }
    
    private static Pair<String, Boolean> validatePdndJwtHeader(org.json.JSONObject headerJSON, JWTInfo jwtInfo)
    {
    	String typ = "";
    	if(jwtInfo.getJwtType() != null && jwtInfo.getJwtType().equals("JWS_Audit"))
    	{
    		typ = getIfStringExistCheckValue(headerJSON, "typ", "JWT");
    		log.info("typ is different for audit_rest_01 and audit_rest_02");
    	}
    	else
    		typ = getIfStringExistCheckValue(headerJSON, "typ", "at+jwt");
		String alg = getIfStringExist(headerJSON, "alg");
		String kid = getIfStringExist(headerJSON, "kid");
		jwtInfo.setPdndKid(kid);
		Map<String, String> map = Stream.of(new String[][] {
			  { "typ", typ }, 
			  { "alg", alg },
			  { "kid", kid }
			}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
		return validateString(map, null);
    }
    
    private static List<Pair<String, Boolean>> validatePdndJwtPayload(org.json.JSONObject payloadJSON, JWTInfo jwtInfo, JWTClaims jwtClaims)
    {
		String aud = getIfStringExist(payloadJSON, "aud");
		jwtInfo.setPdndAud(aud);
		String sub = getIfStringExist(payloadJSON, "sub");
		String iss = getIfStringExist(payloadJSON, "iss");
		jwtInfo.setPdndIss(iss);
		String jti = getIfStringExist(payloadJSON, "jti");
		String client_id = getIfStringExist(payloadJSON, "client_id");
		jwtInfo.setPdndClientId(client_id);
		String purposeId = getIfStringExist(payloadJSON, "purposeId");
		jwtInfo.setPdndPurposeId(purposeId);
		long nbf = getIfLongExist(payloadJSON, "nbf");
		long exp = getIfLongExist(payloadJSON, "exp");
		long iat = getIfLongExist(payloadJSON, "iat");

		Map<String, String> mapString = null;
		Map<String, Long> mapLong = null;
		List<Pair<String, Boolean>> list = null;
		mapString = Stream.of(new String[][] {
			  { "aud", aud }, 
			  { "sub", sub }, 
			  { "iss", iss },
			  { "jti", jti },
			  { "client_id", client_id },
			  { "purposeId", purposeId },
			}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
		if(jwtInfo.getJwtType() != null && jwtInfo.getJwtType().equals("JWS_Audit"))
		{
			mapString.remove("sub");
			mapString.remove("client_id");
			log.info("sub and client_id are not mandatory for audit_rest_01 and audit_rest_02");
		}
		else
		{
			jwtClaims = null;
			log.info("it's a pdnd voucher validation");
		}
		mapLong = Stream.of(new Object[][] {
			  { "nbf", nbf }, 
			  { "exp", exp }, 
			  { "iat", iat }
			}).collect(Collectors.toMap(data -> (String)data[0], data -> (Long)data[1]));
		if(jwtInfo.getDigest() != null && !(jwtInfo.getDigest().equals("")))
    	{
    		log.info("Calculated digest: "+jwtInfo.getDigest());
    		org.json.JSONObject jwsAuditDigestObj = getIfJSONObjectExist(payloadJSON, "digest");
    		if(jwsAuditDigestObj != null)
    		{
    			String alg = jwsAuditDigestObj.getString("alg");
    			String jwsAuditDigest = jwsAuditDigestObj.getString("value");
    			log.info("Digest inside pdnd jwt: "+jwsAuditDigest);
    			if(!(alg.equals("SHA256")) || !(jwsAuditDigest.equals(jwtInfo.getDigest())))
    				mapString.put("jwsAuditDigest", "JWS audit digest different from the one inside PDND jwt");
    		}
    	}
		 list = new ArrayList<Pair<String, Boolean>>(
		            Arrays.asList(validateString(mapString, jwtClaims), validateLong(mapLong)));
		 return list;
    }
    
	public static Pair<String, Boolean> validatePdndSignature(String pdndjwt, String pdndJwksUrl, String pdnd_api_url, JWTInfo jwtInfo) 
	{
		boolean isValid = false;
		PublicKey publicKey = null;
		SignedJWT jwtSigned;
		String content = "", pdndAccessToken = "";
		
		if (getModiCacheEnable() && getModiCache().get(jwtInfo.getPdndKid()) != null) {
    		publicKey = (PublicKey) getModiCache().get(jwtInfo.getPdndKid());
    		log.info("Public key FOUND in cache");
    	}
        else
        {
        	pdndAccessToken = retrieveAccessTokenPdndApiInterop(jwtInfo);
        	if(!(pdndAccessToken.equals("")))
        	{
        		log.info("client api interop enabled");
    			content = callExternalUrl(pdnd_api_url+jwtInfo.getPdndKid(), pdndAccessToken);
        		publicKey = retrievePubKeyFromJWKS(content, "");
        		if(getModiCacheEnable())
        		{
        			getModiCache().put(jwtInfo.getPdndKid(), publicKey);
            		log.info("Public key PUT in cache");	
        		}
        	}
        	else
        	{
        		log.info("client api interop disabled");
        		content = callExternalUrl(pdndJwksUrl, "");
        		publicKey = retrievePubKeyFromJWKS(content, jwtInfo.getPdndKid());
        	}
        }
		if (publicKey != null)
		{
			String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
			jwtInfo.setPdndPublicKey(publicKeyString);
			log.info("pdnd public key signature JWKS: " + jwtInfo.getPdndPublicKey());
		}
		try {
			jwtSigned = SignedJWT.parse(pdndjwt);
			isValid = verifyTokenSignature(jwtSigned, publicKey);
		} catch (ParseException e) {
			log.error("Error while validating JWT signature", e);
		}
		if (isValid)
			return Pair.of("pdnd valid signature", isValid);
		else
			return Pair.of("pdnd signature not valid", false);

	}
    
    
    public static boolean verifyTokenSignature(SignedJWT jwt, PublicKey publicKey) {

        JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
        if ((JWSAlgorithm.RS256.equals(algorithm) || JWSAlgorithm.RS512.equals(algorithm) ||
                JWSAlgorithm.RS384.equals(algorithm)) || JWSAlgorithm.PS256.equals(algorithm)) {
            try {
                JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                return jwt.verify(jwsVerifier);
            } catch (JOSEException e) {
                log.error("Error while verifying JWT signature", e);
                return false;
            }
            catch (IllegalArgumentException e) {
                log.error(e.getMessage());
                return false;
            }
        } else {
            log.error("Public key is not a RSA");
            return false;
        }
    }
    
	private static javax.security.cert.X509Certificate retrieveCertificateFromContent(String base64EncodedCertificate)
			throws APIManagementException {

		if (base64EncodedCertificate != null) {
			byte[] bytes = org.apache.commons.codec.binary.Base64.decodeBase64(base64EncodedCertificate.getBytes(StandardCharsets.UTF_8));
			try (InputStream inputStream = new ByteArrayInputStream(bytes)) {
				return javax.security.cert.X509Certificate.getInstance(inputStream);
			} catch (IOException | javax.security.cert.CertificateException e) {
				String msg = "Error while converting into X509Certificate";
				//log.error(msg, e);
				log.error(msg);
				//throw new APIManagementException(msg, e);
			}
		}
		return null;
	}
    
    
	private static Pair<String, Boolean> validateSignature(String jwt, JWTInfo jwtInfo) {
		boolean isValid = false, pubKeyNotAvailable = false;
		PublicKey publicKey = null;
		if (jwtInfo.getCertificateReference() != null && !(jwtInfo.getCertificateReference().equals(""))) {
			try {
				javax.security.cert.X509Certificate x509certificate = retrieveCertificateFromContent(
						jwtInfo.getCertificateReference());
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
		}
		return Pair.of("signature not valid", false);

	}
    
    private static boolean checkDateValidity(long firstDateTime, long secondDateTime) {

		//a minute of acceptable clock skew
		long timestampSkew = 60;
		Date first = DateUtils.fromSecondsSinceEpoch(firstDateTime);
		Date second = DateUtils.fromSecondsSinceEpoch(secondDateTime);
		return DateUtils.isAfter(first, second, timestampSkew);
		}
    
    public static String callExternalUrl(String urlString, String pdndAccessToken) {
		String urlOutput = "";
		try {
			URI uri = new URL(urlString).toURI();
            log.info("Call URL esterno: " + uri.toASCIIString());
			try (CloseableHttpClient httpClient = (CloseableHttpClient) APIUtil.getHttpClient(0, "https")) {
				HttpGet httpGet = new HttpGet(uri);
				if(!(pdndAccessToken.equals("")))
					httpGet.setHeader("Authorization", "Bearer "+ pdndAccessToken);

				try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
					log.info("External URL response: " + response);

					BufferedReader reader = new BufferedReader(
							new InputStreamReader(response.getEntity().getContent(), StandardCharsets.UTF_8));
					String inputLine;
					StringBuilder stringBuilder = new StringBuilder();

					while ((inputLine = reader.readLine()) != null) {
						stringBuilder.append(inputLine);
					}

					if (!(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK)) {
						String reasonPhrase = response.getStatusLine().getReasonPhrase();
						log.error("External URL response\n\t" + response.getStatusLine().getStatusCode() + ": "
								+ reasonPhrase + "\n\t\t" + stringBuilder);
						httpGet.releaseConnection();
						throw new HttpClientError(reasonPhrase);
					}
					urlOutput = stringBuilder.toString();
					return urlOutput;

				} finally {
					httpGet.releaseConnection();
				}

			} catch (IOException e) {
				log.error("External URL call failed: " + ExceptionUtils.getStackTrace(e));
			}
		} catch (URISyntaxException | MalformedURLException e) {
			log.error("It's not a valid URL.");
		}

		return urlOutput;
	}
    
    
    public static PublicKey retrievePubKeyFromJWKS(String jwksInfo, String kid) 
    {
	 	PublicKey rsaPublicKey = null;
	 	try
	 	{
	 	if(!(kid.equals("")))
	 	{
	 		log.info("Returned a list of keys");
	 		JWKSet jwkSet = JWKSet.parse(jwksInfo);
	        List<JWK> list = jwkSet.getKeys();
	        for(JWK jwk : list)
	        {
	        	if (jwk instanceof RSAKey) {
	        		RSAKey keyByKeyId = (RSAKey) jwk;
	                rsaPublicKey = keyByKeyId.toRSAPublicKey();
	                if(!(kid.equals("")) && keyByKeyId.getKeyID().equals(kid))
	                	break;
	        	} else if (jwk instanceof ECKey) {
	        		ECKey keyByKeyId = (ECKey) jwk;
	                rsaPublicKey = keyByKeyId.toECPublicKey();
	                if(!(kid.equals("")) && keyByKeyId.getKeyID().equals(kid))
	                	break;
	        	}
	        }
	 	}
	 	else
	 	{
	 		log.info("Returned a single JWK");
	 		JWK jwk = JWK.parse(jwksInfo);
        	if (jwk instanceof RSAKey) {
        		RSAKey keyByKeyId = (RSAKey) jwk;
                rsaPublicKey = keyByKeyId.toRSAPublicKey();
        	} else if (jwk instanceof ECKey) {
        		ECKey keyByKeyId = (ECKey) jwk;
                rsaPublicKey = keyByKeyId.toECPublicKey();
        	}
	 	}
	 	
	 	}
	 	catch(JOSEException | ParseException e)
	 	{
	 		log.error("Error with JSON parsing.");
	 	}
        return rsaPublicKey;
        
    }
    
    public static String providePdnd(PdndPKMapping pdndJwt) throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException, MalformedURLException, APISecurityException {
		String jwt = "";
		if (pdndJwt.isEnabled() != null && pdndJwt.isEnabled()) {
			log.info(ModiLogUtils.PDND_TOKEN_REQUEST_START);
			ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

			byte[] encoded = org.apache.commons.codec.binary.Base64.decodeBase64((pdndJwt.getPrivkey().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")).getBytes(StandardCharsets.UTF_8));
			PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encoded);
			RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);
			
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
					.type(JOSEObjectType.JWT)
					.keyID(pdndJwt.getKid())
					.build();
			log.debug("PDND JWT header: " + header.toString());
			
			Builder jwtBuilder = new JWTClaimsSet.Builder()
					 .issueTime(new Date(issued.toInstant().toEpochMilli()))
					 .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
					 .subject(pdndJwt.getSub())
					 .audience(pdndJwt.getAud())
					 .jwtID(UUID.randomUUID().toString())
					 .issuer(pdndJwt.getIss());

			JWTClaimsSet assertion = jwtBuilder.build();
			log.debug("PDND JWT payload: " + assertion.toString());

			SignedJWT signedJWT = new SignedJWT(header, assertion);
			signedJWT.sign(new RSASSASigner(privateKey));

			String clientAssertion = signedJWT.serialize();
			log.debug("PDND client assertion: " + clientAssertion);


	        URL urlObject;
	        StringBuilder payload = new StringBuilder();
	        urlObject = new URL(pdndJwt.getUri());

	        try (CloseableHttpClient httpClient = (CloseableHttpClient) APIUtil
	                .getHttpClient(urlObject.getPort(), urlObject.getProtocol())) {
				log.debug("httpClient: " + httpClient);
	            HttpPost httpPost = new HttpPost(pdndJwt.getUri());
	            log.debug("PDND Uri: " + pdndJwt.getUri());
	            httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");
	            payload.append("grant_type=client_credentials");
	            payload.append("&");

	            log.debug("client id: "+pdndJwt.getClientId());
	            if (StringUtils.isNotBlank(pdndJwt.getClientId())) {
	            	payload.append("client_id=" + pdndJwt.getClientId());
	            	payload.append("&");
	            }
	            
	            payload.append("client_assertion=" + clientAssertion);
	            payload.append("&");
	            payload.append("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

	            log.debug("PDND Payload: " + payload.toString());
	            httpPost.setEntity(new StringEntity(payload.toString()));



	            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
	            	log.info("PDND response: " + response);

	            	BufferedReader reader = new BufferedReader(new InputStreamReader(response
	                        .getEntity().getContent(), StandardCharsets.UTF_8));
	                String inputLine;
	                StringBuilder stringBuilder = new StringBuilder();

	                while ((inputLine = reader.readLine()) != null) {
	                    stringBuilder.append(inputLine);
	                }

	                if (!(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK)) {
	            		String reasonPhrase = response.getStatusLine().getReasonPhrase();
		            	log.error("PDND response\n\t" + response.getStatusLine().getStatusCode() + ": " + reasonPhrase + "\n\t\t" + stringBuilder);
		            	httpPost.releaseConnection();
	            		throw new APISecurityException(response.getStatusLine().getStatusCode(), stringBuilder.toString());
	            	}

	                JSONObject json = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST).parse(stringBuilder.toString());	                          
	                jwt = json.get("access_token").toString();	                	                
	                log.debug(jwt);
	                
	            } catch (net.minidev.json.parser.ParseException pe) {
	            	log.error("Can't get access token: " + ExceptionUtils.getStackTrace(pe));
	            } finally {
	                httpPost.releaseConnection();
	            }
	        } catch (IOException e) {
	        	log.error("Error providing PDND: " + ExceptionUtils.getStackTrace(e));
			}
		log.info(ModiLogUtils.PDND_TOKEN_REQUEST_FINISH);
		}

		return jwt;
	}
    
	private static String retrieveAccessTokenPdndApiInterop(JWTInfo jwtInfo) {
		String pdndAccessToken = "";
		try {
			String applicationUUID = new SubscriptionService().getApplicationUUIDByKid(jwtInfo.getPdndKid());
			log.info("applicationUUID: " + applicationUUID);
			if (!(applicationUUID.equals(""))) {
					PdndPKMapping pdndPKMapping = new SubscriptionService()
							.getCertificatesOutboundPdnd(applicationUUID);
					pdndAccessToken = providePdnd(pdndPKMapping);
					log.info("pdndAccessToken: " + pdndAccessToken);
			}
		} catch (URISyntaxException | DataLoadingException e) {
			log.error("Error while invoking api: " + ExceptionUtils.getStackTrace(e));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | JOSEException | MalformedURLException
				| APISecurityException e) {
			log.error("Error retrieving PDND access token: " + ExceptionUtils.getStackTrace(e));
		}
		return pdndAccessToken;

	}
    
    private static String getPdndJwksUrl()
    {
    	String pdndJwksUrl = "";
		Properties prop = new Properties();
		try (InputStream inputStream = JWTValidator.class.getClassLoader().getResourceAsStream("config.properties")) {
			prop.load(inputStream);
			pdndJwksUrl = prop.getProperty("pdndJwksUrl");
        } catch (IOException e) {
            log.error("Error occurred while reading properties", e);
        }
		return pdndJwksUrl;
    }
    
    
    private static Cache getModiCache() {

        return CacheProviderWeModi.getWeModiCache();
    }
    
    private static boolean getModiCacheEnable() {

        return CacheProviderWeModi.isEnabledCache();
    }

}
