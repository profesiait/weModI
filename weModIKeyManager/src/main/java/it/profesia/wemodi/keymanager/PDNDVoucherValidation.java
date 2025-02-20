package it.profesia.wemodi.keymanager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.httpclient.HttpClientError;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;


public class PDNDVoucherValidation {
	
	private static final Log log = LogFactory.getLog(PDNDVoucherValidation.class);

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
	
    
    private static Pair<String, Boolean> validateString(Map<String, String> map)
	{
    	 for (Map.Entry<String, String> entry : map.entrySet()) {
    		 if  (entry.getValue() == null || entry.getValue().equals(""))
				 return Pair.of(entry.getKey()+" not valid", false);
    	 }
    	 return Pair.of("validateString successful", true);
	}
    
    public static boolean pdndJwtValidation(String pdndJwt)
    {
    	Pair<String, Boolean> pdndValidationPair = validatePdndJwt(pdndJwt);
    	if(pdndValidationPair.getValue())
    		return true;
    	else
    	{
    		String msg = " "+pdndValidationPair.getKey();
    		log.info("pdndJwtValidation - " + msg);
    		return false;
    	}
    	
    }
    
    private static Pair<String, Boolean> validatePdndJwt(String pdndJwt)
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
		Pair<String, Boolean> headerPair = validatePdndJwtHeader(headerJSON);
		List<Pair<String, Boolean>> payloadPair = validatePdndJwtPayload(payloadJSON);
		String pdndJwksUrl = "https://uat.interop.pagopa.it/.well-known/jwks.json";
		Pair<String, Boolean> signaturePair = validatePdndSignature(pdndJwt, pdndJwksUrl);
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
    
    private static Pair<String, Boolean> validatePdndJwtHeader(org.json.JSONObject headerJSON)
    {
    	String typ = getIfStringExistCheckValue(headerJSON, "typ", "at+jwt");
		String alg = getIfStringExist(headerJSON, "alg");
		String kid = getIfStringExist(headerJSON, "kid");
		Map<String, String> map = Stream.of(new String[][] {
			  { "typ", typ }, 
			  { "alg", alg },
			  { "kid", kid }
			}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
		return validateString(map);
    }
    
    private static List<Pair<String, Boolean>> validatePdndJwtPayload(org.json.JSONObject payloadJSON)
    {
		String aud = getIfStringExist(payloadJSON, "aud");
		String sub = getIfStringExist(payloadJSON, "sub");
		String iss = getIfStringExist(payloadJSON, "iss");
		String jti = getIfStringExist(payloadJSON, "jti");
		String client_id = getIfStringExist(payloadJSON, "client_id");
		String purposeId = getIfStringExist(payloadJSON, "purposeId");
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
		mapLong = Stream.of(new Object[][] {
			  { "nbf", nbf }, 
			  { "exp", exp }, 
			  { "iat", iat }
			}).collect(Collectors.toMap(data -> (String)data[0], data -> (Long)data[1]));
		 list = new ArrayList<Pair<String, Boolean>>(
		            Arrays.asList(validateString(mapString), validateLong(mapLong)));
		 return list;
    }
    
	public static Pair<String, Boolean> validatePdndSignature(String pdndjwt, String pdndJwksUrl) 
	{
		boolean isValid = false;
		PublicKey publicKey = null;
		SignedJWT jwtSigned;
		String content = callExternalUrl(pdndJwksUrl);
		try {
			jwtSigned = SignedJWT.parse(pdndjwt);
			String kid = jwtSigned.getHeader().getKeyID();
			log.info("Pdnd Kid: " + kid);
			publicKey = retrievePubKeyFromJWKS(content, kid);
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
    
    private static boolean checkDateValidity(long firstDateTime, long secondDateTime) {

		//a minute of acceptable clock skew
		long timestampSkew = 60;
		
		/*Date first = new Date(firstDateTime);
		Date second = new Date(secondDateTime);*/
		Date first = DateUtils.fromSecondsSinceEpoch(firstDateTime);
		Date second = DateUtils.fromSecondsSinceEpoch(secondDateTime);
		return DateUtils.isAfter(first, second, timestampSkew);
		}
    
    private static String callExternalUrl(String urlString) {
		String urlOutput = "";
		try {
			URI uri = new URL(urlString).toURI();
            log.info("Call URL esterno: " + uri.toASCIIString());
			try (CloseableHttpClient httpClient = (CloseableHttpClient) APIUtil.getHttpClient(0, "https")) {
				HttpGet httpGet = new HttpGet(uri);

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
						httpClient.close();
						throw new HttpClientError(reasonPhrase);
					}
					urlOutput = stringBuilder.toString();
					return urlOutput;

				} finally {
					httpClient.close();
				}

			} catch (IOException e) {
				log.error("External URL call failed: " + ExceptionUtils.getStackTrace(e));
			}
		} catch (URISyntaxException | MalformedURLException e) {
			log.error("It's not a valid URL.");
		}

		return urlOutput;
	}
    
    
    private static PublicKey retrievePubKeyFromJWKS(String jwksInfo, String kid) 
    {
	 	PublicKey rsaPublicKey = null;
	 	try
	 	{
	 	if(!(kid.equals("")))
	 	{
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
	 	
	 	}
	 	catch(JOSEException | ParseException e)
	 	{
	 		log.error("Error with JSON parsing.");
	 	}
        return rsaPublicKey;
        
    }

}
