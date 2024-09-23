package it.profesia.wemodi.providers.jwt;

import java.io.IOException;
import java.io.StringReader;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.wso2.carbon.apimgt.api.APIManagementException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import it.profesia.wemodi.subscriptions.SubscriptionService;

import it.profesia.wemodi.providers.utils.ProvidersUtils;

public class JWTTokenModIProvider {
	private ModiPKMapping modiPKMapping = null;
	private Boolean isIdAuthRest02 = false;
	private Boolean isIntegrityRest01 = false;
	private Boolean isIntegrityRest02 = false;
	private String certificateReference = "";
	private String sha256Base64Digest = "";
	private Map headers = null;

	private static final Log log = LogFactory.getLog(JWTTokenModIProvider.class);

    private JWTTokenModIProvider() {

    }

    /**
     * Ottiene le configurazioni JWT ModI in base al consumer key del Service Provider WSO2
     * 
     * @param consumerKey Il consumer Key dell'Application WSO2
     *
     * @return JWT Provider
     * @throws APIManagementException 
     * @throws URISyntaxException 
     */
    public static JWTTokenModIProvider FromConsumerKey(String consumerKey) throws APIManagementException, URISyntaxException {
        JWTTokenModIProvider provider = new JWTTokenModIProvider();
        /*ModiPrivateKey modiPrivateKey = new ModiPrivateKeyImpl();
        provider.modiPKMapping = modiPrivateKey.getPrivateKeyByConsumerKey(consumerKey);*/
        provider.modiPKMapping = new SubscriptionService().getPrivateKeyByConsumerKeyForModi(consumerKey);
        return provider;
    }

    /**
     * Ottiene le configurazioni JWT ModI in base allo UUID dell'application WSO2
     * 
     * @param consumerKey UUID dell'application WSO2
     *
     * @return JWT Provider
     * @throws APIManagementException 
     
    public static JWTTokenModIProvider FromApplicationUUID(String applicationUUID) throws APIManagementException {
        JWTTokenModIProvider provider = new JWTTokenModIProvider();
        ModiPrivateKey modiPrivateKey = new ModiPrivateKeyImpl();
        provider.modiPKMapping = modiPrivateKey.getPrivateKey(applicationUUID);
        return provider;
    }*/

    /**
     * Recupero del JWT ModI
     * 
     * @return JWT ModI
     * @throws OAuthSystemException
     */
    public String provideModi() throws OAuthSystemException{
		String jwt = "";
		
		JWSHeader header = null;
		
		try(PEMParser pemParser = new PEMParser(new StringReader(modiPKMapping.getPrivkey()))) {
            PemObject pemObject = pemParser.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(content);
		
            if (BooleanUtils.isTrue(isIntegrityRest02)) {
                header = ProvidersUtils.buildJWTHeaderWithKid(modiPKMapping.getKid());
            }
            else
                header = ProvidersUtils.buildJWTHeader(getCertificateReference(), modiPKMapping.getCertificate());
            log.debug("ModI JWT header: " + header.toString());

    		ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

            Builder payloadBuilder = new JWTClaimsSet.Builder()
                    .issueTime(new Date(issued.toInstant().toEpochMilli()))
                    .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
                    .notBeforeTime(new Date(issued.plusDays(0).toInstant().toEpochMilli()))
                    .audience(modiPKMapping.getAud())
                    .subject(modiPKMapping.getSub())
                    .issuer(modiPKMapping.getIss());

            if (BooleanUtils.isTrue(isIdAuthRest02)) {
                payloadBuilder = payloadBuilder.jwtID(UUID.randomUUID().toString());
            }

            if (BooleanUtils.isTrue(isIntegrityRest01)
                    || BooleanUtils.isTrue(isIntegrityRest02)) {
                /**
			 * Il pattern INTEGRITY_REST_01 prevede il claim signed_headers nel JWT
			 *   se non ci sono headers da firmare il claim va ignorato
			 */
    			String digestAlgorithm = "SHA-256";
			
                List<Map<String, Object>> signedHeaders = new ArrayList<Map<String, Object>>();
                Map<String,Object> digestMap = new HashMap<String, Object>(1);

                if (StringUtils.isNotEmpty(sha256Base64Digest)) {
                    digestMap.put("digest", digestAlgorithm + "=" + sha256Base64Digest);

                    headers.put("digest", digestAlgorithm + "=" + sha256Base64Digest);

                    signedHeaders.add(digestMap);
                }

                if (headers.containsKey("content-type")){
                    Map<String,Object> contentTypeMap = new HashMap<String, Object>(1);
                    contentTypeMap.put("content-type", headers.get("content-type"));

                    signedHeaders.add(contentTypeMap);
                }
			
                if (headers.containsKey("content-encoding")){
                    Map<String,Object> contentEncodingMap = new HashMap<String, Object>(1);
                    contentEncodingMap.put("content-encoding", headers.get("content-encoding"));

                    signedHeaders.add(contentEncodingMap);
                }

                log.debug("Signed Headers: " + signedHeaders.stream().map(Object::toString).collect(Collectors.joining(",")));
                if (!signedHeaders.isEmpty())
                    payloadBuilder.claim("signed_headers", signedHeaders);
            }

            JWTClaimsSet payload = payloadBuilder.build();
            log.debug("ModI JWT payload: " + payload.toString());

            /*byte[] pkEncoded = org.apache.commons.codec.binary.Base64.decodeBase64((modiPKMapping.getPrivkey().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")).getBytes(StandardCharsets.UTF_8));
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pkEncoded);*/
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);

            SignedJWT signedJWT = new SignedJWT(header, payload);
            signedJWT.sign(new RSASSASigner(privateKey));

            jwt = signedJWT.serialize();
            log.debug("ModI JWT: " + jwt);
        }
		catch (JOSEException | InvalidKeySpecException | NoSuchAlgorithmException | CertificateException | IOException e) {
            String msg = "Errore nella generazione del JWS Audit.";
            log.error(msg, e);
            throw new OAuthSystemException(msg, e);
        }
		return jwt;
	}

    public ModiPKMapping getModiPKMapping() {
        return modiPKMapping;
    }

    public void setModiPKMapping(ModiPKMapping modiPKMapping) {
        this.modiPKMapping = modiPKMapping;
    }
    
    public Boolean getIsIdAuthRest02() {
		return isIdAuthRest02;
	}

	public void setIsIdAuthRest02(Boolean isIdAuthRest02) {
		this.isIdAuthRest02 = isIdAuthRest02;
	}

	public Boolean getIsIntegrityRest01() {
		return isIntegrityRest01;
	}

	public void setIsIntegrityRest01(Boolean isIntegrityRest01) {
		this.isIntegrityRest01 = isIntegrityRest01;
	}

	public Boolean getIsIntegrityRest02() {
		return isIntegrityRest02;
	}

	public void setIsIntegrityRest02(Boolean isIntegrityRest02) {
		this.isIntegrityRest02 = isIntegrityRest02;
	}

	public String getCertificateReference() {
		return certificateReference;
	}

	public void setCertificateReference(String certificateReference) {
		this.certificateReference = certificateReference;
	}
	
	public String getSha256Base64Digest() {
		return sha256Base64Digest;
	}

	public void setSha256Base64Digest(String sha256Base64Digest) {
		this.sha256Base64Digest = sha256Base64Digest;
	}

	public Map getHeaders() {
		return headers;
	}

	public void setHeaders(Map headers) {
		this.headers = headers;
	}

}
