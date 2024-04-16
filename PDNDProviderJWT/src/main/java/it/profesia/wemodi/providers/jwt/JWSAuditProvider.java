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
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.wso2.carbon.apimgt.api.APIManagementException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.providers.utils.ProvidersUtils;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

public class JWSAuditProvider {
	private JSONObject customClaims = null;
	private ModiPKMapping modiPKMapping = null;
    private Boolean isAuditRest02 = false;
    private Boolean isAuditRest01Modi = false;
    private Boolean isAuditRest01Pdnd = false;
    private String purposeId = "";
    private String certificateReference = "";

	private static final Log log = LogFactory.getLog(JWSAuditProvider.class);

    private JWSAuditProvider() {

    }

    /**
     * Ottiene le configurazioni JWS Audit in base al consumer key del Service Provider WSO2
     * 
     * @param consumerKey Il consumer Key dell'Application WSO2
     *
     * @return JWS Provider
     * @throws APIManagementException 
     * @throws URISyntaxException 
     */
    public static JWSAuditProvider FromConsumerKey(String consumerKey) throws APIManagementException, URISyntaxException {
        JWSAuditProvider provider = new JWSAuditProvider();
        /*ModiPrivateKey modiPrivateKey = new ModiPrivateKeyImpl();
        provider.modiPKMapping = modiPrivateKey.getPrivateKeyByConsumerKey(consumerKey);*/
        provider.modiPKMapping = new SubscriptionService().getPrivateKeyByConsumerKeyForModi(consumerKey);
        return provider;
    }

    /**
     * Ottiene le configurazioni JWS Audit in base allo UUID dell'application WSO2
     * 
     * @param consumerKey UUID dell'application WSO2
     *
     * @return JWT Provider
     * @throws APIManagementException 
     
    public static JWSAuditProvider FromApplicationUUID(String applicationUUID) throws APIManagementException {
        JWSAuditProvider provider = new JWSAuditProvider();
        ModiPrivateKey modiPrivateKey = new ModiPrivateKeyImpl();
        provider.modiPKMapping = modiPrivateKey.getPrivateKey(applicationUUID);
        return provider;
    }*/

    /**
     * Recupero del JWS Audit ModI e PDND
     * 
     * @return JWS Audit
     * @throws OAuthSystemException
     */
    public String provideJWSAudit() throws OAuthSystemException {
        String jwsAudit = "";

        ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

        try(PEMParser pemParser = new PEMParser(new StringReader(modiPKMapping.getPrivkey()))) {
            PemObject pemObject = pemParser.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(content);
            RSAPrivateKey privateKey = (RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);

            JWSHeader header;
            if (isAuditRest01Modi) {
                log.trace("Header JWS secondo specifiche ID_AUDIT_REST_01 ModI.");
                header = ProvidersUtils.buildJWTHeader(getCertificateReference(), modiPKMapping.getCertificate());
            } else {
                header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(JOSEObjectType.JWT)
                        .keyID(modiPKMapping.getKid())
                        .build();
            }
            log.debug("JWS Audit header: " + header.toString());

            Builder jwtBuilder = new JWTClaimsSet.Builder()
                        .issueTime(new Date(issued.toInstant().toEpochMilli()))
                        .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
                        .notBeforeTime(new Date(issued.plusDays(0).toInstant().toEpochMilli()))
                        .audience(modiPKMapping.getAud())
                        .jwtID(UUID.randomUUID().toString())
                        .issuer(modiPKMapping.getIss());
            if (!isAuditRest01Modi) {
                jwtBuilder.claim("purposeId", purposeId);
            }

            if(isAuditRest02) {
                long dnonce = ThreadLocalRandom.current().nextLong(1000000000000L, 10000000000000L);
                jwtBuilder.claim("dnonce", dnonce);
            }

            if (customClaims != null) {
                for (String key : customClaims.keySet()) {
                    Object claim = customClaims.get(key);
                    jwtBuilder.claim(key, claim);
                }
            }

            JWTClaimsSet payload = jwtBuilder.build();
            log.debug("JWS audit payload: " + payload.toString());

            SignedJWT signedJWT = new SignedJWT(header, payload);
            signedJWT.sign(new RSASSASigner(privateKey));

            jwsAudit = signedJWT.serialize();
            log.debug("JWS Audit: " + jwsAudit);
        } catch (JOSEException | InvalidKeySpecException | NoSuchAlgorithmException | CertificateException | IOException e) {
            String msg = "Errore nella generazione del JWS Audit.";
            log.error(msg, e);
            throw new OAuthSystemException(msg, e);
        }

        return jwsAudit;
    }

    public JSONObject getCustomClaims() {
        return customClaims;
    }

    public void setCustomClaims(String customClaims) throws ParseException {
        if (StringUtils.isNotBlank(customClaims))
            this.customClaims = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(customClaims);
    }

    public void setCustomClaims(JSONObject customClaims) {
        this.customClaims = customClaims;
    }

    public ModiPKMapping getModiPKMapping() {
        return modiPKMapping;
    }

    public void setModiPKMapping(ModiPKMapping modiPKMapping) {
        this.modiPKMapping = modiPKMapping;
    }
    
    public Boolean getIsAuditRest01Modi() {
        return isAuditRest01Modi;
    }

    public void setIsAuditRest01Modi(Boolean isAuditRest01Modi) {
        this.isAuditRest01Modi = isAuditRest01Modi;
    }
    
    public Boolean getIsAuditRest01Pdnd() {
        return isAuditRest01Pdnd;
    }

    public void setIsAuditRest01Pdnd(Boolean isAuditRest01Pdnd) {
        this.isAuditRest01Pdnd = isAuditRest01Pdnd;
    }

    public Boolean getIsAuditRest02() {
        return isAuditRest02;
    }

    public void setIsAuditRest02(Boolean isAuditRest02) {
        this.isAuditRest02 = isAuditRest02;
    }

    public String getPurposeId() {
        return purposeId;
    }

    public void setPurposeId(String purposeId) {
        this.purposeId = purposeId;
    }
    
    public String getCertificateReference() {
		return certificateReference;
	}

	public void setCertificateReference(String certificateReference) {
		this.certificateReference = certificateReference;
	}

}
