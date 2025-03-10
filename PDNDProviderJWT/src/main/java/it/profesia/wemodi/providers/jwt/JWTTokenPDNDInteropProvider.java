package it.profesia.wemodi.providers.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.UUID;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

public class JWTTokenPDNDInteropProvider {
    private static final Log log = LogFactory.getLog(JWTTokenPDNDInteropProvider.class);

    private PdndPKMapping pdndPKMapping = null;

	private JWTTokenPDNDInteropProvider() {

    }

   

    /**
     * Ottiene le configurazioni PDND in base allo UUID dell'application WSO2
     * 
     * @param applicationUUID UUID dell'Application WSO2 legata a PDND
     * 
     * @return JWT Provider per PDND
     * @throws APIManagementException
     * @throws URISyntaxException 
     */
     
    public static JWTTokenPDNDInteropProvider FromApplicationUUID(String applicationUUID) throws APIManagementException, URISyntaxException {
    	JWTTokenPDNDInteropProvider provider = new JWTTokenPDNDInteropProvider();
        provider.pdndPKMapping = new SubscriptionService().getCertificatesOutboundPdnd(applicationUUID);
        return provider;
    }

    /**
     * Recupero del Voucher di interoperabilitÓ (access token JWT) da PDND tramite JWT Assertion
     * 
     * @return Voucher PDND di interoperabilitÓ (access token)
     * @throws OAuthSystemException
     */
    public String PDNDJwtAssertion() throws OAuthSystemException {
        String voucher = "";
        
        try(PEMParser pemParser = new PEMParser(new StringReader(pdndPKMapping.getPrivkey())))
        {
	        PemObject pemObject = pemParser.readPemObject();
	        byte[] content = pemObject.getContent();
	        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(content);
	        
            URL urlObject = new URL(pdndPKMapping.getUri());
            CloseableHttpClient httpClient = (CloseableHttpClient) APIUtil.getHttpClient(urlObject.getPort(), urlObject.getProtocol());
            log.trace("CloseableHttpClient: " + httpClient);
            HttpPost httpPost = new HttpPost(pdndPKMapping.getUri());

            log.trace("PDND Uri: " + pdndPKMapping.getUri());
            httpPost.setHeader(APIConstants.HEADER_CONTENT_TYPE, APIConstants.OAuthConstants.APPLICATION_X_WWW_FORM_URLENCODED);

            StringBuilder payload = new StringBuilder();
            payload.append(APIConstants.OAuthConstants.CLIENT_CRED_GRANT_TYPE);
            payload.append("&");

            log.trace("PDND client id: "+pdndPKMapping.getClientId());
            if (StringUtils.isNotBlank(pdndPKMapping.getClientId())) {
                payload.append("client_id=" + pdndPKMapping.getClientId());
                payload.append("&");
            }
            log.trace("PDND scope: "+pdndPKMapping.getScope());
            if (StringUtils.isNotBlank(pdndPKMapping.getScope())) {
                payload.append("scope=" + pdndPKMapping.getScope());
                payload.append("&");
            }

            RSAPrivateKey privateKey = (RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(pkcs8EncodedKeySpec);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID(pdndPKMapping.getKid())
                .build();
            log.trace("PDND client assertion JWT header: " + header.toString());

            ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

            Builder jwtBuilder = new JWTClaimsSet.Builder()
                    .issueTime(new Date(issued.toInstant().toEpochMilli()))
                    .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
                    .subject(pdndPKMapping.getSub())
                    .audience(pdndPKMapping.getAud())
                    .jwtID(UUID.randomUUID().toString())
                    .issuer(pdndPKMapping.getIss());
            

            JWTClaimsSet assertion = jwtBuilder.build();
            log.debug("PDND client assertion JWT payload: " + assertion.toString());

            SignedJWT signedJWT = new SignedJWT(header, assertion);
            signedJWT.sign(new RSASSASigner(privateKey));

            String clientAssertion = signedJWT.serialize();
            log.trace("PDND client assertion: " + clientAssertion);

            payload.append("client_assertion=" + clientAssertion);
            payload.append("&");
            payload.append("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            log.trace("PDND Payload: " + payload.toString());

            httpPost.setEntity(new StringEntity(payload.toString()));
            voucher = GetPDNDVoucher(httpClient, httpPost);
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | JOSEException e) {
            String msg = "Errore nel recupero del voucher PDND di interoperabilitÓ.";
            log.error(msg, e);
            throw new OAuthSystemException(msg, e);
        } 

        return voucher;
    }

    /**
     * Invoca l'endpoint PDND per ottenere il Voucher di interoperabilitÓ (access token)
     * @param httpClient Client per inviare la richiesta
     * @param httpRequest Request di richiesta del JWT 
     * 
     * @return Voucher PDND di interoperabilitÓ (access token)
     * @throws OAuthSystemException
     */
    private String GetPDNDVoucher(CloseableHttpClient httpClient, HttpRequestBase httpRequest) throws OAuthSystemException {
        String voucher = null;

        try (CloseableHttpResponse response = httpClient.execute(httpRequest)) {
            log.debug("PDND response: " + response);

            BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), StandardCharsets.UTF_8));
            String inputLine;
            StringBuilder stringBuilder = new StringBuilder();

            while ((inputLine = reader.readLine()) != null) {
                stringBuilder.append(inputLine);
            }

            if (!(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK)) {
                String reasonPhrase = response.getStatusLine().getReasonPhrase();
                log.error("PDND response\n\t" + response.getStatusLine().getStatusCode() + ": " + reasonPhrase + "\n\t\t" + stringBuilder);
                httpRequest.releaseConnection();
                throw new APISecurityException(response.getStatusLine().getStatusCode(), reasonPhrase, new Throwable(stringBuilder.toString()));
            }

            JSONObject json = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(stringBuilder.toString());
            voucher = json.getAsString("access_token");
            log.debug("PDND access token di interoperabilitÓ: " + voucher);
            
        } catch (ParseException | APISecurityException | UnsupportedOperationException | IOException e) {
            String msg = "Impossibile recuperare il voucher PDND di interoperabilitÓ.";
            log.error(msg, e);
            throw new OAuthSystemException(msg, e);
        } finally {
            httpRequest.releaseConnection();
        }

        return voucher;
    }

    public PdndPKMapping getPdndPKMapping() {
        return pdndPKMapping;
    }

    public void setPdndPKMapping(PdndPKMapping pdndPKMapping) {
        this.pdndPKMapping = pdndPKMapping;
    }

}
