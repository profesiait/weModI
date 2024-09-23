package it.profesia.carbon.apimgt.gateway.handlers.modi;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.Pipe;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.apache.ws.security.WSSecurityException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.xml.sax.SAXException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

import it.profesia.carbon.apimgt.gateway.handlers.logging.ModiLogUtils;
import it.profesia.carbon.apimgt.gateway.handlers.modi.soap.CreateSOAPMessage;
import it.profesia.carbon.apimgt.gateway.handlers.modi.soap.CustomSOAPBuilder;
import it.profesia.carbon.apimgt.gateway.handlers.utils.SOAPUtil;
import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;
import it.profesia.wemodi.subscriptions.utils.CertificateMetadata;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

public class FruizioneModiHandler extends AbstractHandler {

	private static final Log log = LogFactory.getLog(FruizioneModiHandler.class);

    public static final String ID_AUTH_REST_01 = "ID_AUTH_REST_01";
    public static final String ID_AUTH_REST_02 = "ID_AUTH_REST_02";
    public static final String INTEGRITY_REST_01 = "INTEGRITY_REST_01";
    
    public static final String ID_AUTH_SOAP_01 = "ID_AUTH_SOAP_01";
    public static final String ID_AUTH_SOAP_02 = "ID_AUTH_SOAP_02";
    public static final String INTEGRITY_SOAP_01 = "INTEGRITY_SOAP_01";
    public static final String KEY_IDENTIFIER_TYPE = "KEY_IDENTIFIER_TYPE";
    
    public static final String AUDIT_REST_01_PDND = "AUDIT_REST_01_PDND";
    public static final String AUDIT_REST_01_MODI = "AUDIT_REST_01_MODI";
    public static final String AUDIT_REST_02 = "AUDIT_REST_02";
    public static final String INTEGRITY_REST_02 = "INTEGRITY_REST_02";

    private String modi_fruizione;
    private String pdnd_fruizione;
    private String id_auth_rest_01;
    private String id_auth_rest_02;
    private String integrity_rest_01;
    
    private String id_auth_soap_01;
    private String id_auth_soap_02;
    private String integrity_soap_01;
    private String key_identifier_type;
    
    private String audit_rest_01_pdnd;
    private String audit_rest_01_modi;
    private String audit_rest_02;
    private String integrity_rest_02;
    
    private String reference_certificate_type;
    private String jwt_header_name;
    
    public String getJwt_header_name() {
		return jwt_header_name;
	}

	public void setJwt_header_name(String jwt_header_name) {
		this.jwt_header_name = jwt_header_name;
	}

	public String getReference_certificate_type() {
		return reference_certificate_type;
	}

	public void setReference_certificate_type(String reference_certificate_type) {
		this.reference_certificate_type = reference_certificate_type;
	}

	public String getKey_identifier_type() {
		return key_identifier_type;
	}

	public void setKey_identifier_type(String key_identifier_type) {
		this.key_identifier_type = key_identifier_type;
	}

	public String getId_auth_soap_01() {
		return id_auth_soap_01;
	}

	public void setId_auth_soap_01(String id_auth_soap_01) {
		this.id_auth_soap_01 = id_auth_soap_01;
	}

	public String getId_auth_soap_02() {
		return id_auth_soap_02;
	}

	public void setId_auth_soap_02(String id_auth_soap_02) {
		this.id_auth_soap_02 = id_auth_soap_02;
	}

	public String getIntegrity_soap_01() {
		return integrity_soap_01;
	}

	public void setIntegrity_soap_01(String integrity_soap_01) {
		this.integrity_soap_01 = integrity_soap_01;
	}

	public String getModi_fruizione() {
		return modi_fruizione;
	}

	public void setModi_fruizione(String modi_fruizione) {
		this.modi_fruizione = modi_fruizione;
	}

	public String getPdnd_fruizione() {
		return pdnd_fruizione;
	}

	public void setPdnd_fruizione(String pdnd_fruizione) {
		this.pdnd_fruizione = pdnd_fruizione;
	}

	public String getId_auth_rest_01() {
		return id_auth_rest_01;
	}

	public void setId_auth_rest_01(String id_auth_rest_01) {
		this.id_auth_rest_01 = id_auth_rest_01;
	}

	public String getId_auth_rest_02() {
		return id_auth_rest_02;
	}

	public void setId_auth_rest_02(String id_auth_rest_02) {
		this.id_auth_rest_02 = id_auth_rest_02;
	}

	public String getIntegrity_rest_01() {
		return integrity_rest_01;
	}

	public void setIntegrity_rest_01(String integrity_rest_01) {
		this.integrity_rest_01 = integrity_rest_01;
	}
	
	public String getAudit_rest_01_pdnd() {
		return audit_rest_01_pdnd;
	}

	public void setAudit_rest_01_pdnd(String audit_rest_01_pdnd) {
		this.audit_rest_01_pdnd = audit_rest_01_pdnd;
	}

	public String getAudit_rest_01_modi() {
		return audit_rest_01_modi;
	}

	public void setAudit_rest_01_modi(String audit_rest_01_modi) {
		this.audit_rest_01_modi = audit_rest_01_modi;
	}
	
	public String getAudit_rest_02() {
		return audit_rest_02;
	}

	public void setAudit_rest_02(String audit_rest_02) {
		this.audit_rest_02 = audit_rest_02;
	}

	public String getIntegrity_rest_02() {
		return integrity_rest_02;
	}

	public void setIntegrity_rest_02(String integrity_rest_02) {
		this.integrity_rest_02 = integrity_rest_02;
	}

	@Override
	public boolean handleRequest(MessageContext messageContext) {
		boolean handleReturn = true;

		ModiLogUtils.initialize(messageContext);
		log.info(ModiLogUtils.FRUIZIONE_START);

		try {
			Set props = messageContext.getPropertyKeySet();
			if (log.isTraceEnabled()) {
				props.forEach(
						(k) -> {
								log.trace("Property : " + k + ", Value : " + messageContext.getProperty(k.toString()));
							}
						);
			}

			org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
			Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));

			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getPdnd_fruizione()))) {
				log.info(ModiLogUtils.PDND_GET_METADATA_START);
				String metadata = (String) messageContext.getProperty("pdndMetadata");
				JSONObject pdndMetadata = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(metadata);

				
					PdndPKMapping pdndPKMapping = new PdndPKMapping();

					pdndPKMapping.setAlg(pdndMetadata.getAsString("alg"));
					pdndPKMapping.setAud(pdndMetadata.getAsString("aud"));
					pdndPKMapping.setEnabled(true);
					pdndPKMapping.setIss(pdndMetadata.getAsString("iss"));
					pdndPKMapping.setKid(pdndMetadata.getAsString("kid"));
					pdndPKMapping.setPrivkey(pdndMetadata.getAsString("privateKey"));
					pdndPKMapping.setPurposeId(pdndMetadata.getAsString("purposeId"));
					pdndPKMapping.setSub(pdndMetadata.getAsString("sub"));
					pdndPKMapping.setTyp(pdndMetadata.getAsString("typ"));
					pdndPKMapping.setUri(pdndMetadata.getAsString("uri"));
					pdndPKMapping.setClientId(pdndMetadata.getAsString("clientId"));
					pdndPKMapping.setScope(pdndMetadata.getAsString("scope"));
					if (log.isDebugEnabled())
						log.debug(ModiLogUtils.PDND_GET_METADATA_FINISH + "\n\t" + pdndPKMapping);
					else
						log.info(ModiLogUtils.PDND_GET_METADATA_FINISH);
					
					String pdndToken = "";
					ModiPKMapping modiPKMapping = null;
					if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_02()))
							|| BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_pdnd()))
							|| BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_modi()))) {
						String metadataJWSAudit = (String) messageContext.getProperty("modiMetadata");
						JSONObject modiMetadataJWSAudit = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(metadataJWSAudit);

							modiPKMapping = new ModiPKMapping();

							modiPKMapping.setAlg(modiMetadataJWSAudit.getAsString("alg"));
							modiPKMapping.setAud(modiMetadataJWSAudit.getAsString("aud"));
							modiPKMapping.setCertificate(modiMetadataJWSAudit.getAsString("certificate"));
							modiPKMapping.setEnabled(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(modiMetadataJWSAudit.getAsString("enabled"))));
							modiPKMapping.setIss(modiMetadataJWSAudit.getAsString("iss"));
							modiPKMapping.setKid(modiMetadataJWSAudit.getAsString("kid"));
							modiPKMapping.setPrivkey(modiMetadataJWSAudit.getAsString("privkey"));
							modiPKMapping.setPublickey(modiMetadataJWSAudit.getAsString("publickey"));
							modiPKMapping.setSub(modiMetadataJWSAudit.getAsString("sub"));
							modiPKMapping.setTyp(modiMetadataJWSAudit.getAsString("typ"));
					}

					pdndToken = providePdnd(pdndPKMapping, headers, modiPKMapping);
					if (log.isDebugEnabled())
						log.debug(ModiLogUtils.ACCESS_TOKEN_PDND + "\n\t" + pdndToken);
					else
						log.info(ModiLogUtils.ACCESS_TOKEN_PDND);

					headers.put("Authorization", "Bearer " + pdndToken);
				
			}

			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getModi_fruizione()))) {
				
				//Fruizione SOAP
				String soapAction = (String) headers.get("SOAPAction");
				String contentType = (String) headers.get("OriginalContentType");
				if(soapAction != null && !(soapAction.equals("")))
				{
					log.info("Modi Fruizione SOAP start");
					
					log.info("soapAction: "+soapAction);
					Properties modiSOAPProps = new Properties();
					modiSOAPProps.setProperty(ID_AUTH_SOAP_01, id_auth_soap_01);
					modiSOAPProps.setProperty(ID_AUTH_SOAP_02, id_auth_soap_02);
					modiSOAPProps.setProperty(INTEGRITY_SOAP_01, integrity_soap_01);
					modiSOAPProps.setProperty(KEY_IDENTIFIER_TYPE, key_identifier_type);
					String metadataSOAP = (String) messageContext.getProperty("modiMetadataSOAP");
					JSONObject modiMetadataSOAP = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(metadataSOAP);
					log.info("metadata SOAP: "+modiMetadataSOAP.toJSONString());
					ModiPKMapping modiPKMapping = new ModiPKMapping();
					modiPKMapping.setCertificate((modiMetadataSOAP.getAsString("certificate")).replace("-----BEGIN CERTIFICATE-----", "").replaceAll("(\r|\n)", "").replace("-----END CERTIFICATE-----", ""));
					modiPKMapping.setPrivkey((modiMetadataSOAP.getAsString("privkey")).replace("-----BEGIN PRIVATE KEY-----", "").replaceAll("(\r|\n)", "").replace("-----END PRIVATE KEY-----", ""));
					modiPKMapping.setWsaddressingTo(modiMetadataSOAP.getAsString("To"));
					
					Document signedDoc = CreateSOAPMessage.create(SOAPUtil.getOriginalPayload(axis2MC), modiPKMapping, modiSOAPProps);
					createNewPayload(signedDoc, axis2MC, contentType);
					log.info("Modi Fruizione SOAP end");
				}
				else
				{
				log.info(ModiLogUtils.MODI_GET_METADATA_START);
				String metadata = (String) messageContext.getProperty("modiMetadata");
				JSONObject modiMetadata = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(metadata);

					ModiPKMapping modiPKMapping = new ModiPKMapping();

					modiPKMapping.setAlg(modiMetadata.getAsString("alg"));
					modiPKMapping.setAud(modiMetadata.getAsString("aud"));
					modiPKMapping.setCertificate(modiMetadata.getAsString("certificate"));
					modiPKMapping.setEnabled(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(modiMetadata.getAsString("enabled"))));
					modiPKMapping.setIss(modiMetadata.getAsString("iss"));
					modiPKMapping.setKid(modiMetadata.getAsString("kid"));
					modiPKMapping.setPrivkey(modiMetadata.getAsString("privkey"));
					modiPKMapping.setPublickey(modiMetadata.getAsString("publickey"));
					modiPKMapping.setSub(modiMetadata.getAsString("sub"));
					modiPKMapping.setTyp(modiMetadata.getAsString("typ"));
					log.info(ModiLogUtils.MODI_GET_METADATA_FINISH);

					if ((modiPKMapping.isEnabled())) {
						
						PdndPKMapping pdndPKMapping = null;
						if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_pdnd()))) {
						log.info(ModiLogUtils.PDND_GET_METADATA_START);
						String metadataPdnd = (String) messageContext.getProperty("pdndMetadata");
						JSONObject pdndMetadataJWSAudit = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST).parse(metadataPdnd);

						
							pdndPKMapping = new PdndPKMapping();

							pdndPKMapping.setAlg(pdndMetadataJWSAudit.getAsString("alg"));					
							pdndPKMapping.setAud(pdndMetadataJWSAudit.getAsString("aud"));
							pdndPKMapping.setEnabled(true);					
							pdndPKMapping.setIss(pdndMetadataJWSAudit.getAsString("iss"));					
							pdndPKMapping.setKid(pdndMetadataJWSAudit.getAsString("kid"));
							pdndPKMapping.setPrivkey(pdndMetadataJWSAudit.getAsString("privateKey"));
							pdndPKMapping.setPurposeId(pdndMetadataJWSAudit.getAsString("purposeId"));
							pdndPKMapping.setSub(pdndMetadataJWSAudit.getAsString("sub"));
							pdndPKMapping.setTyp(pdndMetadataJWSAudit.getAsString("typ"));
							pdndPKMapping.setUri(pdndMetadataJWSAudit.getAsString("uri"));
							pdndPKMapping.setClientId(pdndMetadataJWSAudit.getAsString("clientId"));
							pdndPKMapping.setScope(pdndMetadataJWSAudit.getAsString("scope"));
							
							if (log.isDebugEnabled())
								log.debug(ModiLogUtils.PDND_GET_METADATA_FINISH + "\n\t" + pdndPKMapping);
							else
								log.info(ModiLogUtils.PDND_GET_METADATA_FINISH);
						}
						
						String modiToken = provideModi(messageContext, modiPKMapping, pdndPKMapping);
						if (log.isDebugEnabled())
							log.debug(ModiLogUtils.JWT_MODI + "\n\t" + modiToken);
						else
							log.info(ModiLogUtils.JWT_MODI);
						
						String modi_jwt = ((modi_jwt = getJwt_header_name()) != null && !(getJwt_header_name().equals("")) && !(getJwt_header_name().contains("additionalProperties"))) ? modi_jwt : "Agid-JWT-Signature";
						headers.put(modi_jwt, modiToken);
					}
				}
			}
			//if (log.isTraceEnabled()) {
				headers.forEach(
						(key, value) -> {
								log.info("Header : " + key + ", Value : " + value);
							}
						);
			//}

		}
		catch (CertificateEncodingException | ParserConfigurationException | SAXException | KeyStoreException | TransformerException | WSSecurityException e) {
			log.error("Errore creazione messaggio SOAP: " + ExceptionUtils.getStackTrace(e));
			handleReturn = false;
		}
		catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException | APIManagementException | JOSEException | CertificateException | ParseException e) {
			log.error("Errore nel recupero delle informazioni PDND/ModI: " + ExceptionUtils.getStackTrace(e));
			handleReturn = false;
		}
		catch (APISecurityException e) {
			log.error("Error handling PDND/ModI data: " + ExceptionUtils.getStackTrace(e));
			handleAuthFailure(messageContext, e);
			handleReturn = false;
		}
		finally {
			log.info(ModiLogUtils.FRUIZIONE_FINISH);
			ModiLogUtils.release();
		}

		return handleReturn;
	}

	@Override
	public boolean handleResponse(MessageContext messageContext) {
		// TODO Auto-generated method stub
		return true;
	}

	private String providePdnd(PdndPKMapping pdndJwt, Map headers, ModiPKMapping modiJWSAudit) throws MalformedURLException, JOSEException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, APISecurityException{
		String jwt = null;

		log.debug(ModiLogUtils.PDND_ENABLED + ": " + pdndJwt.isEnabled());
		if (pdndJwt.isEnabled()) {
			log.info(ModiLogUtils.PDND_TOKEN_REQUEST_START);
			ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

			byte[] encoded = org.apache.commons.codec.binary.Base64.decodeBase64((pdndJwt.getPrivkey().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")).getBytes(StandardCharsets.UTF_8));
			PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encoded);
			RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);
			
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
					.type(JOSEObjectType.JWT)
					.keyID(pdndJwt.getKid())
					.build();
			log.debug("PDND client assertion JWT header: " + header.toString());
			
			Builder jwtBuilder = new JWTClaimsSet.Builder()
					 .issueTime(new Date(issued.toInstant().toEpochMilli()))
					 .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
					 .subject(pdndJwt.getSub())
					 .audience(pdndJwt.getAud())
					 .jwtID(UUID.randomUUID().toString())
					 .issuer(pdndJwt.getIss())
					 .claim("purposeId", pdndJwt.getPurposeId());
			if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_pdnd()))) {
				//Custom claims concordati con l'erogatore
				JSONObject customClaims = customClaims(null, headers);
				
				String jwsAudit = provideJWSAudit(modiJWSAudit, pdndJwt, customClaims);
				//headers.put("Agid-JWT-TrackingEvidence", CertificateMetadata.encodeToBase64(jwsAudit));
				headers.put("Agid-JWT-TrackingEvidence", jwsAudit);
			}
			else if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_modi()))) {
				//Custom claims concordati con l'erogatore
				JSONObject customClaims = customClaims(null, headers);
				
				String jwsAudit = provideJWSAuditModI(modiJWSAudit, customClaims);
				//headers.put("Agid-JWT-TrackingEvidence", CertificateMetadata.encodeToBase64(jwsAudit));
				headers.put("Agid-JWT-TrackingEvidence", jwsAudit);
			}
			else if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_02()))) {
				//Custom claims concordati con l'erogatore
				JSONObject customClaims = customClaims(null, headers);
				
				String jwsAudit = provideJWSAudit(modiJWSAudit, pdndJwt, customClaims);
				//headers.put("Agid-JWT-TrackingEvidence", CertificateMetadata.encodeToBase64(jwsAudit));
				headers.put("Agid-JWT-TrackingEvidence", jwsAudit);
				/*
				 * Per la generazione del digest vedere
				 * https://docs.pagopa.it/interoperabilita-1/manuale-operativo/utilizzare-i-voucher
				 */
				byte[] digestBytes = convertToDigestBytes(jwsAudit);
				String digestValue = CertificateMetadata.hexify(digestBytes);
				JSONObject jsonDigest = new JSONObject();
				jsonDigest.put("alg", "SHA256");
				jsonDigest.put("value", digestValue);
				jwtBuilder.claim("digest", jsonDigest);
			}

			JWTClaimsSet assertion = jwtBuilder.build();
			log.debug("PDND client assertion JWT payload: " + assertion.toString());

			SignedJWT signedJWT = new SignedJWT(header, assertion);
			signedJWT.sign(new RSASSASigner(privateKey));

			String clientAssertion = signedJWT.serialize();
			log.debug("PDND client assertion: " + clientAssertion);


	        URL urlObject;
	        StringBuilder payload = new StringBuilder();
	        urlObject = new URL(pdndJwt.getUri());

	        // Per il codice seguente ho preso ispirazione da OAuthTokenGenerator.getTokenResponse()
	        try (CloseableHttpClient httpClient = (CloseableHttpClient) APIUtil
	                .getHttpClient(urlObject.getPort(), urlObject.getProtocol())) {
				log.trace("CloseableHttpClient: " + httpClient);
	            HttpPost httpPost = new HttpPost(pdndJwt.getUri());
	            log.debug("PDND Uri: " + pdndJwt.getUri());
	            httpPost.setHeader(APIConstants.HEADER_CONTENT_TYPE, APIConstants.OAuthConstants.APPLICATION_X_WWW_FORM_URLENCODED);

	            payload.append(APIConstants.OAuthConstants.CLIENT_CRED_GRANT_TYPE);
	            payload.append("&");

	            log.debug("PDND client id: "+pdndJwt.getClientId());
	            if (StringUtils.isNotBlank(pdndJwt.getClientId())) {
	            	payload.append("client_id=" + pdndJwt.getClientId());
	            	payload.append("&");
	            }
	            log.debug("PDND scope: "+pdndJwt.getScope());
	            if (StringUtils.isNotBlank(pdndJwt.getScope())) {
	            	payload.append("scope=" + pdndJwt.getScope());
	            	payload.append("&");
	            }
	            payload.append("client_assertion=" + clientAssertion);
	            payload.append("&");
	            payload.append("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

	            log.debug("PDND Payload: " + payload.toString());
	            httpPost.setEntity(new StringEntity(payload.toString()));



	            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
	            	log.debug("PDND response: " + response);

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
		            	throw new APISecurityException(response.getStatusLine().getStatusCode(), reasonPhrase, new Throwable(stringBuilder.toString()));
	            	}

	                JSONObject json = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(stringBuilder.toString());
	                jwt = json.getAsString("access_token");
	                log.debug("PDND access token: " + jwt);
	                
	            } catch (ParseException pe) {
	            	log.error("Impossibile recuperare il voucher PDND: " + ExceptionUtils.getStackTrace(pe));
	            } finally {
	                httpPost.releaseConnection();
	            }
	        } catch (IOException e) {
	        	log.error("Errore nel recupero del voucher PDND: " + ExceptionUtils.getStackTrace(e));
			}
			log.info(ModiLogUtils.PDND_TOKEN_REQUEST_FINISH);
		}

		return jwt;
	}
	
	private String provideJWSAudit(ModiPKMapping modiJWSAudit, PdndPKMapping pdndJwt, JSONObject customClaims) throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException{
		log.info(ModiLogUtils.JWS_AUDIT_START);
		ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

		byte[] encoded = org.apache.commons.codec.binary.Base64.decodeBase64((modiJWSAudit.getPrivkey().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")).getBytes(StandardCharsets.UTF_8));
		PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encoded);
		RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT)
				.keyID(modiJWSAudit.getKid())
				.build();
		log.debug("JWS Audit header: " + header.toString());
		
		Builder jwtBuilder = new JWTClaimsSet.Builder()
				 .issueTime(new Date(issued.toInstant().toEpochMilli()))
				 .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
				 .notBeforeTime(new Date(issued.plusDays(0).toInstant().toEpochMilli()))
				 .audience(modiJWSAudit.getAud())
				 .jwtID(UUID.randomUUID().toString())
				 .issuer(modiJWSAudit.getIss())
				 .claim("purposeId", pdndJwt.getPurposeId());
				 if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_02()))) {
						long dnonce = java.util.concurrent.ThreadLocalRandom.current().nextLong(1000000000000L, 10000000000000L);
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

		String jwsAudit = signedJWT.serialize();
		log.debug("Agid-JWT-TrackingEvidence: " + jwsAudit);
		
		log.info(ModiLogUtils.JWS_AUDIT_FINISH);

	return jwsAudit;
}
	
	private String provideJWSAuditModI(ModiPKMapping modiJWSAudit, JSONObject customClaims) throws InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, JOSEException {
		log.info(ModiLogUtils.JWS_AUDIT_START);
		ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

		byte[] encoded = org.apache.commons.codec.binary.Base64.decodeBase64((modiJWSAudit.getPrivkey().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")).getBytes(StandardCharsets.UTF_8));
		PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encoded);
		RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);
		
		JWSHeader header = null;
		header = buildJWTHeader(getReference_certificate_type(), modiJWSAudit.getCertificate(), null);
		log.debug("ModI JWS Audit header: " + header.toString());
		
		Builder jwtBuilder = new JWTClaimsSet.Builder()
				 .issueTime(new Date(issued.toInstant().toEpochMilli()))
				 .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
				 .notBeforeTime(new Date(issued.plusDays(0).toInstant().toEpochMilli()))
				 .audience(modiJWSAudit.getAud())
				 .jwtID(UUID.randomUUID().toString());
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

		String jwsAudit = signedJWT.serialize();
		log.debug("Agid-JWT-TrackingEvidence: " + jwsAudit);
		
		log.info(ModiLogUtils.JWS_AUDIT_FINISH);

	return jwsAudit;
}

	private String provideModi(MessageContext messageContext, ModiPKMapping modiJwt, PdndPKMapping pdndJwsAudit) throws InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, IOException, APIManagementException, JOSEException {
		String jwt = null;

		log.debug(ModiLogUtils.MODI_ENABLED + ": " + modiJwt.isEnabled());
		if (modiJwt.isEnabled()) {
			log.info(ModiLogUtils.MODI_TOKEN_GENERATION_START);
			org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
			
			Map headers = (Map) (axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS));

			JWSHeader header = null;
			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getIntegrity_rest_02()))) {
				header = buildJWTHeader(getReference_certificate_type(), null, modiJwt.getKid());
			}
			else
				header = buildJWTHeader(getReference_certificate_type(), modiJwt.getCertificate(), null);
			log.debug("ModI JWT header: " + header.toString());

			ZonedDateTime issued = ZonedDateTime.now(ZoneOffset.UTC);

			Builder payloadBuilder = new JWTClaimsSet.Builder()
					 .issueTime(new Date(issued.toInstant().toEpochMilli()))
					 .expirationTime(new Date(issued.plusDays(60).toInstant().toEpochMilli()))
					 .notBeforeTime(new Date(issued.plusDays(0).toInstant().toEpochMilli()))
					 .audience(modiJwt.getAud())
					 .subject(modiJwt.getSub())
					 .issuer(modiJwt.getIss());

			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getId_auth_rest_02()))) {
				payloadBuilder = payloadBuilder.jwtID(UUID.randomUUID().toString());
			}

			JSONObject customClaims = customClaims(axis2MC, null);
			if (customClaims != null) {
				for (String key : customClaims.keySet()) {
					Object claim = customClaims.get(key);
					payloadBuilder.claim(key, claim);
				}
			}

			if (BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getIntegrity_rest_01()))
					|| BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getIntegrity_rest_02()))) {
				/**
				 * Il pattern INTEGRITY_REST_01 prevede il claim signed_headers nel JWT
				 *   se non ci sono headers da firmare il claim va ignorato
				 */
				String digestAlgorithm = "SHA-256";
				
				List<Map<String, Object>> signedHeaders = new ArrayList<Map<String, Object>>();
				Map<String,Object> digestMap = new HashMap<String, Object>(1);

				String sha256Base64 = digestPayload(axis2MC, headers);
				if (StringUtils.isNotEmpty(sha256Base64)) {
					digestMap.put("digest", digestAlgorithm + "=" + sha256Base64);

					headers.put("digest", digestAlgorithm + "=" + sha256Base64);

					signedHeaders.add(digestMap);
				}

				if (headers.containsKey("content-type")){
					Map<String,Object> contentTypeMap = new HashMap<String, Object>(1);
					//contentTypeMap.put("content-type", "application/json");
					//contentTypeMap.put("content-type", null);
					contentTypeMap.put("content-type", headers.get("content-type"));

					signedHeaders.add(contentTypeMap);
				}

				log.debug("Signed Headers: " + signedHeaders.stream().map(Object::toString).collect(Collectors.joining(",")));
				if (!signedHeaders.isEmpty())
					payloadBuilder.claim("signed_headers", signedHeaders);
			}

			JWTClaimsSet payload = payloadBuilder.build();
			log.debug("ModI JWT payload: " + payload.toString());

			byte[] pkEncoded = org.apache.commons.codec.binary.Base64.decodeBase64((modiJwt.getPrivkey().replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")).getBytes(StandardCharsets.UTF_8));
			PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pkEncoded);
			RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(encodedKeySpec);

			SignedJWT signedJWT = new SignedJWT(header, payload);
			signedJWT.sign(new RSASSASigner(privateKey));

			jwt = signedJWT.serialize();
			log.debug("ModI JWT: " + jwt);
			if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_modi()))) {
				//Custom claims concordati con l'erogatore
				//customClaims = customClaims(null, headers);
				
				String jwsAudit = provideJWSAuditModI(modiJwt, customClaims);
				//headers.put("Agid-JWT-TrackingEvidence", CertificateMetadata.encodeToBase64(jwsAudit));
				headers.put("Agid-JWT-TrackingEvidence", jwsAudit);
			}
			else if(BooleanUtils.isTrue(BooleanUtils.toBooleanObject(getAudit_rest_01_pdnd()))) {
				//Custom claims concordati con l'erogatore
				//customClaims = customClaims(null, headers);
				
				String jwsAudit = provideJWSAudit(modiJwt, pdndJwsAudit, customClaims);
				//headers.put("Agid-JWT-TrackingEvidence", CertificateMetadata.encodeToBase64(jwsAudit));
				headers.put("Agid-JWT-TrackingEvidence", jwsAudit);
			}
			log.info(ModiLogUtils.MODI_TOKEN_GENERATION_FINISH);
		}

		return jwt;
	}

	/**
	 * Returns custom claims to be added to the JWT
	 * 
	 * @param axis2MC Message context
	 * @return custom claims
	 */
	private JSONObject customClaims (org.apache.axis2.context.MessageContext axis2MC, Map inputHeaders) {
		JSONObject claims = null;
		Map headers = null;
		if(axis2MC != null)
			headers = (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
		else
			headers = inputHeaders;
		log.info("Recupero dei claim aggiuntivi per il JWT");

		try {
			if (headers.containsKey("modi_jwt_claims")) {
				String modiJwtClaims = (String) headers.get("modi_jwt_claims");
				log.debug("Custom JWT claims: " + modiJwtClaims);
				claims = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(modiJwtClaims);
			}
		} catch (ParseException e) {
			log.error("Recupero dei claim aggiuntivi per il JWT: ", e);
		}
		return claims;
	}

    private String digestPayload(org.apache.axis2.context.MessageContext axis2MC, Map headers) throws IOException
    {
    	String digest = "";
    	ByteArrayOutputStream byteArrayOutputStream = null;
    	final Pipe pipe = (Pipe) axis2MC.getProperty(PassThroughConstants.PASS_THROUGH_PIPE);
    	if (pipe != null)
    	{
    		InputStream in = pipe.getInputStream();
    		if(in != null)
    		{
    		byteArrayOutputStream = new ByteArrayOutputStream();
            int numOfBytes = IOUtils.copy(in, byteArrayOutputStream);
            if(numOfBytes > 0)
            {
            	byteArrayOutputStream.flush();
                String originalPayload = byteArrayOutputStream.toString();
                log.debug("originalPayload: "+originalPayload);
                in =  new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
                RelayUtils.buildMessage(axis2MC, false, in);
                digest = convertToDigest(originalPayload);
            }
            else
            	digest = digestGenerationFromPayload(axis2MC, headers);
    		}
    	}
    	return digest;
    }
    
    /*
     * Needed to calculate digest when Custom Data Provider is used
     * https://gitlab.csi.it/prodotti/apimint/analytics-custom-data-provider
     */
    private String digestGenerationFromPayload(org.apache.axis2.context.MessageContext axis2MC, Map headers) throws IOException
    {
    	String contentType = "", digest = "", genericPayload = "";
    	contentType = ((contentType = (String) headers.get(HttpHeaders.CONTENT_TYPE)) != null) ? contentType : "";
    	log.info("contentType: " + contentType);
    	if(contentType.equals("application/json"))
    	{
    		InputStream jsonPayloadStream = JsonUtil
                    .getJsonPayload(axis2MC);
            if (jsonPayloadStream != null) {
                StringWriter writer = new StringWriter();
                String encoding = null;
                IOUtils.copy(jsonPayloadStream, writer, encoding);
                String jsonPayload = writer.toString();
                log.debug("jsonPayload: " + jsonPayload);
                digest = convertToDigest(jsonPayload);
            }
    	}
    	else
    	{
    		genericPayload = axis2MC.getEnvelope().getBody().getFirstElement().toString();
    		log.debug("genericPayload: " + genericPayload);
    		digest = convertToDigest(genericPayload);
    	}
    	return digest;
    	
    }

	private String convertToDigest(String payload) {
		String digestAlgorithm = "SHA-256";
		String sha256Base64 = "";
		try {
			MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
			byte[] encodedhash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
			sha256Base64 = new String(Base64.getEncoder().encode(encodedhash));
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
		}
		return sha256Base64;
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
    
    private void createNewPayload(Document signedDoc, org.apache.axis2.context.MessageContext axis2MC, String contentType) throws TransformerException, IOException
	{
		
		Element soapEnvelopeEl = (Element) signedDoc.getDocumentElement();
		log.info("content type: "+contentType);
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			SOAPUtil.elementToStream(soapEnvelopeEl, baos);
			InputStream soapEnvelopeStream = new ByteArrayInputStream(baos.toByteArray());
			CustomSOAPBuilder customSOAPBuilder = new CustomSOAPBuilder();
			SOAPEnvelope soapEnvelope = (SOAPEnvelope) customSOAPBuilder.processDocument(soapEnvelopeStream, contentType, axis2MC);
			log.info("soapEnvelope new: "+soapEnvelope.toString());
			axis2MC.setEnvelope(soapEnvelope);
			axis2MC.setProperty(Constants.Configuration.CONTENT_TYPE, "application/xml");
			axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/xml");
		}
		
	}
    
    private URI isValidURL(String url) {
		URI uri = null;
	    try {
	        uri = new URL(url).toURI();
	    } catch (MalformedURLException | URISyntaxException e) {
	        log.error("It's not a valid URL: "+url);
	    } 
	    return uri;
	}
    
    private com.nimbusds.jose.JWSHeader.Builder setX5c(com.nimbusds.jose.JWSHeader.Builder headerBuilder, X509Certificate cert) throws CertificateEncodingException
	 {
		 List<com.nimbusds.jose.util.Base64> certs = new ArrayList<>();
		 certs.add(new com.nimbusds.jose.util.Base64(Base64.getUrlEncoder().withoutPadding().encodeToString(cert.getEncoded())));
		 headerBuilder.x509CertChain(certs);
		 return headerBuilder;
	 }
    
    private JWSHeader buildJWTHeader(String reference_certificate_type, String certificate, String kid) throws CertificateException
    {
    	JWSHeader header = null;
		URI x5u = null;
		String thumbprint = "", thumbprint256 = "";
		com.nimbusds.jose.JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT);
		if((x5u = isValidURL(reference_certificate_type)) == null)
		{
			X509Certificate cert = null;
			CertificateFactory certificateFactory = null;
			certificateFactory = CertificateFactory.getInstance("X.509");
			if(certificate != null)
				cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getBytes()));
	        
	        if(reference_certificate_type == null || reference_certificate_type.contains("additionalProperties") || reference_certificate_type.equals(""))
	        {
	        	if(kid == null)
	        		return setX5c(headerBuilder, cert).build();
	        	else if(kid != null && !(kid.equals("")))
	        	{
	        		headerBuilder.keyID(kid);
		        	log.info("kid is not null: "+kid);
		        	return headerBuilder.build();
	        	}
	        }
	        	
	        
	        switch(reference_certificate_type) {
	        case "x5t":
	        	thumbprint = CertificateMetadata.getThumbprintOfCertificate(cert);
				headerBuilder.x509CertThumbprint(new com.nimbusds.jose.util.Base64URL(thumbprint));
				break;
	        case "x5t#S256":
	        	thumbprint256 = CertificateMetadata.getThumbprintOfCertificate256(cert);
	        	headerBuilder.x509CertSHA256Thumbprint(new com.nimbusds.jose.util.Base64URL(thumbprint256));
	        	break;
	        case "x5c":
	        	setX5c(headerBuilder, cert);
				break;
	        default:
	        	setX5c(headerBuilder, cert);
	      }
		}
		else
			headerBuilder.x509CertURL(x5u);
		header = headerBuilder.build();
    	return header;
    }
    
    private void handleAuthFailure(MessageContext messageContext, APISecurityException e) {
        messageContext.setProperty(SynapseConstants.ERROR_CODE, e.getErrorCode());
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, e.getMessage());

        Mediator sequence = messageContext.getSequence(APISecurityConstants.API_AUTH_FAILURE_HANDLER);
        
        String errorDetail = e.getCause().getMessage();
        messageContext.setProperty(SynapseConstants.ERROR_DETAIL, errorDetail);

        // By default we send a 401 response back
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {
            //In case of an error it is logged and the process is continued because we're setting a fault message in the payload.
            log.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        int status;
        status = e.getErrorCode();

        messageContext.setProperty(APIMgtGatewayConstants.HTTP_RESPONSE_STATUS_CODE, status);

        // Invoke the custom error handler specified by the user
        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling
            // logic from getting executed
            return;
        }

        sendFault(messageContext, status);
    }

    protected void sendFault(MessageContext messageContext, int status) {
        Utils.sendFault(messageContext, status);
    }

}
