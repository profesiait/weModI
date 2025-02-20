package it.profesia.wemodi.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.Vector;

import javax.ws.rs.core.MediaType;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.axis2.context.MessageContext;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.util.XMLUtils;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import it.profesia.wemodi.ApiConfig;
import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

public class WeModIContextHelper {
    private MessageContext axis2MessageContext;
    private MessageContext origianlMessageContext;
    private Map headers;
    private String contentType;
    private String payload;
    private String soapEnvNamespace;
    private Document soapPayload;

	private Log log = LogFactory.getLog(WeModIContextHelper.class);

    public WeModIContextHelper(MessageContext axis2MessageContext) {
        this.origianlMessageContext = axis2MessageContext;
        setAxis2MessageContext(axis2MessageContext);
    }

    /**
     * Genera il JSON dei custom claims da allegare al voucher PDND
     * 
     * @return Additional data in formato JSON
     */
    public JSONObject getAdditionalData() {
        JSONObject claims = null;
		log.info("Recupero dei claim aggiuntivi per il JWT");

		try {
            String headerName = null;
            /*
             * Nginx non gestisce gli headers con <b>_</b>: https://my.f5.com/manage/s/article/K000091240
             */
            if (headers.containsKey("weModI-PDND-Additional-Data")) {
                headerName = "weModI-PDND-Additional-Data";
            } else if (headers.containsKey("modi_jwt_claims")) {
                headerName ="modi_jwt_claims";
            } else {
                return null;
            }

            String modiJwtClaims = (String) headers.get(headerName);
            log.debug("Custom JWT claims: " + modiJwtClaims);
            claims = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(modiJwtClaims);
		} catch (ParseException e) {
			log.error("Recupero dei claim aggiuntivi per il JWT: ", e);
		}
		return claims;
    }

    /**
     * Calcola il digest relativo al Payload del messaggio
     * 
     * @return Digest relativo al Payload
     */
    public String digestPayload() {
		String digestAlgorithm = "SHA-256";
		String sha256Base64 = "";
		if(payload != null && !(payload.equals("")))
		{
			try {
				MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
				byte[] encodedhash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
				sha256Base64 = new String(Base64.getEncoder().encode(encodedhash));
			} catch (NoSuchAlgorithmException e) {
				log.error(String.format("Errore nella generazione del digest per il payload %s", payload), e);
			}
		}
		return sha256Base64;

    }

    public MessageContext getAxis2MessageContext() {
        return axis2MessageContext;
    }

    public void setAxis2MessageContext(MessageContext axis2MessageContext) {
    	String genericPayload = "";
        this.axis2MessageContext = axis2MessageContext;
        headers = (Map) (axis2MessageContext.getProperty(MessageContext.TRANSPORT_HEADERS));
        String soapAction = (String) headers.get("SOAPAction");

        setContentType((String)headers.get(HttpHeaders.CONTENT_TYPE));

        switch (getContentType()) {
            case MediaType.APPLICATION_JSON:
            case MediaType.TEXT_XML:
            case MediaType.APPLICATION_XML:
                InputStream jsonPayloadStream = JsonUtil.getJsonPayload(axis2MessageContext);

                if (jsonPayloadStream != null) {
                    StringWriter writer = new StringWriter();
                    String encoding = null;
                    String jsonPayload = "";
                    try {
                        IOUtils.copy(jsonPayloadStream, writer, encoding);
                        jsonPayload = writer.toString();
                    } catch (IOException e) {
                        log.error("Impossibile recuperare il Payload dal messaggio.", e);
                    }
                    log.debug("jsonPayload: " + jsonPayload);
                    setPayload(jsonPayload);
                } else {
                	if(soapAction != null && !(soapAction.equals("")))
                	{
                		genericPayload = axis2MessageContext.getEnvelope().toString();
                    	log.debug("SOAP payload: " + genericPayload);
                	}
                	else
                	{
                		genericPayload = axis2MessageContext.getEnvelope().getBody().getFirstElement().toString();
                        log.debug("payload: " + genericPayload);
                	}
                	setPayload(genericPayload);
                }
                break;
            case "application/soap+xml":
            	genericPayload = axis2MessageContext.getEnvelope().toString();
            	log.debug("application/soap+xml payload: " +genericPayload);
                setPayload(genericPayload);
                break;
        }
    }

    /**
     * Crea il messaggio SOAP secondo i pattern ModI
     * 
     * @param modiPKMapping Configurazione del certificato weModI
     * @param apiConfig Configurazione dell'API weModI
     * @return Messaggio XML da inviare all'ente erogatore
     * @throws IOException
     * @throws CertificateException
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws KeyStoreException 
     */
    public Document createSoapPayload(ModiPKMapping modiPKMapping, ApiConfig apiConfig) throws IOException, CertificateException, ParserConfigurationException, SAXException, KeyStoreException {
    	
    	Document doc = null;
    	WSSecSignature sign = new WSSecSignature();
    	Crypto crypto = getCryptoInstance();
    	WSSecHeader secHeader = new WSSecHeader();
    	try(PEMParser certPemParser = new PEMParser(new StringReader(modiPKMapping.getCertificate()));
    		PEMParser pkPemParser = new PEMParser(new StringReader(modiPKMapping.getPrivkey()));)
    	{
    	PemObject certPemObject = certPemParser.readPemObject();
    	X509Certificate x509certificate = getX509Certificate(certPemObject);

        sign.setX509Certificate(x509certificate);

        String keyStoreAlias = RandomStringUtils.randomAlphanumeric(10);
		String keyStorePassword = RandomStringUtils.randomAlphanumeric(10);
        sign.setUserInfo(keyStoreAlias, keyStorePassword);

        String updatedMsg = addElementToExistingXml(modiPKMapping.getWsaddressingTo(), apiConfig.isIdAuthSoap02());
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try (InputStream in = new ByteArrayInputStream(updatedMsg.getBytes())) {
        	factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            doc = builder.parse(in);
        }

        KeyStore keystore = getKeyStore(keyStorePassword.toCharArray());
        PemObject privateKey = pkPemParser.readPemObject();

        PrivateKey signingKey = getPrivateKey(privateKey);
        keystore.setKeyEntry(keyStoreAlias, signingKey, keyStorePassword.toCharArray(), new Certificate[]{x509certificate});
        ((Merlin) crypto).setKeyStore(keystore);
        crypto.loadCertificate(new ByteArrayInputStream(x509certificate.getEncoded()));  

        secHeader.setMustUnderstand(false);
        secHeader.insertSecurityHeader(doc);

        switch (apiConfig.getKeyIdentifierType().toUpperCase()) {
            case "BST_DIRECT_REFERENCE":
                sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
                break;
            case "X509_KEY_IDENTIFIER":
                sign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
                break;
            case "ISSUER_SERIAL":
                sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
                break;
            case "THUMBPRINT_IDENTIFIER":
                sign.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
                break;
            case "SKI_KEY_IDENTIFIER":
                sign.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
                break;
            default:
                log.warn(String.format( "Valore non supportato %s:%s.", ApiConfig.KEY_IDENTIFIER_TYPE, apiConfig.getKeyIdentifierType()));
        }

        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        timestamp.build(doc, secHeader);

        Vector<WSEncryptionPart> signParts = new Vector<WSEncryptionPart>();
        signParts.add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        if(apiConfig.isIdAuthSoap02())
        	signParts.add(new WSEncryptionPart("MessageID", "http://www.w3.org/2005/08/addressing", "Element"));
        signParts.add(new WSEncryptionPart("To", "http://www.w3.org/2005/08/addressing", "Element"));
        if(apiConfig.isIntegritySoap01())
        	signParts.add(new WSEncryptionPart("Body", soapEnvNamespace, "Element"));
        sign.setParts(signParts);
    	}
    	catch(IOException | CertificateException | ParserConfigurationException | SAXException | KeyStoreException e)
    	{
    		log.error("Errore creazione messaggio SOAP", e);
    		throw e;
    		
    	}
    	
        Document signedDoc = sign.build(doc, crypto, secHeader);
        if(log.isDebugEnabled()) {
        	String outputMsg = XMLUtils.PrettyDocumentToString(signedDoc);
        	log.debug("Busta SOAP inviata all'erogatore: " + outputMsg);
        }
        soapPayload = signedDoc;
        return signedDoc;
    }

    private String addElementToExistingXml(String toElemValue, boolean idAuthSoap02) {
	 	XMLStreamWriter xmlStreamWriter = null;
        XMLStreamReader xmlStreamReader = null;
		StringWriter stringWriter = new StringWriter();
		try
		{
		XMLOutputFactory outputFactory = XMLOutputFactory.newInstance();
		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		xmlStreamWriter = outputFactory.createXMLStreamWriter(stringWriter);
		xmlStreamReader = xmlInputFactory.createXMLStreamReader(new StringReader(getPayload()));
		
		 while (xmlStreamReader.hasNext()) {
			    int event = xmlStreamReader.next();

			    switch (event) {
			        case XMLStreamConstants.START_ELEMENT:
			        	if(!(xmlStreamReader.getLocalName().equalsIgnoreCase("Header")))
			        	{
			        	xmlStreamWriter.writeStartElement(xmlStreamReader.getPrefix(), xmlStreamReader.getLocalName(), xmlStreamReader.getNamespaceURI());
			        	
			        	int namespacesCount = xmlStreamReader.getNamespaceCount();
			        	for (int i = 0; i < namespacesCount; i++) {
			        		xmlStreamWriter.writeNamespace(xmlStreamReader.getNamespacePrefix(i), xmlStreamReader.getNamespaceURI(i));
			            }
			        	
			        	int attributeCount = xmlStreamReader.getAttributeCount();
			            for (int i = 0; i < attributeCount; i++) {
			            	xmlStreamWriter.writeAttribute(xmlStreamReader.getAttributePrefix(i), xmlStreamReader.getAttributeNamespace(i), xmlStreamReader.getAttributeLocalName(i), xmlStreamReader.getAttributeValue(i));
			            }
			        	}
			            if(xmlStreamReader.getLocalName().equalsIgnoreCase("Envelope"))
			        	{
			            	soapEnvNamespace = xmlStreamReader.getNamespaceURI();
			        		xmlStreamWriter.writeStartElement(xmlStreamReader.getPrefix(), "Header", xmlStreamReader.getNamespaceURI());
			        		/*xmlStreamWriter.writeNamespace("wsa", "http://www.w3.org/2005/08/addressing");
			        		xmlStreamWriter.writeStartElement("wsa", "To", "http://www.w3.org/2005/08/addressing");*/
			        		if(idAuthSoap02)
			        		{
			        			xmlStreamWriter.writeStartElement("MessageID");
				        		xmlStreamWriter.writeDefaultNamespace("http://www.w3.org/2005/08/addressing");
				        		xmlStreamWriter.writeCharacters("urn:uuid:"+UUID.randomUUID());
				        		xmlStreamWriter.writeEndElement();
			        		}
			        		xmlStreamWriter.writeStartElement("To");
			        		xmlStreamWriter.writeDefaultNamespace("http://www.w3.org/2005/08/addressing");
			        		xmlStreamWriter.writeCharacters(toElemValue);
			        		xmlStreamWriter.writeEndElement();
			        		xmlStreamWriter.writeEndElement();
			        	}
			            break;
			        case XMLStreamConstants.END_ELEMENT:
			        	if(!(xmlStreamReader.getLocalName().equalsIgnoreCase("Header")))
			        		xmlStreamWriter.writeEndElement();
			            break;
			        case XMLStreamConstants.CHARACTERS:
			        	xmlStreamWriter.writeCharacters(xmlStreamReader.getText());
			            break;
			    }
			}
		 xmlStreamWriter.flush();
		}
		catch(Exception e)
		{
			log.error(e);
		}
		finally {
			 try {
				xmlStreamReader.close();
				xmlStreamWriter.close();
			} catch (XMLStreamException e) {
				log.error(e);
			}
		}
		return stringWriter.toString();

    }

    private Crypto getCryptoInstance() {
    	Crypto crypto = null;
    	Properties properties = new Properties();
        properties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        try {
			crypto = CryptoFactory.getInstance(properties);
		} catch (Exception e) {
			log.error(e);
		}
        return crypto;
    }

    private KeyStore getKeyStore(char[] password) {
    	KeyStore keystore = null;
    	try {
            keystore = KeyStore.getInstance("JKS");
            keystore.load(null, password);
    	} catch(Exception e) {
    		log.error(e);
    	}
    	return keystore;
    }
    
    
	private X509Certificate getX509Certificate(PemObject pemObject) {
		X509Certificate x509Certificate = null;
		byte[] cert = pemObject.getContent();
		try (ByteArrayInputStream serverCert = new ByteArrayInputStream(cert);) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate generatedCertificate = cf.generateCertificate(serverCert);
			x509Certificate = (X509Certificate) generatedCertificate;
		} catch (CertificateException | IOException e) {
			log.error(e);
		}
		return x509Certificate;
	}

	private PrivateKey getPrivateKey(PemObject pemObject) {
		PrivateKey signingKey = null;
		try {
			byte[] encoded = pemObject.getContent();
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(encoded);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			signingKey = kf.generatePrivate(ks);
		} catch (Exception e) {
			log.error(e);
		}
		return signingKey;
	}

    /**
     * Crea il messaggio SOAP secondo i pattern ModI
     * 
     * @param modiPKMapping Configurazione del certificato weModI
     * @param apiConfig Configurazione dell'API weModI
     * @return Messaggio XML da inviare all'ente erogatore
     * @throws CertificateException
     * @trhows KeyStoreException
     * @trhows IOException
     * @trhows ParserConfigurationException
     * @trhows SAXException
     * @trhows TransformerException
     */
    public InputStream createSoapPayloadAsStream(ModiPKMapping modiPkMappingSOAP, ApiConfig apiConfig) throws CertificateException, KeyStoreException, IOException, ParserConfigurationException, SAXException, TransformerException {
        createSoapPayload(modiPkMappingSOAP, apiConfig);
        return getSoapPayloadAsStream();
    }

    private InputStream getSoapPayloadAsStream() throws TransformerException {
        Element soapEnvelopeEl = (Element) soapPayload.getDocumentElement();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        DOMSource source = new DOMSource(soapEnvelopeEl);
        StreamResult result = new StreamResult(baos);

        TransformerFactory transFactory = TransformerFactory.newInstance();
        transFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try {
            transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        } catch (IllegalArgumentException ex) { //NOPMD
            // ignore
        }

        Transformer transformer = transFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.transform(source, result);

        InputStream soapEnvelopeStream = new ByteArrayInputStream(baos.toByteArray());
        return soapEnvelopeStream;
    }

    public MessageContext getOrigianlMessageContext() {
        return origianlMessageContext;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = (contentType != null ? contentType : "");
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getSoapEnvNamespace() {
        return soapEnvNamespace;
    }

    public void setSoapEnvNamespace(String soapEnvNamespace) {
        this.soapEnvNamespace = soapEnvNamespace;
    }

    public Document getSoapPayload() {
        return soapPayload;
    }

    public void setSoapPayload(Document soapPayload) {
        this.soapPayload = soapPayload;
    }

}
