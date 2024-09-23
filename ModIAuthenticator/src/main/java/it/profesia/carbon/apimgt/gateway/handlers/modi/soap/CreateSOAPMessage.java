package it.profesia.carbon.apimgt.gateway.handlers.modi.soap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;
import java.util.UUID;
import java.util.Vector;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.util.XMLUtils;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import it.profesia.carbon.apimgt.gateway.handlers.modi.FruizioneModiHandler;
import it.profesia.carbon.apimgt.gateway.handlers.utils.SOAPUtil;
import it.profesia.wemodi.ApiConfig;
import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;

/**
 * @deprecated Utilizzare la classe {@link it.profesia.wemodi.utils.WeModIContextHelper}
 */
public class CreateSOAPMessage {
	
	private static final Log log = LogFactory.getLog(CreateSOAPMessage.class);
	
	static String soapEnvNamespace = "";

    /**
     * @deprecated utilizzare il metodo {@link it.profesia.wemodi.utils.WeModIContextHelper#createSoapPayload(ModiPKMapping, ApiConfig)}
     * Crea il messaggio SOAP secondo i pattern ModI
     * 
     * @param msg Messaggio SOAP del client
     * @param modiPKMapping Configurazione del certificato weModI
     * @param apiConfig Configurazione dell'API weModI
     * @return Messaggio XML da inviare all'ente erogatore
     * @throws IOException
     * @throws CertificateException
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws KeyStoreException 
     */
    public static Document create(String msg, ModiPKMapping modiPKMapping, ApiConfig apiConfig) throws IOException, CertificateException, ParserConfigurationException, SAXException, KeyStoreException {
    	PEMParser certPemParser = new PEMParser(new StringReader(modiPKMapping.getCertificate()));
    	PemObject certPemObject = certPemParser.readPemObject();

        X509Certificate x509certificate = getX509Certificate(certPemObject);
        WSSecSignature sign = new WSSecSignature();
        sign.setX509Certificate(x509certificate);

        String keyStoreAlias = RandomStringUtils.randomAlphanumeric(10);
		String keyStorePassword = RandomStringUtils.randomAlphanumeric(10);
        sign.setUserInfo(keyStoreAlias, keyStorePassword);

        String updatedMsg = CreateSOAPMessage.addElementToExistingXml(msg, modiPKMapping.getWsaddressingTo(), apiConfig.isIdAuthSoap02());

        Document doc = SOAPUtil.toSOAPPart(updatedMsg);

        Crypto crypto = SOAPUtil.getCryptoInstance();
        KeyStore keystore = SOAPUtil.getKeyStore(keyStorePassword.toCharArray());

        PEMParser pkPemParser = new PEMParser(new StringReader(modiPKMapping.getPrivkey()));
        PemObject privateKey = pkPemParser.readPemObject();

        PrivateKey signingKey = getPrivateKey(privateKey);
        keystore.setKeyEntry(keyStoreAlias, signingKey, keyStorePassword.toCharArray(), new Certificate[]{x509certificate});
        ((Merlin) crypto).setKeyStore(keystore);
        crypto.loadCertificate(new ByteArrayInputStream(x509certificate.getEncoded()));  

        WSSecHeader secHeader = new WSSecHeader();
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
                log.warn(String.format( "Valore non supportato %s:%s.", apiConfig.KEY_IDENTIFIER_TYPE, apiConfig.getKeyIdentifierType()));
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

        Document signedDoc = sign.build(doc, crypto, secHeader);
        if(log.isDebugEnabled()) {
        	String outputMsg = XMLUtils.PrettyDocumentToString(signedDoc);
            log.debug(outputMsg);
        }
        return signedDoc;
    }

    /**
     * @deprecated utilizzare {@link #create(String, ModiPKMapping, ApiConfig)}
     * Crea il messaggio SOAP secondo i pattern ModI
     * 
     * @param msg
     * @param modiPKMapping
     * @param modiSOAPProps
     * @return
     * @throws KeyStoreException
     * @throws WSSecurityException
     * @throws CertificateEncodingException
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
	public static Document create(String msg, ModiPKMapping modiPKMapping, Properties modiSOAPProps) throws KeyStoreException, WSSecurityException, CertificateEncodingException, ParserConfigurationException, SAXException, IOException 
	{
		//String outputMsg = "";
		
		/*String certificate = "MIID6zCCAtOgAwIBAgIUBFy5HujD8fwA5oKItUyj4o+0DdkwDQYJKoZIhvcNAQELBQAwgYQxCzAJBgNVBAYTAklUMQswCQYDVQQIDAJCTzEQMA4GA1UEBwwHQm9sb2duYTERMA8GA1UECgwIUHJvZmVzaWExDTALBgNVBAsMBEx5bngxEjAQBgNVBAMMCWxvY2FsaG9zdDEgMB4GCSqGSIb3DQEJARYRcGlwcG9AcHJvZmVzaWEuaXQwHhcNMjIxMTI1MDkyMTM5WhcNMjMxMTI1MDkyMTM5WjCBhDELMAkGA1UEBhMCSVQxCzAJBgNVBAgMAkJPMRAwDgYDVQQHDAdCb2xvZ25hMREwDwYDVQQKDAhQcm9mZXNpYTENMAsGA1UECwwETHlueDESMBAGA1UEAwwJbG9jYWxob3N0MSAwHgYJKoZIhvcNAQkBFhFwaXBwb0Bwcm9mZXNpYS5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANDS1LZTSCXHEMoFkWzfuBZU8v7uAvuK6pkN4F7cppR5fpbGemWiUWKdlkwaKSTiPKm06HzkAV/wRmym7S0VvqHW2ziSw8HyR6RSimfdNm4fDi0zS8041Yg5DhbmrWEsRxU7kIdtehW7sb9dSTohIEE+FaUpU+/doOAnOQuSvKk122c0HsDxSxJH2FMm2/Tc0uywloGitGz0VJKRQZw8FURaMSB5q9BIaM3bmUWnFW9lrFoaN/ugG1CSB3BBZW/Grh5+/8rSc7oO6RXUK3dLwdcTbGmkTOvSQmr2HxTHqQTpXVRK4cE4HVlpS9FxyaM1BGuICy2xiuqtMvtcLKpqS6kCAwEAAaNTMFEwHQYDVR0OBBYEFEYj3RUWpoRs7QsV7zujrpWo9ybyMB8GA1UdIwQYMBaAFEYj3RUWpoRs7QsV7zujrpWo9ybyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGHOSLsD/NqStQcXssJDGlH8gBMpD9yzuNmabbV6HI4gRdN6VtQ82xbC9HjpIewSOjfSd1jLEFbhcEH+2lGjQhJ8HlsFh9LS8vSaDkhDsv4eHIsg/dfSTlit1hQmb4Jb5ArY1Bz9+io9tsxCNO0zdZMQy4nHWEL9z5YvAK2UYdc4UwQ+KlOQtQtSbhZcaOURguzL9aZbkT76oXCMpO+WqSUkvErYtCc0lW7ZD+GZMixre7Tjiv1wYdnM8FUBjWLdzh4qlnJGw5TtpfbQPqpCY2al5ltzkG6UVtVNG49/M5YeJb4p/0DAt3s+irGFYdmaNXDEPf1N0ejIPgc2HU0TMas=";
		String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQ0tS2U0glxxDKBZFs37gWVPL+7gL7iuqZDeBe3KaUeX6WxnplolFinZZMGikk4jyptOh85AFf8EZspu0tFb6h1ts4ksPB8kekUopn3TZuHw4tM0vNONWIOQ4W5q1hLEcVO5CHbXoVu7G/XUk6ISBBPhWlKVPv3aDgJzkLkrypNdtnNB7A8UsSR9hTJtv03NLssJaBorRs9FSSkUGcPBVEWjEgeavQSGjN25lFpxVvZaxaGjf7oBtQkgdwQWVvxq4efv/K0nO6DukV1Ct3S8HXE2xppEzr0kJq9h8Ux6kE6V1USuHBOB1ZaUvRccmjNQRriAstsYrqrTL7XCyqakupAgMBAAECggEAJTqxOaA3aKTI1XuQpbxs8W5LtC9y0K2/jXHv4nmsKSRP8UmJYL1DjTVTKlYvp6e98POTz1BG/nez1oMcHcGWrvvDMZ7Yz6cGJsGgc0v4/EEFIgHXLctIJnUlkeemWYCvW5W2+q4F6gIAeoGDIJ3vRjJvYXawxD7bA5t6jBmpEPF6j1roHbDo0NR5HNFDNYkUS4D+2LpZzbCIKQhb6O7wsDJEqvAdUtfNHfZv0j+RtHoqxRDZug2F4Y/JeoXKHeV5h2mLM7RI6Xa1BRUMPu6k4DtrLb1s5l1lvLFm/225CLnynyWQGeMFUAInRNqjI4cGubMwsgFM6D2ZJhvUeauNkQKBgQD0NZb9AG0m7+ZMSNgTdJvQQngKjPMcVoNJB+q1Ke0gZlhHOuJEXGgPLgDjDa9bR5Z8HUYuopBzlG8kh6VqiSimkrfZEX7KblT6SXxKcPyySALGvOT65p/LMPZyo62w0YTGbBZwPDBvIZzYFRdWO+NUk+VnJHvQCk90N4jpqMHIwwKBgQDa5+AZ8FiHTllEJWyrFHLtAThoVfEBscc+VtfetpsrOUPNCVT3YeKhMEv+KDSjiwWhT8RgDJEaTVI70FlFZxu4NhXLuZnZMn51KCVeWh4/stDx5bNuVUA5IXpgygqfR2W+O+Xu8kANJ5jCdZXIt/09MRM1DlZEyjnIJiMiSI8zIwKBgCR90YcSxjy4QmCJzgfyN8pB9HAXKcjFQK7sCO1zS2S5Bl32dZMjf8Us6aMEC30HUHxRX4hecFllB8qcnmIyBqoFaIV+MMUNAZO44WK6SXhWfFu4JDs9tQkG0vzEapLua/m+cwfoZpBkpGxBkpAnOMwNoYztDbdDoyXJmqLXvcVDAoGBALnXXQPobeAA/fvCoezj4WWgQZkiTQcZPIOKCp5C/JzHcu4g3AdhDJu3eux8iaPGJLN8GsVIJe/kcMni6cbn8DqFgB+CpEAmhAFGYeMmMsP1NToHvjsPGQTnjROas0XhwVitVVl0RDhmw2NjnBPZT56hiSLj1w1zeXaYGf/DBf9tAoGAYf1kGkSwwlWqs8jg77qVD5e7XperhO3sgYNYLjP9wRL3dBtatcrBfD/ZsKv/e8IEsZtqt8IKUGGZJd5xRzNFx769Y0wXkgaI5hWAbPoPml75mu3sAsAJTQNch80BMIJnRTZJwl5YFIIcB2JIxju+9w8lMBdDfdYBWEPL4iwZaKc=";
		String toElemValue = "https://api.ente.example/soap/echo/v1";*/
		boolean id_auth_soap_02 = BooleanUtils.isTrue(BooleanUtils.toBooleanObject(modiSOAPProps.getProperty(FruizioneModiHandler.ID_AUTH_SOAP_02)));
		boolean integrity_soap_01 = BooleanUtils.isTrue(BooleanUtils.toBooleanObject(modiSOAPProps.getProperty(FruizioneModiHandler.INTEGRITY_SOAP_01)));
		String keyIdentifierType = modiSOAPProps.getProperty(FruizioneModiHandler.KEY_IDENTIFIER_TYPE);
		log.info("keyIdentifierType: "+keyIdentifierType);
		
		String certificate = modiPKMapping.getCertificate();
		String privateKey = modiPKMapping.getPrivkey();
		String toElemValue = modiPKMapping.getWsaddressingTo();
		String keyStoreAlias = RandomStringUtils.randomAlphanumeric(10);
		String keyStorePassword = RandomStringUtils.randomAlphanumeric(10);
		
		/*Document originalDoc = SOAPUtil.toSOAPPart(msg);
		
		Element toElem = originalDoc.createElementNS("http://www.w3.org/2005/08/addressing", "To");
        toElem.setTextContent(toElemValue);
        Element soapHeader = (Element) originalDoc.getElementsByTagName("soap:Header").item(0);
        soapHeader.appendChild(toElem);
        
        String updatedMsg = XMLUtils.PrettyDocumentToString(originalDoc);*/
		
		String updatedMsg = addElementToExistingXml(msg, toElemValue, id_auth_soap_02);
        Document doc = SOAPUtil.toSOAPPart(updatedMsg);
	
		WSSConfig.getNewInstance();
		
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.setMustUnderstand(false);
        secHeader.insertSecurityHeader(doc);
        
        X509Certificate x509certificate = SOAPUtil.getX509Certificate(certificate);
        Certificate[] certificateObj = new Certificate[]{x509certificate};

        Crypto crypto = SOAPUtil.getCryptoInstance();
        KeyStore keystore = SOAPUtil.getKeyStore(keyStorePassword.toCharArray());
		PrivateKey signingKey = SOAPUtil.getPrivateKey(privateKey);
        keystore.setKeyEntry(keyStoreAlias, signingKey, keyStorePassword.toCharArray(), certificateObj);
        ((Merlin) crypto).setKeyStore(keystore);
        crypto.loadCertificate(new ByteArrayInputStream(x509certificate.getEncoded()));  
        
        WSSecSignature sign = new WSSecSignature();
        sign.setX509Certificate(x509certificate);
        sign.setUserInfo(keyStoreAlias, keyStorePassword);
        
//        sign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
//        sign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        if(keyIdentifierType.equals("BST_DIRECT_REFERENCE"))
        	sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        if(keyIdentifierType.equals("X509_KEY_IDENTIFIER"))
        	sign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        if(keyIdentifierType.equals("ISSUER_SERIAL"))
        	sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        if(keyIdentifierType.equals("THUMBPRINT_IDENTIFIER"))
        	sign.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        if(keyIdentifierType.equals("SKI_KEY_IDENTIFIER"))
        	sign.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);

//        sign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
//        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
//        sign.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
//        sign.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        timestamp.build(doc, secHeader);
        Vector<WSEncryptionPart> signParts = new Vector<WSEncryptionPart>();
        signParts.add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
        if(id_auth_soap_02)
        	signParts.add(new WSEncryptionPart("MessageID", "http://www.w3.org/2005/08/addressing", "Element"));
        signParts.add(new WSEncryptionPart("To", "http://www.w3.org/2005/08/addressing", "Element"));
        if(integrity_soap_01)
        	signParts.add(new WSEncryptionPart("Body", soapEnvNamespace, "Element"));
        sign.setParts(signParts);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        if(log.isDebugEnabled())
        {
        	String outputMsg = XMLUtils.PrettyDocumentToString(signedDoc);
            log.debug(outputMsg);
        }
        return signedDoc;
	}
	
	private static String addElementToExistingXml(String msg, String toElemValue, boolean id_auth_soap_02)
    {
	 	XMLStreamWriter xmlStreamWriter = null;
        XMLStreamReader xmlStreamReader = null;
		StringWriter stringWriter = new StringWriter();
		try
		{
		XMLOutputFactory outputFactory = XMLOutputFactory.newInstance();
		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		xmlStreamWriter = outputFactory.createXMLStreamWriter(stringWriter);
		xmlStreamReader = xmlInputFactory.createXMLStreamReader(new StringReader(msg));
		
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
			        		if(id_auth_soap_02)
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
	
	private static X509Certificate getX509Certificate(PemObject pemObject) {
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

	private static PrivateKey getPrivateKey(PemObject pemObject) {
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

}
