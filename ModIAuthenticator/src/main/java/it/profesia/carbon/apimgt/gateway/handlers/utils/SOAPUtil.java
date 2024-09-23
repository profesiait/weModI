package it.profesia.carbon.apimgt.gateway.handlers.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Vector;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMDocument;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axiom.soap.SOAPFaultCode;
import org.apache.axiom.soap.SOAPFaultDetail;
import org.apache.axiom.soap.SOAPFaultReason;
import org.apache.axiom.soap.SOAPFaultText;
import org.apache.axiom.soap.SOAPFaultValue;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.RelatesTo;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.Pipe;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.commons.lang3.tuple.Pair;
import org.xml.sax.SAXException;

/**
 * @deprecated Utilizzare la classe {@link it.profesia.wemodi.utils.WeModIContextHelper}
 */
public class SOAPUtil {

	private static final Log log = LogFactory.getLog(SOAPUtil.class);
    private static DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

    
    public static org.w3c.dom.Document toSOAPPart(String xml) throws ParserConfigurationException, SAXException, IOException {
        try (InputStream in = new ByteArrayInputStream(xml.getBytes())) {
        	factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(in);
        }
        
    }
    
    
    public static void elementToStream(Element element, OutputStream out)
	        throws TransformerException {
	        DOMSource source = new DOMSource(element);
	        StreamResult result = new StreamResult(out);

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
	    }
      
    /**
     * @deprecated utilizzare {@link org.bouncycastle.openssl.PEMReader}
     */
    public static X509Certificate getX509Certificate(String certificate)
    {
    	X509Certificate x509Certificate = null;
        byte[] cert = (org.apache.commons.codec.binary.Base64.decodeBase64(certificate.getBytes(StandardCharsets.UTF_8)));
        try (ByteArrayInputStream serverCert = new ByteArrayInputStream(cert);){
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate generatedCertificate = cf.generateCertificate(serverCert);
                x509Certificate = (X509Certificate) generatedCertificate;
        } catch (CertificateException | IOException e) {
            log.error(e);
        }
        return x509Certificate;
    }

    /**
     * @deprecated utilizzare {@link org.bouncycastle.openssl.PEMReader}
     */
    public static PrivateKey getPrivateKey(String privateKey)
    {
    	PrivateKey signingKey = null;
    	try
    	{
    	byte[] encoded = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(encoded);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		signingKey = kf.generatePrivate(ks);
    	}
    	catch(Exception e)
    	{
    		log.error(e);
    	}
    	return signingKey;
    }
    
    public static KeyStore getKeyStore(char[] password)
    {
    	KeyStore keystore = null;
    	try
    	{
        keystore = KeyStore.getInstance("JKS");
        keystore.load(null, password);
    	}
    	catch(Exception e)
    	{
    		log.error(e);
    	}
    	return keystore;
    }
    
    public static Crypto getCryptoInstance()
    {
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
    
    public static Vector verify(Document doc, Crypto crypto, WSSecurityEngine secEngine) throws WSSecurityException {
    	secEngine.setWssConfig(WSSConfig.getNewInstance());
        Vector results = secEngine.processSecurityHeader(
            doc, null, null, crypto
        );
        return results;
    }
    
    public static String getOriginalPayload(org.apache.axis2.context.MessageContext axis2MC) throws AxisFault, IOException
    {
    	String originalPayload = "";
    	ByteArrayOutputStream byteArrayOutputStream = null;
    	final Pipe pipe = (Pipe) axis2MC.getProperty(PassThroughConstants.PASS_THROUGH_PIPE);
    	if (pipe != null)
    	{
    		InputStream in = pipe.getInputStream();
    		if(in != null)
    		{
    		byteArrayOutputStream = new ByteArrayOutputStream();
            IOUtils.copy(in, byteArrayOutputStream);
            byteArrayOutputStream.flush();
            originalPayload = byteArrayOutputStream.toString();
            log.debug("originalPayload: "+originalPayload);
            in =  new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            RelayUtils.buildMessage(axis2MC, false, in);
    		}
    	}
    	return originalPayload;
    }
    
    public static String extractSOAPAction(String contentType)
    {
    	String actionValue = "";
    	if(contentType != null && contentType.contains("action"))
        {
        	String actionNameValue = contentType.substring(contentType.lastIndexOf("action"));
        	actionValue = actionNameValue.substring(actionNameValue.indexOf("\"")+1, actionNameValue.lastIndexOf("\""));	
        }
    	return actionValue;
    }
    
    public static List<Pair<String, String>> getCertificateReference(String msg) throws XMLStreamException
    {
    	List<Pair<String, String>> certificateReference = new ArrayList<Pair<String, String>>();
		XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
		XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new StringReader(msg));
		while (xmlStreamReader.hasNext()) {
		    int event = xmlStreamReader.next();
		    switch (event) {
	        case XMLStreamConstants.START_ELEMENT:
	        	int attributeCount = xmlStreamReader.getAttributeCount();
	            if(xmlStreamReader.getLocalName().equalsIgnoreCase("BinarySecurityToken"))
	            	certificateReference.add(Pair.of("BinarySecurityToken", xmlStreamReader.getElementText()));
	            else if(xmlStreamReader.getLocalName().equalsIgnoreCase("X509IssuerName"))
	            	certificateReference.add(Pair.of("X509IssuerName", xmlStreamReader.getElementText()));
	            else if(xmlStreamReader.getLocalName().equalsIgnoreCase("X509SerialNumber"))
	            	certificateReference.add(Pair.of("X509SerialNumber", xmlStreamReader.getElementText()));
	            else if(xmlStreamReader.getLocalName().equalsIgnoreCase("KeyIdentifier"))
	            {
	            	for(int i = 0; i<attributeCount; i++)
	            		if(xmlStreamReader.getAttributeLocalName(i).equalsIgnoreCase("ValueType"))
	            				if(xmlStreamReader.getAttributeValue(i).contains("X509SubjectKeyIdentifier"))
	            					certificateReference.add(Pair.of("X509SubjectKeyIdentifier", xmlStreamReader.getElementText()));
	            				else if(xmlStreamReader.getAttributeValue(i).contains("ThumbprintSHA1"))
	            					certificateReference.add(Pair.of("ThumbprintSHA1", xmlStreamReader.getElementText()));
	            				else if(xmlStreamReader.getAttributeValue(i).contains("X509v3"))
	            					certificateReference.add(Pair.of("X509KeyIdentifier", xmlStreamReader.getElementText()));
	            }
	            	
	            break;
	    }
		}
		return certificateReference;
    }
    
	public static void setSOAPFault(MessageContext messageContext, String code, String reason, String detail) {
		SOAPFactory factory = (messageContext.isSOAP11() ? OMAbstractFactory.getSOAP11Factory()
				: OMAbstractFactory.getSOAP12Factory());

		OMDocument soapFaultDocument = factory.createOMDocument();
		SOAPEnvelope faultEnvelope = factory.getDefaultFaultEnvelope();
		soapFaultDocument.addChild(faultEnvelope);

		SOAPFault fault = faultEnvelope.getBody().getFault();
		if (fault == null) {
			fault = factory.createSOAPFault();
		}

		SOAPFaultCode faultCode = factory.createSOAPFaultCode();
		if (messageContext.isSOAP11()) {
			faultCode.setText(code);
		} else {
			SOAPFaultValue value = factory.createSOAPFaultValue(faultCode);
			value.setText(code);
		}
		fault.setCode(faultCode);

		SOAPFaultReason faultReason = factory.createSOAPFaultReason();
		if (messageContext.isSOAP11()) {
			faultReason.setText(reason);
		} else {
			SOAPFaultText text = factory.createSOAPFaultText();
			text.setText(reason);
			text.setLang("en");
			faultReason.addSOAPText(text);
		}
		fault.setReason(faultReason);

		SOAPFaultDetail soapFaultDetail = factory.createSOAPFaultDetail();
		soapFaultDetail.setText(detail);
		fault.setDetail(soapFaultDetail);

		// set the all headers of original SOAP Envelope to the Fault Envelope
		if (messageContext.getEnvelope() != null) {
			SOAPHeader soapHeader = messageContext.getEnvelope().getHeader();
			if (soapHeader != null) {
				for (Iterator iterator = soapHeader.examineAllHeaderBlocks(); iterator.hasNext();) {
					Object o = iterator.next();
					if (o instanceof SOAPHeaderBlock) {
						SOAPHeaderBlock header = (SOAPHeaderBlock) o;
						faultEnvelope.getHeader().addChild(header);
					} else if (o instanceof OMElement) {
						faultEnvelope.getHeader().addChild((OMElement) o);
					}
				}
			}
		}
		
		faultEnvelope.getBody().addChild(fault);
		
		

		try {
			messageContext.setEnvelope(faultEnvelope);
		} catch (AxisFault af) {
			log.error("Error while setting SOAP fault as payload", af);
			return;
		}

		if (messageContext.getFaultTo() != null) {
			messageContext.setTo(messageContext.getFaultTo());
		} else if (messageContext.getReplyTo() != null) {
			messageContext.setTo(messageContext.getReplyTo());
		} else {
			messageContext.setTo(null);
		}

		// set original messageID as relatesTo
		if (messageContext.getMessageID() != null) {
			RelatesTo relatesTo = new RelatesTo(messageContext.getMessageID());
			messageContext.setRelatesTo(new RelatesTo[] { relatesTo });
		}
	}
	
	public static String extractCertificateAsLinearizedString(String certificate)
	{
		if(certificate != null)
			return certificate.replace("-----BEGIN CERTIFICATE-----", "").replaceAll(System.lineSeparator(), "").replace("-----END CERTIFICATE-----", "");
		return "";
	}
    


	
}
