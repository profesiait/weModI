package it.profesia.carbon.apimgt.gateway.handlers.modi.soap;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Vector;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import it.profesia.carbon.apimgt.gateway.handlers.utils.SOAPUtil;

public class ValidateSOAPMessage {
	
	private static WSSecurityEngine secEngine = new WSSecurityEngine();
	private static final Log log = LogFactory.getLog(ValidateSOAPMessage.class);
	
	public static X509Certificate validate(String msg, String certificate) throws KeyStoreException, WSSecurityException, IOException, SAXException, ParserConfigurationException, XMLStreamException
	{
		//boolean isValid = false;
		
		/*String certificate = "";
		List<Pair<String, String>> certificateReference = SOAPUtil.getCertificateReference(msg);
		for(Pair<String, String> ref : certificateReference)
		{
			certificate = ref.getValue();
			log.info("Certificate reference: "+ref.getKey() + " " + certificate);
		}*/
		
		//String certificate = "MIID6zCCAtOgAwIBAgIUBFy5HujD8fwA5oKItUyj4o+0DdkwDQYJKoZIhvcNAQELBQAwgYQxCzAJBgNVBAYTAklUMQswCQYDVQQIDAJCTzEQMA4GA1UEBwwHQm9sb2duYTERMA8GA1UECgwIUHJvZmVzaWExDTALBgNVBAsMBEx5bngxEjAQBgNVBAMMCWxvY2FsaG9zdDEgMB4GCSqGSIb3DQEJARYRcGlwcG9AcHJvZmVzaWEuaXQwHhcNMjIxMTI1MDkyMTM5WhcNMjMxMTI1MDkyMTM5WjCBhDELMAkGA1UEBhMCSVQxCzAJBgNVBAgMAkJPMRAwDgYDVQQHDAdCb2xvZ25hMREwDwYDVQQKDAhQcm9mZXNpYTENMAsGA1UECwwETHlueDESMBAGA1UEAwwJbG9jYWxob3N0MSAwHgYJKoZIhvcNAQkBFhFwaXBwb0Bwcm9mZXNpYS5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANDS1LZTSCXHEMoFkWzfuBZU8v7uAvuK6pkN4F7cppR5fpbGemWiUWKdlkwaKSTiPKm06HzkAV/wRmym7S0VvqHW2ziSw8HyR6RSimfdNm4fDi0zS8041Yg5DhbmrWEsRxU7kIdtehW7sb9dSTohIEE+FaUpU+/doOAnOQuSvKk122c0HsDxSxJH2FMm2/Tc0uywloGitGz0VJKRQZw8FURaMSB5q9BIaM3bmUWnFW9lrFoaN/ugG1CSB3BBZW/Grh5+/8rSc7oO6RXUK3dLwdcTbGmkTOvSQmr2HxTHqQTpXVRK4cE4HVlpS9FxyaM1BGuICy2xiuqtMvtcLKpqS6kCAwEAAaNTMFEwHQYDVR0OBBYEFEYj3RUWpoRs7QsV7zujrpWo9ybyMB8GA1UdIwQYMBaAFEYj3RUWpoRs7QsV7zujrpWo9ybyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGHOSLsD/NqStQcXssJDGlH8gBMpD9yzuNmabbV6HI4gRdN6VtQ82xbC9HjpIewSOjfSd1jLEFbhcEH+2lGjQhJ8HlsFh9LS8vSaDkhDsv4eHIsg/dfSTlit1hQmb4Jb5ArY1Bz9+io9tsxCNO0zdZMQy4nHWEL9z5YvAK2UYdc4UwQ+KlOQtQtSbhZcaOURguzL9aZbkT76oXCMpO+WqSUkvErYtCc0lW7ZD+GZMixre7Tjiv1wYdnM8FUBjWLdzh4qlnJGw5TtpfbQPqpCY2al5ltzkG6UVtVNG49/M5YeJb4p/0DAt3s+irGFYdmaNXDEPf1N0ejIPgc2HU0TMas=";
		String keyStoreAlias = RandomStringUtils.randomAlphanumeric(10);
		String keyStorePassword = RandomStringUtils.randomAlphanumeric(10);
		
		Document docResult = SOAPUtil.toSOAPPart(msg);
		
		X509Certificate x509certificate = SOAPUtil.getX509Certificate(certificate);
		
        Crypto cryptoToVal = SOAPUtil.getCryptoInstance();
        KeyStore keystoreToVal = SOAPUtil.getKeyStore(keyStorePassword.toCharArray());
        keystoreToVal.setCertificateEntry(keyStoreAlias, x509certificate);
        ((Merlin) cryptoToVal).setKeyStore(keystoreToVal);
        Vector results = SOAPUtil.verify(docResult, cryptoToVal, secEngine);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        if(cert != null)
        {
        	log.info("Valid SOAP Certificate: "+cert.toString());
        	return cert;
        	//isValid = true;
        }
        //return isValid;
        return null;
        
		}
	}


