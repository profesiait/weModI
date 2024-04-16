package it.profesia.wemodi.providers.utils;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import it.profesia.wemodi.subscriptions.utils.CertificateMetadata;

public class ProvidersUtils {
	
	private static final Log log = LogFactory.getLog(ProvidersUtils.class);
	
	public static JWSHeader buildJWTHeaderWithKid(String kid) {
		com.nimbusds.jose.JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT);
		if (kid != null && !(kid.equals("")))
			headerBuilder.keyID(kid);
		return headerBuilder.build();
	}
	
	public static JWSHeader buildJWTHeader(String reference_certificate_type, String certificate) throws CertificateException
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
	        
	        if(reference_certificate_type == null || reference_certificate_type.equals(""))
	        		return setX5c(headerBuilder, cert).build();
	        	
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
	
	public static URI isValidURL(String url) {
		URI uri = null;
	    try {
	        uri = new URL(url).toURI();
	    } catch (MalformedURLException | URISyntaxException e) {
	        log.error("It's not a valid URL: "+url);
	    } 
	    return uri;
	}
    
    public static com.nimbusds.jose.JWSHeader.Builder setX5c(com.nimbusds.jose.JWSHeader.Builder headerBuilder, X509Certificate cert) throws CertificateEncodingException
	 {
		 List<com.nimbusds.jose.util.Base64> certs = new ArrayList<>();
		 certs.add(new com.nimbusds.jose.util.Base64(Base64.getUrlEncoder().withoutPadding().encodeToString(cert.getEncoded())));
		 headerBuilder.x509CertChain(certs);
		 return headerBuilder;
	 }
    
    public static byte[] convertToDigestBytes(String payload) {
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

}
