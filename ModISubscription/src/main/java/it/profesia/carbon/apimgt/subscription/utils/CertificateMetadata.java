package it.profesia.carbon.apimgt.subscription.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.common.gateway.util.JWTUtil;

import com.nimbusds.jose.util.X509CertUtils;

public class CertificateMetadata {
	private static final Log log = LogFactory.getLog(CertificateMetadata.class);

	public static X509Certificate getX509Certificate(String certificate) {

		X509Certificate x509Certificate = null;
		byte[] cert = (org.apache.commons.codec.binary.Base64.decodeBase64(certificate.getBytes(StandardCharsets.UTF_8)));
		try (ByteArrayInputStream serverCert = new ByteArrayInputStream(cert);){
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate generatedCertificate = cf.generateCertificate(serverCert);
			x509Certificate = (X509Certificate) generatedCertificate;
		} catch (CertificateException | IOException e) {
			log.error("Error while converting into X509Certificate.", e);
		}
		log.debug("X509Certificate: " + x509Certificate);
		return x509Certificate;
	}

	public static String getThumbprintOfCertificate(X509Certificate publicCert)
	{
		String base64UrlEncodedThumbPrint = "";
		try {
			//generate the SHA-1 thumbprint of the certificate
			MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
			byte[] der = publicCert.getEncoded();
			digestValue.update(der);
			byte[] digestInBytes = digestValue.digest();
			String publicCertThumbprint = JWTUtil.hexify(digestInBytes);
			base64UrlEncodedThumbPrint = java.util.Base64.getUrlEncoder()
					.encodeToString(publicCertThumbprint.getBytes("UTF-8"));

		} catch (NoSuchAlgorithmException | CertificateEncodingException | UnsupportedEncodingException e) {
			log.error("Error in generating public certificate thumbprint", e);
		}
		return base64UrlEncodedThumbPrint;
	}


	public static String getThumbprintOfCertificate256(X509Certificate publicCert)
	{
		String base64UrlEncodedThumbPrint = "";
		try {
			//generate the SHA-1 thumbprint of the certificate
			MessageDigest digestValue = MessageDigest.getInstance("SHA-256");
			byte[] der = publicCert.getEncoded();
			digestValue.update(der);
			byte[] digestInBytes = digestValue.digest();
			String publicCertThumbprint = JWTUtil.hexify(digestInBytes);
			base64UrlEncodedThumbPrint = java.util.Base64.getUrlEncoder()
					.encodeToString(publicCertThumbprint.getBytes("UTF-8"));

		} catch (NoSuchAlgorithmException | CertificateEncodingException | UnsupportedEncodingException e) {
			log.error("Error in generating public certificate thumbprint", e);
		}
		return base64UrlEncodedThumbPrint;
	}

	public String getThumbprint (String certificate) {
		String thumbprint = getThumbprintOfCertificate(getX509Certificate(certificate));
		return thumbprint;
	}

	public String getThumbprint256 (String certificate) {
		String thumbprint256 = getThumbprintOfCertificate256(getX509Certificate(certificate));
		return thumbprint256;
	}

	public static String getSerialNumber(String certificate) {
		byte[] cert = (org.apache.commons.codec.binary.Base64.decodeBase64(certificate.getBytes(StandardCharsets.UTF_8)));
		String serialNumber = ""; //SN
		try (ByteArrayInputStream serverCert = new ByteArrayInputStream(cert);){
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			// while (serverCert.available() > 0) {
			Certificate generatedCertificate = cf.generateCertificate(serverCert);
			X509Certificate x509Certificate = (X509Certificate) generatedCertificate;

			serialNumber = x509Certificate.getSerialNumber().toString();

			// }
		} catch (CertificateException | IOException e) {
			log.error("Error while getting serial number of the certificate.", e);
		} /*finally {
            closeStreams(serverCert);
        }*/
		return serialNumber;
	}

	public static String getIssuerDN(String certificate) {
		byte[] cert = (org.apache.commons.codec.binary.Base64.decodeBase64(certificate.getBytes(StandardCharsets.UTF_8)));
		String issuerDN = ""; //IDN
		try (ByteArrayInputStream serverCert = new ByteArrayInputStream(cert);){
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			// while (serverCert.available() > 0) {
			Certificate generatedCertificate = cf.generateCertificate(serverCert);
			X509Certificate x509Certificate = (X509Certificate) generatedCertificate;
			X500Principal p = x509Certificate.getIssuerX500Principal();

			issuerDN = p.getName();

			// }
		} catch (CertificateException | IOException e) {
			log.error("Error while getting issuerDN of the certificate.", e);
		} /*finally {
            closeStreams(serverCert);
        }*/
		return issuerDN;
	}
	
	public static String getIssuerName(String certificate) {
		byte[] cert = (org.apache.commons.codec.binary.Base64.decodeBase64(certificate.getBytes(StandardCharsets.UTF_8)));
		String issuerName = ""; 
		try (ByteArrayInputStream serverCert = new ByteArrayInputStream(cert);){
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			// while (serverCert.available() > 0) {
			Certificate generatedCertificate = cf.generateCertificate(serverCert);
			X509Certificate x509Certificate = (X509Certificate) generatedCertificate;

			issuerName = (x509Certificate.getIssuerDN().getName()).replaceAll("\\s", "");

			// }
		} catch (CertificateException | IOException e) {
			log.error("Error while getting issuer name of the certificate.", e);
		} /*finally {
            closeStreams(serverCert);
        }*/
		return issuerName;
	}

    public static String getUniqueIdentifierOfCertificate(X509Certificate x509Certificate) {
    	
    	String uniqueIdentifier = "";

        /**
         * Il metodo getIssuerDN() &egrave; marcato come <strong>Denigrated</strong>
         * attualmente &egrave; ancora utilizzato nel codice sorgente dei prodotti WSO2:
         *
         * <strong>PROFESIADEV-363</strong>:
         * <strong>getIssuerX500Principal()</strong> is the correct method to use.
         * <strong>getIssuerDN()</strong> method has been deprecated since jdk 16,
         * hence we will migrate the method in the upcoming release (with JDK 17 support).
         * But, if you have any concerns, you can simply implement this util method
         * in your custom implementation and use <strong>getIssuerX500Principal()</strong>
         * instead of <strong>getIssuerDN()</strong>
         */
        X500Principal p = x509Certificate.getIssuerX500Principal();
        uniqueIdentifier = x509Certificate.getSerialNumber() + "_" + p.getName();
        //uniqueIdentifier = x509Certificate.getSerialNumber() + "_" + x509Certificate.getIssuerDN();
        uniqueIdentifier = uniqueIdentifier.replaceAll(",", "#").replaceAll("\"", "'");

        return uniqueIdentifier;
    }

    public static String getHashOfCertificate(X509Certificate x509Certificate) {

    	String clientCertificateHash = "";
    	clientCertificateHash = X509CertUtils.computeSHA256Thumbprint(x509Certificate).toString();
    	log.info("clientCertificateHash: "+clientCertificateHash);
    	return clientCertificateHash;
    }
    
    public static String getSubjectKeyIdentifierSOAP(String certificate) {
		//
        // Gets the DER-encoded OCTET string for the extension value (extnValue)
        // identified by the passed-in oid String. The oid string is represented
        // by a set of positive whole numbers separated by periods.
        //
		String base64UrlEncodedSki = "";
		X509Certificate x509certificate = CertificateMetadata.getX509Certificate(certificate);
        byte[] derEncodedValue = x509certificate.getExtensionValue("2.5.29.14");

        if (x509certificate.getVersion() < 3 || derEncodedValue == null) {
            PublicKey key = x509certificate.getPublicKey();
            
            byte[] encoded = key.getEncoded();
            // remove 22-byte algorithm ID and header
            byte[] value = new byte[encoded.length - 22];
            System.arraycopy(encoded, 22, value, 0, value.length);
            MessageDigest sha = null;
            try {
                sha = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }
            sha.reset();
            sha.update(value);
            return java.util.Base64.getEncoder()
                    .encodeToString(sha.digest());
        }

        //
        // Strip away first four bytes from the DerValue (tag and length of
        // ExtensionValue OCTET STRING and KeyIdentifier OCTET STRING)
        //
        byte abyte0[] = new byte[derEncodedValue.length - 4];

        System.arraycopy(derEncodedValue, 4, abyte0, 0, abyte0.length);
        base64UrlEncodedSki = java.util.Base64.getEncoder()
                .encodeToString(abyte0);
        return base64UrlEncodedSki;
	}
    
	public static String getThumbprintSOAP(String certificate) {
		String base64UrlEncodedThumbPrint = "";
		X509Certificate x509certificate = CertificateMetadata.getX509Certificate(certificate);
		 try {
	            //generate the SHA-1 thumbprint of the certificate
	            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
	            byte[] der = x509certificate.getEncoded();
	            digestValue.update(der);
	            byte[] digestInBytes = digestValue.digest();
	            base64UrlEncodedThumbPrint = java.util.Base64.getEncoder()
	                    .encodeToString(digestInBytes);

	        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
	            log.error("Error in getting thumbprint for SOAP", e);
	        }
		 return base64UrlEncodedThumbPrint;
	}
	
	public static String getThumbprint256SOAP(String certificate) {
		String base64UrlEncodedThumbPrint = "";
		X509Certificate x509certificate = CertificateMetadata.getX509Certificate(certificate);
		 try {
	            //generate the SHA-256 thumbprint of the certificate
	            MessageDigest digestValue = MessageDigest.getInstance("SHA-256");
	            byte[] der = x509certificate.getEncoded();
	            digestValue.update(der);
	            byte[] digestInBytes = digestValue.digest();
	            base64UrlEncodedThumbPrint = java.util.Base64.getEncoder()
	                    .encodeToString(digestInBytes);

	        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
	            log.error("Error in getting thumbprint for SOAP", e);
	        }
		 return base64UrlEncodedThumbPrint;
	}
	
	/**
     * Helper method to hexify a byte array.
     *
     * @param bytes - The input byte array
     * @return hexadecimal representation
     */
    public static String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }
    
    public static String encodeToBase64(String jwt)
	{
		String encodedString = Base64.getEncoder().encodeToString(jwt.getBytes());
		return encodedString;
		
	}
	
	public static String decodeFromBase64(String encodedJwt)
	{
		byte[] decodedBytes = Base64.getDecoder().decode(encodedJwt);
		String decodedString = new String(decodedBytes);
		return decodedString;
		
	}

}
