package it.profesia.carbon.apimgt.subscription.utils;

public class CertificateUtils{
	
	
	public static String getUniqueIdentifierOfCertificate(String certificate) {
		certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
		return CertificateMetadata.getUniqueIdentifierOfCertificate(CertificateMetadata.getX509Certificate(certificate));
	}

    
	public static String getThumbprintOfCertificate(String publicCert) {
    	publicCert = publicCert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
    	return CertificateMetadata.getThumbprintOfCertificate(CertificateMetadata.getX509Certificate(publicCert));  
    }


	
	public static String getIssuerDNOfCertificate(String publicCert) {
		publicCert = publicCert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
		return CertificateMetadata.getX509Certificate(publicCert).getIssuerDN().toString();
	}

	
    public static String getHashOfCertificate(String publicCert) {
		publicCert = publicCert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
		return CertificateMetadata.getHashOfCertificate(CertificateMetadata.getX509Certificate(publicCert));
    }


	
	public static String getThumbprintOfCertificate256(String publicCert) {
		publicCert = publicCert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
		return CertificateMetadata.getThumbprintOfCertificate256(CertificateMetadata.getX509Certificate(publicCert));
	}


	public static String getThumbprint256(String publicCert) {
		if(publicCert != null && !(publicCert.equals("")))
		{
			publicCert = publicCert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getThumbprintOfCertificate256(CertificateMetadata.getX509Certificate(publicCert));
		}
		return null;
		
	}

	public static String getThumbprint(String publicCert) {
		if(publicCert != null && !(publicCert.equals("")))
		{
			publicCert = publicCert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getThumbprintOfCertificate(CertificateMetadata.getX509Certificate(publicCert));
		}
		return null;
		
	}

	public static String getSerialNumber(String certificate) {
		if(certificate != null && !(certificate.equals("")))
		{
			certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getSerialNumber(certificate);
		}
		return null;
		
	}

	public static String getIssuerDN(String certificate) {
		if(certificate != null && !(certificate.equals("")))
		{
			certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getIssuerDN(certificate);
		}
		return null;
		
	}
	
	public static String getIssuerName(String certificate) {
		if(certificate != null && !(certificate.equals("")))
		{
			certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getIssuerName(certificate);
		}
		return null;
	}
	
	public static String getSubjectKeyIdentifierSOAP(String certificate) {
		if(certificate != null && !(certificate.equals("")))
		{
			certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getSubjectKeyIdentifierSOAP(certificate);
		}
		return null;
	}
	
	public static String getThumbprintSOAP(String certificate) {
		if(certificate != null && !(certificate.equals("")))
		{
			certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getThumbprintSOAP(certificate);
		}
		return null;
	}
	
	public static String getThumbprint256SOAP(String certificate) {
		if(certificate != null && !(certificate.equals("")))
		{
			certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
			return CertificateMetadata.getThumbprint256SOAP(certificate);
		}
		return null;
	}

}
