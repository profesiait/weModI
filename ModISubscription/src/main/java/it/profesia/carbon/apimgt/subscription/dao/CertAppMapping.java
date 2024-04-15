package it.profesia.carbon.apimgt.subscription.dao;

public class CertAppMapping {
	
	private String applicationUUID;
	private String applicationName;
	private String applicationCreator;
	private String certHash;
	private String serialNumber;
	private String issuerDN;
	private String issuerName;
	private String alias;
	private String thumbprint;
	private String thumbprintSha256;
	private String pdndPublicKey;
	private String pdndPurposeId;
	private String certificate;
	private String subjectKeyIndentifier;
	private String pdndKidApiInterop;
	
	public String getPdndKidApiInterop() {
		return pdndKidApiInterop;
	}

	public void setPdndKidApiInterop(String pdndKidApiInterop) {
		this.pdndKidApiInterop = pdndKidApiInterop;
	}
	
	public String getSubjectKeyIndentifier() {
		return subjectKeyIndentifier;
	}

	public void setSubjectKeyIndentifier(String subjectKeyIndentifier) {
		this.subjectKeyIndentifier = subjectKeyIndentifier;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	public String getPdndPurposeId() {
		return pdndPurposeId;
	}

	public void setPdndPurposeId(String pdndPurposeId) {
		this.pdndPurposeId = pdndPurposeId;
	}

	public String getPdndClientId() {
		return pdndClientId;
	}

	public void setPdndClientId(String pdndClientId) {
		this.pdndClientId = pdndClientId;
	}
	private String pdndClientId;
	
	

	public String getPdndPublicKey() {
		return pdndPublicKey;
	}

	public void setPdndPublicKey(String pdndPublicKey) {
		this.pdndPublicKey = pdndPublicKey;
	}

	public String getThumbprintSha256() {
		return thumbprintSha256;
	}

	public void setThumbprintSha256(String thumbprintSha256) {
		this.thumbprintSha256 = thumbprintSha256;
	}

	public String getThumbprint() {
		return thumbprint;
	}

	public void setThumbprint(String thumbprint) {
		this.thumbprint = thumbprint;
	}

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}

	public String getIssuerDN() {
		return issuerDN;
	}

	public void setIssuerDN(String issuerDN) {
		this.issuerDN = issuerDN;
	}
	
	public String getIssuerName() {
		return issuerName;
	}

	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}
	
	private boolean isValid;
	
	public CertAppMapping()
	{
		
	}
	
	public CertAppMapping(String applicationUUID, String certHash, boolean isValid)
	{
		this.applicationUUID = applicationUUID;
		this.certHash = certHash;
		this.isValid = isValid;
	}
	
	public String getApplicationUUID() {
		return applicationUUID;
	}
	public void setApplicationUUID(String applicationUUID) {
		this.applicationUUID = applicationUUID;
	}
	public String getApplicationName() {
		return applicationName;
	}
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}
	public String getApplicationCreator() {
		return applicationCreator;
	}
	public void setApplicationCreator(String applicationCreator) {
		this.applicationCreator = applicationCreator;
	}
	public String getCertHash() {
		return certHash;
	}
	public void setCertHash(String certHash) {
		this.certHash = certHash;
	}
	public boolean isValid() {
		return isValid;
	}
	public void setValid(boolean isValid) {
		this.isValid = isValid;
	}

	@Override
	public String toString() {
		/*
		 *         return "Application [id=" + id + ", name=" + name + ", subId=" + subId + ", policy=" + policy + ", tokenType="
                + tokenType + ", groupIds=" + groupIds + ", attributes=" + attributes + "]";

		 */
		return "CertAppMapping [" +
				" applicationUUID: " + applicationUUID + "," +
				" applicationName: " + applicationName + "," +
				" applicationCreator: " + applicationCreator + "," +
				" certHash: " + certHash + "," +
				" serialNumber: " + serialNumber + "," +
				" issuerDN: " + issuerDN + "," +
				" issuerName: " + issuerName + "," +
				" alias: " + alias + "," +
				" thumbprint: " + thumbprint + "," +
				" thumbprintSha256: " + thumbprintSha256 + "," +
				" pdndPublicKey: " + pdndPublicKey + "," +
				" pdndPurposeId: " + pdndPurposeId + "," +
				" certificate: " + certificate + "," +
				" subjectKeyIndentifier: " + subjectKeyIndentifier + "]";
	}
}
