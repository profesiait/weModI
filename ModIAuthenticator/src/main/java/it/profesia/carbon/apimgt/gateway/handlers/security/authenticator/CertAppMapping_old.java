package it.profesia.carbon.apimgt.gateway.handlers.security.authenticator;

public class CertAppMapping_old {
	
	private int applicationId;
	private String applicationUUID;
	private String certHash;
	private String serialNumber;
	private String issuerDN;
	private String alias;
	private String thumbprint;
	
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
	private boolean isValid;
	
	public CertAppMapping_old()
	{
		
	}
	
	public CertAppMapping_old(int applicationId, String applicationUUID, String certHash, boolean isValid)
	{
		this.applicationId = applicationId;
		this.applicationUUID = applicationUUID;
		this.certHash = certHash;
		this.isValid = isValid;
	}
	
	
	public int getApplicationId() {
		return applicationId;
	}
	public void setApplicationId(int applicationId) {
		this.applicationId = applicationId;
	}
	public String getApplicationUUID() {
		return applicationUUID;
	}
	public void setApplicationUUID(String applicationUUID) {
		this.applicationUUID = applicationUUID;
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

}
