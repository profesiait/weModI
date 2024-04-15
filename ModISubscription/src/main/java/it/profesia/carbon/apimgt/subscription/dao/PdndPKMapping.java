package it.profesia.carbon.apimgt.subscription.dao;

public class PdndPKMapping {
	private Boolean enabled;
	private String uri;
	private String kid;
	private String alg;
	private String typ;
	private String iss;
	private String sub;
	private String aud;
	private String purposeId;
	private String privkey;
	private String clientId;
	private String scope;
	private String applicationUUID;
	
	public String getApplicationUUID() {
		return applicationUUID;
	}
	public void setApplicationUUID(String applicationUUID) {
		this.applicationUUID = applicationUUID;
	}
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public Boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}
	public String getUri() {
		return uri;
	}
	public void setUri(String uri) {
		this.uri = uri;
	}
	public String getKid() {
		return kid;
	}
	public void setKid(String kid) {
		this.kid = kid;
	}
	public String getAlg() {
		return alg;
	}
	public void setAlg(String alg) {
		this.alg = alg;
	}
	public String getTyp() {
		return typ;
	}
	public void setTyp(String typ) {
		this.typ = typ;
	}
	public String getIss() {
		return iss;
	}
	public void setIss(String iss) {
		this.iss = iss;
	}
	public String getSub() {
		return sub;
	}
	public void setSub(String sub) {
		this.sub = sub;
	}
	public String getAud() {
		return aud;
	}
	public void setAud(String aud) {
		this.aud = aud;
	}
	public String getPurposeId() {
		return purposeId;
	}
	public void setPurposeId(String purposeId) {
		this.purposeId = purposeId;
	}
	public String getPrivkey() {
		return privkey;
	}
	public void setPrivkey(String privkey) {
		this.privkey = privkey;
	}

}
