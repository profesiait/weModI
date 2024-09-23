package it.profesia.wemodi.subscriptions.dao;

public class ModiPKMapping {

	private Boolean enabled;
	private String kid;
	private String alg;
	private String typ;
	private String sub;
	private String aud;
	private String iss;
	private String privkey;
	private String publickey;
	private String certificate;
	private String wsaddressingTo;
	private String applicationUUID;
	
	public String getApplicationUUID() {
		return applicationUUID;
	}
	public void setApplicationUUID(String applicationUUID) {
		this.applicationUUID = applicationUUID;
	}

	public String getWsaddressingTo() {
		return wsaddressingTo;
	}
	public void setWsaddressingTo(String wsaddressingTo) {
		this.wsaddressingTo = wsaddressingTo;
	}
	public Boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
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
	public String getIss() {
		return iss;
	}
	public void setIss(String iss) {
		this.iss = iss;
	}
	public String getPrivkey() {
		return privkey;
	}
	public void setPrivkey(String privkey) {
		this.privkey = privkey;
	}
	public String getPublickey() {
		return publickey;
	}
	public void setPublickey(String publickey) {
		this.publickey = publickey;
	}
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
}
