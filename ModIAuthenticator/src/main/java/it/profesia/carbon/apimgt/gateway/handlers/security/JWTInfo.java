package it.profesia.carbon.apimgt.gateway.handlers.security;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class JWTInfo {
	
	private String certificateReference;
	private String sub;
	private RSAPublicKey publicKeyFromJWK;
	private String pdndPublicKey;
	private String certificate;
	private X509Certificate certificateX509;
	private String thumbprint;
	private String pdndClientId;
	private String pdndPurposeId;
	private String pdndKid;
	private String pdndAud;
	private String pdndIss;
	private String jwtType;
	private String digest;
	private boolean kidForModI;
	private boolean isAuditModI;
	
	public boolean isAuditModI() {
		return isAuditModI;
	}
	public void setAuditModI(boolean isAuditModI) {
		this.isAuditModI = isAuditModI;
	}
	
	public boolean isKidForModI() {
		return kidForModI;
	}
	public void setKidForModI(boolean kidForModI) {
		this.kidForModI = kidForModI;
	}
	public String getDigest() {
		return digest;
	}
	public void setDigest(String digest) {
		this.digest = digest;
	}
	public String getJwtType() {
		return jwtType;
	}
	public void setJwtType(String jwtType) {
		this.jwtType = jwtType;
	}
	public String getPdndAud() {
		return pdndAud;
	}
	public void setPdndAud(String pdndAud) {
		this.pdndAud = pdndAud;
	}
	public String getPdndIss() {
		return pdndIss;
	}
	public void setPdndIss(String pdndIss) {
		this.pdndIss = pdndIss;
	}
	public String getPdndKid() {
		return pdndKid;
	}
	public void setPdndKid(String pdndKid) {
		this.pdndKid = pdndKid;
	}
	public String getPdndClientId() {
		return pdndClientId;
	}
	public void setPdndClientId(String pdndClientId) {
		this.pdndClientId = pdndClientId;
	}
	public String getPdndPurposeId() {
		return pdndPurposeId;
	}
	public void setPdndPurposeId(String pdndPurposeId) {
		this.pdndPurposeId = pdndPurposeId;
	}
	public String getThumbprint() {
		return thumbprint;
	}
	public void setThumbprint(String thumbprint) {
		this.thumbprint = thumbprint;
	}
	public X509Certificate getCertificateX509() {
		return certificateX509;
	}
	public void setCertificateX509(X509Certificate certificateX509) {
		this.certificateX509 = certificateX509;
	}
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	public String getCertificateReference() {
		return certificateReference;
	}
	public void setCertificateReference(String certificateReference) {
		this.certificateReference = certificateReference;
	}
	public RSAPublicKey getPublicKeyFromJWK() {
		return publicKeyFromJWK;
	}
	public void setPublicKeyFromJWK(RSAPublicKey publicKeyFromJWK) {
		this.publicKeyFromJWK = publicKeyFromJWK;
	}
	public String getSub() {
		return sub;
	}
	public void setSub(String sub) {
		this.sub = sub;
	}
	public String getPdndPublicKey() {
		return pdndPublicKey;
	}
	public void setPdndPublicKey(String pdndPublicKey) {
		this.pdndPublicKey = pdndPublicKey;
	}

}
