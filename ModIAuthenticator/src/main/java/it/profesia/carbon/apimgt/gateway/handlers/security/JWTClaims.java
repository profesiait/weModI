package it.profesia.carbon.apimgt.gateway.handlers.security;

public class JWTClaims {
	
	private String contentType;
	private String digest;
	private String digestFromHeader;
	private String aud;
	
	public JWTClaims(String contentType, String digest, String aud, String digestFromHeader)
	{
		this.contentType = contentType;
		this.digest = digest;
		this.aud = aud;
		this.digestFromHeader = digestFromHeader;
	}
	
	public String getDigestFromHeader() {
		return digestFromHeader;
	}

	public void setDigestFromHeader(String digestFromHeader) {
		this.digestFromHeader = digestFromHeader;
	}
	
	public String getContentType() {
		return contentType;
	}
	public void setContentType(String contentType) {
		this.contentType = contentType;
	}
	public String getDigest() {
		return digest;
	}
	public void setDigest(String digest) {
		this.digest = digest;
	}
	public String getAud() {
		return aud;
	}
	public void setAud(String aud) {
		this.aud = aud;
	}
	

}
