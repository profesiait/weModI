package it.profesia.wemodi.handlers.security;

public abstract class IdAuthRest extends AbstractInnerModiJWTValidator {
	
	private String aud = "";

	public IdAuthRest() {
        super();
    }
	
	public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}

}
