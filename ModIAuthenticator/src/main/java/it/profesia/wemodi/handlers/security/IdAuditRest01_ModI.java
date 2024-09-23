package it.profesia.wemodi.handlers.security;

public class IdAuditRest01_ModI extends IdAuditRest01 {
	
	
	public static final String CERTIFICATE_REFERENCE = "x5c|x5t|x5t#S256|x5u";

    public IdAuditRest01_ModI() {
        super();
    }

    @Override
    protected void InitHeaderClaimsMap() {
    	super.InitHeaderClaimsMap();
        headerClaimsMap.put(CERTIFICATE_REFERENCE, new ClaimValidator(true, this, "checkCertificate"));
    }

    @Override
    protected void InitPayloadClaimsMap() {
    	super.InitPayloadClaimsMap();
    }

}
