package it.profesia.wemodi.handlers.security;

public class IdAuditRest01_Pdnd extends IdAuditRest01 {
	
	public static final String KID = "kid";
	public static final String PURPOSEID = "purposeId";

    public IdAuditRest01_Pdnd() {
        super();
    }

    @Override
    protected void InitHeaderClaimsMap() {
    	
    	super.InitHeaderClaimsMap();
        headerClaimsMap.put(KID, new ClaimValidator(true, this, "checkCertificateReference"));
    }

    @Override
    protected void InitPayloadClaimsMap() {
    	 super.InitPayloadClaimsMap();
    	 payloadClaimsMap.put(PURPOSEID, new ClaimValidator(true, this, "checkPurposeId"));
    }
    
    

}
