package it.profesia.wemodi.handlers.security;

public class IdAuditRest02 extends IdAuditRest01_Pdnd {
	
	public static final String DNONCE = "dnonce";
	
	public IdAuditRest02() {
        super();
    }

    @Override
    protected void InitHeaderClaimsMap() {
    	super.InitHeaderClaimsMap();
    }

    @Override
    protected void InitPayloadClaimsMap() {
    	 super.InitPayloadClaimsMap();
    	 payloadClaimsMap.put(DNONCE, new ClaimValidator(true, this, "checkDnonce"));
    }

}
