package it.profesia.wemodi.handlers.security;

public class PdndAuditRest02Auth extends PdndAuth{
	
	private String jwsDigest = "";
	public static final String DIGEST = "digest";

    public PdndAuditRest02Auth(String jwsDigest) {
        super();
        this.jwsDigest = jwsDigest;
    }

    @Override
    protected void InitHeaderClaimsMap() {
        super.InitHeaderClaimsMap();
    }

    @Override
    protected void InitPayloadClaimsMap() {
        super.InitPayloadClaimsMap();
        payloadClaimsMap.put(DIGEST, new ClaimValidator(true, this, "checkDigest"));
    }
    
    protected Boolean checkDigest(String claimName, net.minidev.json.JSONObject digest)
    {
    	return digest.getAsString("alg").equals("SHA256") && digest.getAsString("value").equals(jwsDigest);
    }
}
