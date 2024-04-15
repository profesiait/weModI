package it.profesia.wemodi;

public class ApiConfig {

	public static final String PDND_AUTH = "PDND_AUTH";
	public static final String ID_AUTH_CHANNEL_01 = "ID_AUTH_CHANNEL_01";
	public static final String ID_AUTH_CHANNEL_02 = "ID_AUTH_CHANNEL_02";
	public static final String ID_AUTH_REST_01 = "ID_AUTH_REST_01";
	public static final String ID_AUTH_REST_02 = "ID_AUTH_REST_02";
	public static final String INTEGRITY_REST_01 = "INTEGRITY_REST_01";
    public static final String INTEGRITY_REST_02 = "INTEGRITY_REST_02";
    public static final String AUDIT_REST_01 = "AUDIT_REST_01";
    public static final String AUDIT_REST_02 = "AUDIT_REST_02";
	public static final String MODI_TOKEN_NAME = "MODI_TOKEN_NAME";

	private boolean pdndAuth = false;
    private boolean idAuthChannel01 = false;
    private boolean idAuthChannel02 = false;
	private boolean idAuthRest01 = false;
	private boolean idAuthRest02 = false;
	private boolean integrityRest01 = false;
	private boolean integrityRest02 = false;
	private boolean auditRest01 = false;
	private boolean auditRest02 = false;
	private String modiTokenName = "Agid-JWT-Signature";

	public boolean isPdndAuth() {
		return pdndAuth;
	}

	public void setPdndAuth(boolean pdndAuth) {
		this.pdndAuth = pdndAuth;
	}

	public boolean isIdAuthChannel01() {
		return idAuthChannel01;
	}

	public void setIdAuthChannel01(boolean idAuthChannel01) {
		this.idAuthChannel01 = idAuthChannel01;
	}

	public boolean isIdAuthChannel02() {
		return idAuthChannel02;
	}

	public void setIdAuthChannel02(boolean idAuthChannel02) {
		this.idAuthChannel02 = idAuthChannel02;
	}

	public Boolean isIdAuthRest01() {
		return idAuthRest01;
	}

	public void setIdAuthRest01(Boolean idAuthRest01) {
		this.idAuthRest01 = idAuthRest01;
	}

	public Boolean isIdAuthRest02() {
		return idAuthRest02;
	}

	public void setIdAuthRest02(Boolean idAuthRest02) {
		this.idAuthRest02 = idAuthRest02;
	}

	public Boolean isIntegrityRest01() {
		return integrityRest01;
	}

	public void setIntegrityRest01(Boolean integrityRest01) {
		this.integrityRest01 = integrityRest01;
	}

	public Boolean isIntegrityRest02() {
		return integrityRest02;
	}

	public void setIntegrityRest02(Boolean integrityRest02) {
		this.integrityRest02 = integrityRest02;
	}

	public boolean isAuditRest01() {
		return auditRest01;
	}

	public void setAuditRest01(boolean auditRest01) {
		this.auditRest01 = auditRest01;
	}

	public boolean isAuditRest02() {
		return auditRest02;
	}

	public void setAuditRest02(boolean auditRest02) {
		this.auditRest02 = auditRest02;
	}

	public String getModiTokenName() {
		return modiTokenName;
	}

	public void setModiTokenName(String modiTokenName) {
		this.modiTokenName = modiTokenName;
	}

	public String getPatterns() {
		String patterns = "";

		patterns = patterns.concat(pdndAuth ? ((patterns.length() > 0 ? "," : "") + PDND_AUTH) : "");
		patterns = patterns.concat(idAuthChannel01 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_CHANNEL_01) : "");
		patterns = patterns.concat(idAuthChannel02 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_CHANNEL_02) : "");
		patterns = patterns.concat(idAuthRest01 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_REST_01) : "");
		patterns = patterns.concat(idAuthRest02 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_REST_02) : "");
		patterns = patterns.concat(integrityRest01 ? ((patterns.length() > 0 ? "," : "") + INTEGRITY_REST_01) : "");
		patterns = patterns.concat(auditRest01 ? ((patterns.length() > 0 ? "," : "") + AUDIT_REST_02) : "");
		patterns = patterns.concat(auditRest02 ? ((patterns.length() > 0 ? "," : "") + AUDIT_REST_02) : "");

		return patterns;
	}
}
