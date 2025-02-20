package it.profesia.wemodi;

import java.util.Iterator;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

public class ApiConfig {
	private static final Log log = LogFactory.getLog(ApiConfig.class);

	public static final String PDND_AUTH = "PDND_AUTH";
	public static final String ID_AUTH_CHANNEL_01 = "ID_AUTH_CHANNEL_01";
	public static final String ID_AUTH_CHANNEL_02 = "ID_AUTH_CHANNEL_02";
    public static final String ID_AUTH_SOAP_01 = "ID_AUTH_SOAP_01";
    public static final String ID_AUTH_SOAP_02 = "ID_AUTH_SOAP_02";
	public static final String ID_AUTH_REST_01 = "ID_AUTH_REST_01";
	public static final String ID_AUTH_REST_02 = "ID_AUTH_REST_02";
	public static final String INTEGRITY_SOAP_01 = "INTEGRITY_SOAP_01";
	public static final String INTEGRITY_REST_01 = "INTEGRITY_REST_01";
    public static final String INTEGRITY_REST_02 = "INTEGRITY_REST_02";
    public static final String AUDIT_REST_01 = "AUDIT_REST_01";
    public static final String AUDIT_REST_01_MODI = "AUDIT_REST_01_MODI";
    public static final String AUDIT_REST_01_PDND = "AUDIT_REST_01_PDND";
    public static final String AUDIT_REST_02 = "AUDIT_REST_02";
	public static final String MODI_TOKEN_NAME = "JWT_HEADER_NAME";
	public static final String TRACKING_EVIDENCE_TOKEN_NAME = "TRACKING_EVIDENCE_TOKEN_NAME";
	public static final String AUD = "AUD";
	public static final String URL_API_INTEROP = "PDND_API_URL";
	public static final String URL_PDND_JWKS = "PDND_JWKS_URL";
	public static final String CERTIFICATE_REFERENCE = "REFERENCE_CERTIFICATE_TYPE";
    public static final String KEY_IDENTIFIER_TYPE = "KEY_IDENTIFIER_TYPE";

    private boolean pdndAuth = false;
    private boolean idAuthChannel01 = false;
    private boolean idAuthChannel02 = false;
    private boolean idAuthSoap01 = false;
    private boolean idAuthSoap02 = false;
    private boolean idAuthRest01 = false;
    private boolean idAuthRest02 = false;
    private boolean integritySoap01 = false;
    private boolean integrityRest01 = false;
    private boolean integrityRest02 = false;
    private boolean auditRest01Modi = false;
    private boolean auditRest01Pdnd = false;
    private boolean auditRest02 = false;
    private String modiTokenName = "Agid-JWT-Signature";
    private String trackingEvidenceTokenName = "Agid-JWT-TrackingEvidence";
    private boolean jwsAudit = false;
    private String urlApiInterop = "";
    private String urlPdndJwks = "";
    private String certificateReference = "";
    private String keyIdentifierType = "";

    private String aud = "";

    public ApiConfig() {

    }

     /**
      * Costruisce l'oggetto {@link it.profesia.wemodi.ApiConfig ApiConfig} in base ai pattern ModI/PDND forniti in formato JSON
      * @param properties Struttura {@link org.json.JSONObject JSONObject} dei pattern ModI/PDND
      */
    public ApiConfig(JSONObject properties) {
        fromJSONObject(properties);
    }

    /**
     * Costruisce l'oggetto {@link it.profesia.wemodi.ApiConfig ApiConfig} in base ai pattern ModI/PDND forniti in formato <a href="https://apim.docs.wso2.com/en/latest/design/endpoints/endpoint-security/oauth-2.0/">Endpoint Security</a>
     * 
     * @param customParameters Struttura dei parametri ModI/PDND
     */
    public ApiConfig(String customParameters) {
    	fromEndpointSecurityParams(customParameters);
    }

	private ApiConfig fromJSONObject(JSONObject properties) {
        Iterator propertiesIterator = properties.keys();
        log.debug("Configurazione ApiConfig: " + properties);
        while (propertiesIterator.hasNext()) {
            String propertyName = (String) propertiesIterator.next();
            JSONObject property = properties.getJSONObject(propertyName);
            
            String name = property.getString("name").trim().toUpperCase();
            String value = property.getString("value");
            log.trace(String.format("Recuperata property dell'API %s: %s", name, value));
            setPatterns(name, value);
        }
        log.debug("Pattern API weModI: " + getPatterns());
        return this;
	}

	private ApiConfig fromEndpointSecurityParams(String customParameters) {
		JSONObject properties = new JSONObject(customParameters);
		Iterator propertiesIterator = properties.keys();
        log.debug("Configurazione ApiConfig: " + properties);
        while (propertiesIterator.hasNext()) {
            String propertyName = (String) propertiesIterator.next();
            String propertyValue = properties.getString(propertyName);
            propertyName = propertyName.trim().toUpperCase();
            log.trace(String.format("Recuperata property dell'API %s: %s", propertyName, propertyValue));
            setPatterns(propertyName, propertyValue);
        }
        log.debug("Pattern API weModI: " + getPatterns());
        return this;
	}
	
	private void setPatterns(String name, String value) {
		switch (name) {
            case ID_AUTH_CHANNEL_01:
                setIdAuthChannel01(BooleanUtils.toBooleanObject(value));
                break;
            case ID_AUTH_CHANNEL_02:
                setIdAuthChannel02(BooleanUtils.toBooleanObject(value));
                break;
            case ID_AUTH_SOAP_01:
                setIdAuthSoap01(BooleanUtils.toBooleanObject(value));
                break;
            case ID_AUTH_SOAP_02:
                setIdAuthSoap02(BooleanUtils.toBooleanObject(value));
                break;
            case ID_AUTH_REST_01:
                setIdAuthRest01(BooleanUtils.toBooleanObject(value));
                break;
            case ID_AUTH_REST_02:
                setIdAuthRest02(BooleanUtils.toBooleanObject(value));
                break;
            case INTEGRITY_SOAP_01:
                setIntegritySoap01(BooleanUtils.toBooleanObject(value));
                break;
            case INTEGRITY_REST_01:
                setIntegrityRest01(BooleanUtils.toBooleanObject(value));
                break;
            case INTEGRITY_REST_02:
                setIntegrityRest02(BooleanUtils.toBooleanObject(value));
                break;
            case AUDIT_REST_01_MODI:
                setAuditRest01Modi(BooleanUtils.toBooleanObject(value));
                break;
            case AUDIT_REST_01_PDND:
                setAuditRest01Pdnd(BooleanUtils.toBooleanObject(value));
                break;
            case AUDIT_REST_02:
                setAuditRest02(BooleanUtils.toBooleanObject(value));
                break;
            case PDND_AUTH:
                setPdndAuth(BooleanUtils.toBooleanObject(value));
                break;
            case MODI_TOKEN_NAME:
                setModiTokenName(value);
                break;
            case TRACKING_EVIDENCE_TOKEN_NAME:
                setTrackingEvidenceTokenName(value);
                break;
            case AUD:
                setAud(value);
                break;
            case URL_API_INTEROP:
                setUrlApiInterop(value);
                break;
            case URL_PDND_JWKS:
                setUrlPdndJwks(value);
                break;
            case CERTIFICATE_REFERENCE:
                setCertificateReference(value);
                break;
            case KEY_IDENTIFIER_TYPE:
                setKeyIdentifierType(value);
                break;
        }
	}

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

	public boolean isIdAuthSoap01() {
        return idAuthSoap01;
    }

    public void setIdAuthSoap01(boolean idAuthSoap01) {
        this.idAuthSoap01 = idAuthSoap01;
    }

    public boolean isIdAuthSoap02() {
        return idAuthSoap02;
    }

    public void setIdAuthSoap02(boolean idAuthSoap02) {
        this.idAuthSoap02 = idAuthSoap02;
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

	public boolean isIntegritySoap01() {
        return integritySoap01;
    }

    public void setIntegritySoap01(boolean integritySoap01) {
        this.integritySoap01 = integritySoap01;
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
	
	public boolean isAuditRest01Modi() {
		return auditRest01Modi;
	}

	public void setAuditRest01Modi(boolean auditRest01Modi) {
        this.auditRest01Modi = auditRest01Modi;
        setJwsAudit(auditRest01Modi == true || auditRest01Pdnd == true || auditRest02 == true);
	}

	public boolean isAuditRest01Pdnd() {
		return auditRest01Pdnd;
	}

	public void setAuditRest01Pdnd(boolean auditRest01Pdnd) {
		this.auditRest01Pdnd = auditRest01Pdnd;
        setJwsAudit(auditRest01Modi == true || auditRest01Pdnd == true || auditRest02 == true);
	}

	public boolean isAuditRest02() {
		return auditRest02;
	}

	public void setAuditRest02(boolean auditRest02) {
		this.auditRest02 = auditRest02;
        setJwsAudit(auditRest01Modi == true || auditRest01Pdnd == true || auditRest02 == true);
	}

	public String getModiTokenName() {
		return modiTokenName;
	}

	public void setModiTokenName(String modiTokenName) {
		this.modiTokenName = modiTokenName;
	}

	public String getTrackingEvidenceTokenName() {
		return trackingEvidenceTokenName;
	}

	public void setTrackingEvidenceTokenName(String trackingEvidenceTokenName) {
		this.trackingEvidenceTokenName = trackingEvidenceTokenName;
	}

	public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}

	public boolean isJwsAudit() {
        return jwsAudit;
    }

    public void setJwsAudit(boolean jwsAudit) {
        this.jwsAudit = jwsAudit;
    }

    public String getUrlApiInterop() {
		return urlApiInterop;
	}

	public void setUrlApiInterop(String urlApiInterop) {
		this.urlApiInterop = urlApiInterop;
	}
	
	public String getUrlPdndJwks() {
		return urlPdndJwks;
	}

	public void setUrlPdndJwks(String urlPdndJwks) {
		this.urlPdndJwks = urlPdndJwks;
	}
	
	public String getCertificateReference() {
		return certificateReference;
	}

	public void setCertificateReference(String certificateReference) {
		this.certificateReference = certificateReference;
	}

	public String getKeyIdentifierType() {
        return keyIdentifierType;
    }

    public void setKeyIdentifierType(String keyIdentifierType) {
        this.keyIdentifierType = keyIdentifierType;
    }

    /**
	 * Lista dei pattern ModI/PDND richiesti per l'API
	 * 
	 * @return Pattern in formato CSV
	 */
	public String getPatterns() {
		String patterns = "";

		patterns = patterns.concat(idAuthChannel01 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_CHANNEL_01) : "");
		patterns = patterns.concat(idAuthChannel02 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_CHANNEL_02) : "");
		patterns = patterns.concat(idAuthRest01 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_REST_01) : "");
		patterns = patterns.concat(idAuthRest02 ? ((patterns.length() > 0 ? "," : "") + ID_AUTH_REST_02) : "");
		patterns = patterns.concat(integrityRest01 ? ((patterns.length() > 0 ? "," : "") + INTEGRITY_REST_01) : "");
		patterns = patterns.concat(integrityRest02 ? ((patterns.length() > 0 ? "," : "") + INTEGRITY_REST_02) : "");
		patterns = patterns.concat(auditRest01Modi || auditRest01Pdnd ? ((patterns.length() > 0 ? "," : "") + AUDIT_REST_01) : "");
		patterns = patterns.concat(auditRest02 ? ((patterns.length() > 0 ? "," : "") + AUDIT_REST_02) : "");

		return patterns;
	}

    @Override
    public String toString() {
        return "ApiConfig [" +
                "pdndAuth=" + pdndAuth + "," +
                " idAuthChannel01=" + idAuthChannel01 + "," +
                " idAuthChannel02=" + idAuthChannel02 + "," +
                " idAuthSoap01=" + idAuthSoap01 + "," +
                " idAuthSoap02=" + idAuthSoap02 + "," +
                " idAuthRest01=" + idAuthRest01 + "," +
                " idAuthRest02=" + idAuthRest02 + "," +
                " integrityRest01=" + integrityRest01 + "," +
                " integrityRest02=" + integrityRest02 + "," +
                " auditRest01Modi=" + auditRest01Modi + "," +
                " auditRest01Pdnd=" + auditRest01Pdnd + "," +
                " auditRest02=" + auditRest02 + "," +
                " modiTokenName=" + modiTokenName + "," +
                " trackingEvidenceTokenName=" + trackingEvidenceTokenName + "," +
                " jwsAudit=" + jwsAudit + "," +
                " urlApiInterop=" + urlApiInterop + "," +
                " urlPdndJwks=" + urlPdndJwks + "," +
                " certificateReference=" + certificateReference + "," +
                " aud=" + aud + "," +
                " keyIdentifierType=" + keyIdentifierType +
                "]";
    }
}
