package it.profesia.wemodi.handlers.security;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.time.Instant;

import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.keymgt.model.exception.DataLoadingException;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.util.DateUtils;

import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.CertAppMapping;
import net.minidev.json.JSONObject;

public abstract class AbstractInnerModiJWTValidator implements InnerModiJWTValidator {
    protected static final Log log = LogFactory.getLog(InnerModiJWTValidator.class);

    private Certificate certificate = null;
    private PublicKey publicKey = null;
    private Long exp = null;
    private Long iat = null;
    private Long nbf = null;
    protected final long timestampSkew = 60;
    protected Map<String, ClaimValidator> headerClaimsMap = null;
    protected Map<String, ClaimValidator> payloadClaimsMap = null;

    protected class ClaimValidator {
        private InnerModiJWTValidator validatorObject = null;
        private Boolean mandatory = false;
        private String checkMetod = null;

        private ClaimValidator() {
            throw new UnsupportedOperationException("Invocare il costruttore ClaimValidator(Boolean, InnerModiJWTValidator, Method)");
        }

        protected ClaimValidator(Boolean mandatory, InnerModiJWTValidator validatorObject, String checkMethod) {
            this.mandatory = mandatory;
            this.validatorObject = validatorObject;
            this.checkMetod = checkMethod;
        }
			
        public Boolean isMandatory() {
            return mandatory;
        }

        public void setMandatory(Boolean mandatory) {
            this.mandatory = mandatory;
        }

        public String getCheckMetod() {
            return checkMetod;
        }

        public void setCheckMetod(String checkMetod) {
            this.checkMetod = checkMetod;
        }

        public InnerModiJWTValidator getValidatorObject() {
            return validatorObject;
        }

        @Override
        public String toString() {
            String s = "ClaimValidator [mandatory=" + (mandatory != null ? mandatory : "null");
            s += ", checkMethods=" + (checkMetod != null ? checkMetod : "null") + "]";
            return s;
        }


    }

    public Map<String, ClaimValidator> getHeaderClaimsMap() {
        return headerClaimsMap;
    }

    public Map<String, ClaimValidator> getPayloadClaimsMap() {
        return payloadClaimsMap;
    }


    public AbstractInnerModiJWTValidator() {
        InitHeaderClaimsMap();
        InitPayloadClaimsMap();
    }

    protected abstract void InitHeaderClaimsMap();

    protected abstract void InitPayloadClaimsMap();

    @Override
    public Boolean validateHeader(JWSHeader jwtHeader) {
        Pair<String, Boolean> validate = checkClaims(headerClaimsMap, jwtHeader.toJSONObject());
        if (!validate.getValue()) {
            log.error("Validazione JWT Header fallita: " + validate.getKey());
            return false;
        }

        return true;
    }

    @Override
    public Boolean validatePayload(Payload payload) {
        Pair<String, Boolean> validate = checkClaims(payloadClaimsMap, payload.toJSONObject());
        if (!validate.getValue() || !validateTimestamps()) {
            log.error("Validazione JWT Payload fallita: " + validate.getKey());
            return false;
        }

        return true;
    }

    // Dalla versione 4.3 il metodo Payload.toJSONObject() restituisce un oggetto Map, nelle precedenti un oggetto JSONObject
    /*protected Pair<String, Boolean> checkClaims(Map<String, ClaimValidator> map, JSONObject jwtClaims) {
        Map<String, Object> jwtClaimsMap = null;
        jwtClaims.putAll(jwtClaimsMap);
        return checkClaims(map, jwtClaimsMap);
    }*/

    protected Pair<String, Boolean> checkClaims(Map<String, ClaimValidator> map, Map<String,Object> jwtClaims) {
        for (Map.Entry<String, ClaimValidator> entry : map.entrySet()) {
            ClaimValidator validator = entry.getValue();
            Boolean isFound = !validator.isMandatory();
            String keys = entry.getKey();
            Object value = null;

            for (String key : keys.split("\\|")) {
                log.debug("Validazione del claim " + key + " " + validator);

                value = jwtClaims.get(key);

                if (value != null)
                    isFound = StringUtils.isNotBlank(value.toString());
                if (isFound) {
                    log.trace(String.format("Trovato il claim \"%s\": %s", key, value));

                    if (validator.getCheckMetod() != null) {
                        Boolean check = false;

                        try {
                            log.trace(String.format("Ricerca del metodo di validazione: %s(java.lang.String, %s)", validator.getCheckMetod(), value.getClass().getName()));

                            Method method = findTheCheckMethod(validator.getValidatorObject(), validator.getCheckMetod(), key, value);
                            if (method != null) {
                                boolean accessible = method.isAccessible();
                                method.setAccessible(true);
                                check = (Boolean) method.invoke(validator.getValidatorObject(), key, value);
                                method.setAccessible(accessible);
                            } else {
                                log.error("Nessun metodo di validazione dichiarato per il claim: " + keys);
                            }
                        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | SecurityException e) {
                            log.error("Errore in fase di validazione del claim " + entry.getKey(), e);
                        }
                        if (!check) {
                            return Pair.of(entry.getKey() + " dato non valido: " + value + ".", false);
                        }
                    }
                    break;
                }
            }
            if (!isFound) {
                return Pair.of(keys + " dato obbligatorio non presente.", false);
            }
        }

        return Pair.of("Validazione claims.", true);
    }

    private Method findTheCheckMethod(InnerModiJWTValidator validatorObject, String methodName, String claim, Object value) {
        Method method = null;
        Class clazz = null;
        String className = "";
        
        try {
            clazz = validatorObject.getClass();
            className = clazz.getTypeName();
            while (clazz != null && InnerModiJWTValidator.class.isAssignableFrom(Class.forName(className))) {
                Method[] methods = clazz.getDeclaredMethods();
                for (Method loopMethod : methods) {
                	//log.info("className: " + className + " methodName: " + methodName + " loopMethodName:" + loopMethod.getName());
                    if (methodName.equals(loopMethod.getName()) && loopMethod.getParameterCount() == 2) {
                        Type parameter = null;
                        parameter = loopMethod.getGenericParameterTypes()[0];
                        className = parameter.getTypeName();
                        if (Class.forName(className).isAssignableFrom(String.class)) {
                            parameter = loopMethod.getGenericParameterTypes()[1];
                            className = parameter.getTypeName();
                            if (Class.forName(className).isAssignableFrom(value.getClass())) {
                                method = loopMethod;
                                log.trace(String.format("La classe %s implementa il metodo %s(java.lang.String, %s)", clazz.getName(), method.getName(), parameter.getTypeName()));
                                break;
                            }
                        }
                    }
                }
                if (method == null) {
                    log.trace(String.format("La classe %s non implementa il metodo %s(java.lang.String, %s)", clazz.getName(), methodName, value.getClass().getName()));
                    clazz = clazz.getSuperclass();
                } else {
                    break;
                }
            }
        } catch (ClassNotFoundException e) {
            log.trace("Classe non trovata: " + className, e);
        }

        return method;
    }

    protected Boolean checkCertificate(String claimName, List certificateReferenceArray) {
        for (Object certificateReference : certificateReferenceArray) {
            if (checkCertificate(claimName, certificateReference.toString()))
                return true;
        }
        return false;
    }

    protected Boolean checkCertificate(String claimName, JSONArray certificateReferenceArray) {
        return checkCertificate(claimName, certificateReferenceArray.optString(0));
    }

    protected Boolean checkCertificate(String claimName, String certificateReference) {
        Boolean check = false;

        try {
            log.info("Tentativo di generazione del certificato x509: " + certificateReference);
            javax.security.cert.X509Certificate x509certificate = retrieveCertificateFromContent(certificateReference);

            setCertificate(x509certificate);
            log.info("Public Key del certificato: " + Base64.getEncoder().encodeToString(getPublicKey().getEncoded()));
            return true;
        } catch (APIManagementException | CertificateException | java.security.cert.CertificateException e) {
            log.warn("Certificato non valido.", e);
        }

        try {
            log.info("Tentativo di generazione del certificato thumbrint: " + certificateReference);
            CertAppMapping cam = new SubscriptionService().getAliasWithThumbprint(certificateReference);
            String alias = cam.getAlias();
            
            Certificate certificate = getCertificateFromAlias(alias);
            setCertificate(certificate);
            log.info("Public Key del certificato: " + Base64.getEncoder().encodeToString(getPublicKey().getEncoded()));
            return true;
        } catch (DataLoadingException | URISyntaxException e) {
            log.warn("Thumbprint non valido.", e);
        }

        return check;
    }

    private Certificate getCertificateFromAlias(String alias)
    {
        log.trace("Recupero del certificato dal TrustStore in base all'alias.");
    	Certificate cert = null;
        try {
            KeyStore trustStore = ServiceReferenceHolder.getInstance().getTrustStore();
            log.info("TrustStore type: " + trustStore.getType());
            if (trustStore != null) {
                // Read certificate from trust store
                cert = trustStore.getCertificate(alias);
                log.debug(String.format("Certificato recuperato in base all'alias %s: %s", alias, (cert != null ? cert : "null")));
            }
        } catch (KeyStoreException e) {
            String msg = "Errore durante il recupero del certificato in base all'alias " + alias;
            log.error(msg, e);
        }
        return cert;
    }

    private javax.security.cert.X509Certificate retrieveCertificateFromContent(String base64EncodedCertificate) throws APIManagementException, CertificateException {
        byte[] bytes = org.apache.commons.codec.binary.Base64.decodeBase64(base64EncodedCertificate.getBytes(StandardCharsets.UTF_8));
        InputStream inputStream = new ByteArrayInputStream(bytes);
        return javax.security.cert.X509Certificate.getInstance(inputStream);
    }

    private Boolean checkTyp(String claimName, String typ) {
        return typ.equals("JWT");
    }

    private Boolean checkAlg(String claimName, String alg) {
        return Arrays.asList(new String[]{JWSAlgorithm.RS256.toString(), JWSAlgorithm.RS512.toString(), JWSAlgorithm.RS384.toString(), JWSAlgorithm.PS256.toString()}).contains(alg);
    }

    private JSONArray getIfJSONArrayExist(JSONObject jsonObject, String field) {
        JSONArray jsonArray = null;
        log.trace(String.format("Ricerca del claim [%s] in [%s]", field, jsonObject));
        if(jsonObject.containsKey(field) && jsonObject.get(field) instanceof JSONArray) {
            jsonArray = (JSONArray) jsonObject.get(field);
            log.trace(String.format("Trovato claim [%s] in [%s]: %s", field, jsonObject, jsonArray));
        }
        return jsonArray;
    }
	
    private String getIfStringExist(JSONObject jsonObject, String field) {
        String string = "";
        log.trace(String.format("Ricerca del claim [%s] in [%s]", field, jsonObject));
        if(jsonObject != null && jsonObject.containsKey(field)) {
            string = jsonObject.getAsString(field);
            log.trace(String.format("Trovato claim [%s] in [%s]: %s", field, jsonObject, string));
        }
        return string;
    }
    
    private boolean validateTimestamps()
    {
    	if (iat != null && nbf != null && !checkDateValidity(iat, nbf))
    	{
    		log.debug("nbf o iat non validi");
    		return false;
    	}
    	return true;
    }
    
    private boolean checkDateValidity(long firstDateTime, long secondDateTime) {

		Date first = DateUtils.fromSecondsSinceEpoch(firstDateTime);
		Date second = DateUtils.fromSecondsSinceEpoch(secondDateTime);
		return DateUtils.isAfter(first, second, timestampSkew);
		}

    @Override
    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
        setPublicKey(this.certificate.getPublicKey());
    }

    public void setCertificate(javax.security.cert.Certificate certificate) throws java.security.cert.CertificateException, CertificateEncodingException {
        byte[] encoded = certificate.getEncoded();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encoded);
        java.security.cert.CertificateFactory certificateFactory = java.security.cert.CertificateFactory.getInstance("X.509");
        this.certificate = certificateFactory.generateCertificate(byteArrayInputStream);
        setPublicKey(this.certificate.getPublicKey());
    }

    @Override
    public Certificate getCertificate() {
        return this.certificate;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        if (certificate != null) {
            byte[] certEncoded = "".getBytes();
            try {
                certEncoded = certificate.getEncoded();
                certificate.verify(publicKey);
            } catch (InvalidKeyException e) {
                log.warn(String.format("Viene impostata la chiave pubblica [%s] non corenete con il certificato [%s].", Base64.getEncoder().encodeToString(publicKey.getEncoded()), Base64.getEncoder().encodeToString(certEncoded)));
            } catch (java.security.cert.CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                log.warn("Impossibile verificare il certificato in base alla chiave pubblica: " + e.getLocalizedMessage());
            }
        }
        this.publicKey = publicKey;
    }
    
    @Override
	public void setExp(Long exp) {
		this.exp = exp;
		
	}

	@Override
	public Long getExp() {
		return exp;
	}
	
	@Override
	public void setIat(Long iat) {
		this.iat = iat;
		
	}

	@Override
	public Long getIat() {
		return iat;
	}
	
	@Override
	public void setNbf(Long nbf) {
		this.nbf = nbf;
		
	}

	@Override
	public Long getNbf() {
		return nbf;
	}

}