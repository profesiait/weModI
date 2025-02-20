package it.profesia.wemodi.handlers.security;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.keymgt.model.exception.DataLoadingException;

import com.nimbusds.jose.JOSEException;

import it.profesia.carbon.apimgt.gateway.handlers.security.JWTValidator;
import it.profesia.wemodi.subscriptions.SubscriptionService;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;

public class IntegrityRest02 extends IntegrityRest01 {
    /**
     * URI per ottenere la chiave pubblica in base al kid
     */
    private String uriApiInteropKeys = "/keys/";
    /**
     * URL delle API di Interoperabilità
     */
    private String urlApiInterop = "";

    public IntegrityRest02() {
    	super();
		log.trace("Pattern di accesso al soggetto fruitre non definito, viene impostato di default ID_AUTH_REST01.");
		this.idAuthRest = new IdAuthRest01();
    }

    public IntegrityRest02 (IdAuthRest idAuthRest) {
    	super();
		if (idAuthRest == null) {
			log.trace("Pattern di accesso al soggetto fruitre non definito, viene impostato di default ID_AUTH_REST01.");
			this.idAuthRest = new IdAuthRest01();
			return;
		}
		this.idAuthRest = idAuthRest;
    }

    @Override
    protected void InitHeaderClaimsMap() {
    	super.InitHeaderClaimsMap();
        headerClaimsMap.remove(IdAuthRest01.CERTIFICATE_REFERENCE);
        headerClaimsMap.put(KID, new ClaimValidator(true, this, "checkCertificateReference"));
    }

    private Boolean checkCertificateReference(String claim, String value) {
        Boolean isValid = false;
        if (KID.equals(claim)) {
            log.info("Validazione del certificato in base al kid PDND: " + value);
            String pdndAccessToken;
            try {
                pdndAccessToken = retrieveAccessTokenPdndApiInterop(value);
                String content = JWTValidator.callExternalUrl(urlApiInterop + uriApiInteropKeys + value, pdndAccessToken);
                //String content = "{\"alg\": \"RS256\", \"e\": \"AQAB\", \"kid\": \"lss6Y7_SyDIkTvSaRtw4M5EJ45aJaey9h0bCI9oHNWI\", \"kty\": \"RSA\", \"n\": \"vGCdUzXM4sh0_x1IalPT_6FsFo7UjGxQPncXSBzT5fMZTMJJ89sE4BJiZq2vsoS4lCJxHsdoOCCJKBJEe_XrYD1WTzaz6aPR4tesQtv41st_FuxJtOoTDcZJ0hENV8bau2dE5C5iHC8aCgw_VkrIMkWFeA6T_y8vduBZ5YTICWqAcnDRxynNWsn71pn1yvTCLf1AJqG_a9sbD_5VkDusdCEgieg7quZAb2h9iinUJtOBCESAomJxgnstZy9fFLx0XbzLdwPrJcn5-euMNYpflBJNpeph0QCMwd3YiJo8FC9j0IBtFWKdd42Pecqh_7WRvyIHkJBO5_JQFdI-EuifkQ\", \"use\": \"sig\"}";
                PublicKey publicKey = JWTValidator.retrievePubKeyFromJWKS(content, "");
                setPublicKey(publicKey);
                isValid = true;
            } catch (DataLoadingException | URISyntaxException | InvalidKeySpecException | NoSuchAlgorithmException | MalformedURLException | JOSEException | APISecurityException e) {
                log.error("Errore durante il recupero dell'Access Token di interop per il recupero del certificato tramite kid.", e);
                return false;
            }
        }
        return isValid;
    }

    private String retrieveAccessTokenPdndApiInterop(String kid) throws DataLoadingException, URISyntaxException, InvalidKeySpecException, NoSuchAlgorithmException, MalformedURLException, JOSEException, APISecurityException {
        log.info("Richiesta del token PDND per invocare API di interoperabilità.");
		String pdndAccessToken = "";

        String applicationUUID = new SubscriptionService().getApplicationUUIDByKid(kid);
        log.debug("Recuperato applicationUUID: " + applicationUUID);
        if (!(applicationUUID.equals(""))) {
            PdndPKMapping pdndPKMapping = new SubscriptionService().getCertificatesOutboundPdnd(applicationUUID);
            pdndAccessToken = JWTValidator.providePdnd(pdndPKMapping);
            log.info("Ottenuto Access Token PDND: " + pdndAccessToken);
        }
		return pdndAccessToken;

	}

    public void setUriApiInteropKeys(String uriApiInteropKeys) {
        this.uriApiInteropKeys = uriApiInteropKeys;
    }

    public void setUrlApiInterop(String urlApiInterop) {
        this.urlApiInterop = urlApiInterop;
    }

}
