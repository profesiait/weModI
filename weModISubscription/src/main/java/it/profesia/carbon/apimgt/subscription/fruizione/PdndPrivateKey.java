package it.profesia.carbon.apimgt.subscription.fruizione;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;

import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;

public interface PdndPrivateKey {

    /**
     * @deprecated utilizzare {@link #insertPrivateKey(String, String, String, String, String, String, String, String, String, String, String, String, String, Boolean) per la gestione degli endpoint di SANDBOX o PRODUCTION}
     * 
     * @param applicationUuid
     * @param uri
     * @param kid
     * @param alg
     * @param typ
     * @param iss
     * @param sub
     * @param aud
     * @param purposeId
     * @param clientId
     * @param scope
     * @param privkey
     * @param enabled
     * @return
     * @throws APIManagementException
     * @throws APIManagerDatabaseException
     */
	public default PdndPKMapping insertPrivateKey(String applicationUuid, String uri, String kid, String alg, String typ, String iss, String sub, String aud, String purposeId, String clientId, String scope, String privkey, Boolean enabled) throws APIManagementException, APIManagerDatabaseException {
        return insertPrivateKey(applicationUuid, "PRODUCTION", uri, kid, alg, typ, iss, sub, aud, purposeId, clientId, scope, privkey, enabled);
    }
    /**
     * Inserisce i dati della chiave privata per la JWT Assertion PDND
     * 
     * @param applicationUuid UUID dell'application Oauth WSO2
     * @param keyType PRODUCTION o SANDBOX
     * @param uri
     * @param kid
     * @param alg
     * @param typ
     * @param iss
     * @param sub
     * @param aud
     * @param purposeId
     * @param clientId
     * @param scope
     * @param privkey
     * @param enabled
     * @return Chiave privata weModI
     * @throws APIManagementException
     * @throws APIManagerDatabaseException
     */
    public PdndPKMapping insertPrivateKey(String applicationUuid, String keyType, String uri, String kid, String alg, String typ, String iss, String sub, String aud, String purposeId, String clientId, String scope, String privkey, Boolean enabled) throws APIManagementException, APIManagerDatabaseException;
    /**
     * @deprecated utilizzare {@link #getPrivateKey(String, String)} per gestire i dati di PRODUCTION/SANDBOX
     * @param appUUID
     * @return
     * @throws APIManagementException
     * 
     */
    public default PdndPKMapping getPrivateKey(String appUUID) throws APIManagementException {
        return getPrivateKey(appUUID, "PRODUCTION");
    }
    /**
     * 
     * @param appUUID UUID della Oauth application di autorizzazione
     * @param keyType PRODUCTION o SANDBOX
     * @return Chiave privata weModI
     * @throws APIManagementException
     */
    public PdndPKMapping getPrivateKey(String appUUID, String keyType) throws APIManagementException;
    /**
     * Restituisce la chiave privata per firmare la JWT assertion PDND
     * @param consumerKey Oauth application di autorizzazione
     * @return Chiave privata weModI
     * @throws APIManagementException
     */
    public PdndPKMapping getPrivateKeyByConsumerKey(String consumerKey) throws APIManagementException;
    public int updatePrivateKey(String applicationUuid) throws APIManagementException, APIManagerDatabaseException;

}
