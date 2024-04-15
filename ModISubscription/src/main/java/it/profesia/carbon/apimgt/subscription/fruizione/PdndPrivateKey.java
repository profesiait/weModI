package it.profesia.carbon.apimgt.subscription.fruizione;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;

import it.profesia.carbon.apimgt.subscription.dao.PdndPKMapping;

public interface PdndPrivateKey {

	public PdndPKMapping insertPrivateKey(String applicationUuid, String uri, String kid, String alg, String typ, String iss, String sub, String aud, String purposeId, String clientId, String scope, String privkey, Boolean enabled) throws APIManagementException, APIManagerDatabaseException;
    public PdndPKMapping getPrivateKey(String appUUID);
    public PdndPKMapping getPrivateKeyByConsumerKey(String consumerKey);
    public int updatePrivateKey(String applicationUuid) throws APIManagementException, APIManagerDatabaseException;

}
