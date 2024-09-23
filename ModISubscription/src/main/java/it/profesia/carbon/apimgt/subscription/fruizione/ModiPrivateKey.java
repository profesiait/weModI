package it.profesia.carbon.apimgt.subscription.fruizione;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;

import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;

public interface ModiPrivateKey {

	public ModiPKMapping insertPrivateKey(String applicationUuid, String typ, String iss, String sub, String aud, String kid, String privkey, String publickey, String certificate, boolean enabled) throws APIManagementException, APIManagerDatabaseException;
	public ModiPKMapping insertPrivateKeySOAP(String applicationUuid, String wsaddressingTo, String privkey, String certificate, boolean enabled) throws APIManagementException, APIManagerDatabaseException;
	public ModiPKMapping getPrivateKey(String appUUID) throws APIManagementException;
	public ModiPKMapping getPrivateKeyByConsumerKey(String consumerKey) throws APIManagementException;
	public ModiPKMapping getPrivateKeySOAP(String appUUID);
	public ModiPKMapping getPrivateKeyByConsumerKeySOAP(String consumerKey);
	public int updatePrivateKey(String applicationUuid) throws APIManagementException, APIManagerDatabaseException;
	public int updatePrivateKeySOAP(String applicationUuid) throws APIManagementException, APIManagerDatabaseException;
}
