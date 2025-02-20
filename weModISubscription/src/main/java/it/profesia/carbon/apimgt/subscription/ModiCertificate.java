package it.profesia.carbon.apimgt.subscription;

import java.util.List;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;

import it.profesia.wemodi.subscriptions.dao.CertAppMapping;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;

public interface ModiCertificate {

    public List<CertAppMapping> getCertificates(String appUUID);
    public CertAppMapping getCertificate(String appUUID);
    public List<CertAppMapping> getCertificatesSOAP(String appUUID);
    public CertAppMapping getCertificateDetailsSOAP(String appUUID);
    public CertAppMapping getCertificateSOAP(String whereClauseParam1, String whereClauseParam2);
    public String insertCertificateSOAP(String appUUID, String alias, String certificate) throws APIManagementException, APIManagerDatabaseException;
    public String insertCertificateDetailsSOAP(String appUUID, String serialNumber, String issuerDN, String issuerName, String alias, String thumbprint, String thumbprintSha256, String subjectKeyIndentifier, String certificate) throws APIManagementException, APIManagerDatabaseException;
    
    public CertAppMapping getAliasWithThumbprint(String thumbprint);
    public CertAppMapping getAppDetailsFromName(String appName, String createdBy);
    
    public String insertCertificate(String appUUID, String createdBy, String alias
    		, String pdndPublicKey, String pdndClientId, String pdndPurposeId, String privatekey, String pdndKidApiInterop) throws APIManagementException, APIManagerDatabaseException;
    public String insertCertificateDetails(String appUUID, String serialNumber, String issuerDN, String alias, String thumbprint, String thumbprintSha256, String pdndClientId, String pdndKidApiInterop) throws APIManagementException, APIManagerDatabaseException;

    // Metodo di test per il servizio Soap
    public String getString(String value);
    
    public List<String> getAllApplicationsCreators();
    public List<String> getApplicationsCreatedByUser(String user);
    public List<CertAppMapping> getApplicationsFromSameOrg(String username);
    
    public PdndPKMapping getSubscriptionDetails(String subscriptionUUID) throws APIManagementException;
    public String addSubscriptionMapping(String subscriptionUUID, String pdndAud, String pdndIss, String pdndPurposeId) throws APIManagementException, APIManagerDatabaseException;
    public int updateSubscriptionMapping(String subscriptionUUID) throws APIManagementException, APIManagerDatabaseException;
    public int updateCertificate(String applicationUuid) throws APIManagementException, APIManagerDatabaseException;
	public int updateCertificateSOAP(String applicationUuid) throws APIManagementException, APIManagerDatabaseException;
	
	public String getApplicationUUIDByKid(String kidPdndApi);
}
