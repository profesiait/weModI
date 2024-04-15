package it.profesia.carbon.apimgt.subscription.fruizione;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;

import it.profesia.carbon.apimgt.subscription.ModiDBUtil;
import it.profesia.carbon.apimgt.subscription.dao.ModiPKMapping;

public class ModiPrivateKeyImpl implements ModiPrivateKey {
	private static final Log log = LogFactory.getLog(ModiPrivateKeyImpl.class);

	@Override
	public ModiPKMapping insertPrivateKey(String applicationUuid, String typ, String iss, String sub, String aud, String kid, String privkey, String publickey, String certificate, boolean enabled) throws APIManagementException, APIManagerDatabaseException{
		ModiPKMapping modiPK = new ModiPKMapping();
		try {
			ModiDBUtil.initialize();

			String INSERT_MODI_FRUIZIONE_SUB_SQL = "INSERT INTO MODI_FRUIZIONE_SUBSCRIPTION (APPLICATION_UUID,TYP,ISS,SUB,AUD,KID,"
					+ "PRIVATE_KEY_PEM,PUBLIC_KEY_PEM,CERTIFICATE_PEM,ENABLED)"
					+ " VALUES (?,?,?,?,?,?,?,?,?,?)";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(INSERT_MODI_FRUIZIONE_SUB_SQL)) {
				ps.setString(1, StringUtils.defaultIfBlank(applicationUuid, null));
				ps.setString(2, StringUtils.defaultIfBlank(typ, null));
				ps.setString(3, StringUtils.defaultIfBlank(iss, null));
				ps.setString(4, StringUtils.defaultIfBlank(sub, null));
				ps.setString(5, StringUtils.defaultIfBlank(aud, null));
				ps.setString(6, StringUtils.defaultIfBlank(kid, null));
				ps.setString(7, StringUtils.defaultIfBlank(privkey, null));
				ps.setString(8, StringUtils.defaultIfBlank(publickey, null));
				ps.setString(9, StringUtils.defaultIfBlank(certificate, null));
				ps.setBoolean(10, enabled);

				ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in inserting modi fruizione sub : ", e);
				throw new APIManagementException("Error in inserting modi fruizione sub", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return modiPK;
	}

	@Override
	public ModiPKMapping getPrivateKey(String appUUID) {
		ModiPKMapping privateKey = new ModiPKMapping();

		String GET_PK_APP_MAPPING_SQL =
    			"SELECT " +
    			"TYP AS TYP, " +
    			"ISS AS ISS, " +
    			"SUB AS SUB, " +
    			"AUD AS AUD, " +
    			"PRIVATE_KEY_PEM AS PRIVATE_KEY_PEM, " +
   				"PUBLIC_KEY_PEM AS PUBLIC_KEY_PEM, " +
  				"CERTIFICATE_PEM AS CERTIFICATE_PEM, " +
  				"KID AS KID " +
    			"FROM " +
                "MODI_FRUIZIONE_SUBSCRIPTION " +
    			"WHERE " +
                "APPLICATION_UUID = ? " +
                "AND ENABLED = '1'";
        try (Connection conn = ModiDBUtil.getConnection();
                PreparedStatement ps =
                        conn.prepareStatement(GET_PK_APP_MAPPING_SQL)) {

            ps.setString(1, appUUID);
            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null && privateKey != null) {
            		if (resultSet.next()) {
            			privateKey.setTyp(resultSet.getString("TYP"));
            			privateKey.setIss(resultSet.getString("ISS"));
            			privateKey.setSub(resultSet.getString("SUB"));
            			privateKey.setAud(resultSet.getString("AUD"));
            			privateKey.setPrivkey(resultSet.getString("PRIVATE_KEY_PEM"));
            			privateKey.setPublickey(resultSet.getString("PUBLIC_KEY_PEM"));
            			privateKey.setCertificate(resultSet.getString("CERTIFICATE_PEM"));
            			privateKey.setKid(resultSet.getString("KID"));
            			privateKey.setEnabled(true);
            			privateKey.setApplicationUUID(appUUID);
            		}
            	}

            }

        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + appUUID, e);
        }
		return privateKey;
	}

	@Override
	public ModiPKMapping getPrivateKeyByConsumerKey(String consumerKey) {
		ModiPKMapping privateKey = new ModiPKMapping();

		String GET_APPLICATION_ID = "SELECT AA.UUID AS APPUUID "
				+ "FROM AM_APPLICATION_KEY_MAPPING AKM, "
				+ "AM_APPLICATION AA "
				+ "WHERE "
				+ "AKM.APPLICATION_ID = AA.APPLICATION_ID AND "
				+ "AKM.CONSUMER_KEY = ?";
        try (Connection conn = APIMgtDBUtil.getConnection();
                PreparedStatement ps =
                        conn.prepareStatement(GET_APPLICATION_ID)) {
        	ps.setString(1, consumerKey);
            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null && privateKey != null) {
            		if (resultSet.next()) {
            			String appUUID = resultSet.getString("APPUUID");
            			privateKey = getPrivateKey(appUUID);
            		}
            	}
            }
        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + consumerKey, e);
        }

		return privateKey;
	}
	
	@Override
	public int updatePrivateKey(String applicationUuid) throws APIManagementException, APIManagerDatabaseException{

		int result = 0;
		try {
			ModiDBUtil.initialize();
			
			String UPDATE_MODI_FRUIZIONE_SUB_SQL = "UPDATE MODI_FRUIZIONE_SUBSCRIPTION SET ENABLED = '0' "
					+ " WHERE APPLICATION_UUID = ? "
					+ " AND ENABLED = '1' ";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(UPDATE_MODI_FRUIZIONE_SUB_SQL)) {
				ps.setString(1, applicationUuid);

				result = ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in updating modi fruizione sub : ", e);
				throw new APIManagementException("Error in updating modi fruizione sub", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public int updatePrivateKeySOAP(String applicationUuid) throws APIManagementException, APIManagerDatabaseException{

		int result = 0;
		try {
			ModiDBUtil.initialize();
			
			String UPDATE_MODI_FRUIZIONE_SUB_SQL = "UPDATE MODI_FRUIZIONE_SUBSCRIPTION_SOAP SET ENABLED = '0' "
					+ " WHERE APPLICATION_UUID = ? "
					+ " AND ENABLED = '1' ";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(UPDATE_MODI_FRUIZIONE_SUB_SQL)) {
				ps.setString(1, applicationUuid);

				result = ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in updating modi fruizione sub : ", e);
				throw new APIManagementException("Error in updating modi fruizione sub", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public ModiPKMapping getPrivateKeyByConsumerKeySOAP(String consumerKey) {
		ModiPKMapping privateKey = new ModiPKMapping();

		String GET_APPLICATION_ID = "SELECT AA.UUID AS APPUUID "
				+ "FROM AM_APPLICATION_KEY_MAPPING AKM, "
				+ "AM_APPLICATION AA "
				+ "WHERE "
				+ "AKM.APPLICATION_ID = AA.APPLICATION_ID AND "
				+ "AKM.CONSUMER_KEY = ?";
        try (Connection conn = APIMgtDBUtil.getConnection();
                PreparedStatement ps =
                        conn.prepareStatement(GET_APPLICATION_ID)) {
        	ps.setString(1, consumerKey);
            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null && privateKey != null) {
            		if (resultSet.next()) {
            			String appUUID = resultSet.getString("APPUUID");
            			privateKey = getPrivateKeySOAP(appUUID);
            		}
            	}
            }
        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + consumerKey, e);
        }

		return privateKey;
	}
	
	@Override
	public ModiPKMapping getPrivateKeySOAP(String appUUID) {
		ModiPKMapping privateKey = new ModiPKMapping();

		String GET_PK_APP_MAPPING_SQL =
    			"SELECT " +
    			"PRIVATE_KEY_PEM AS PRIVATE_KEY_PEM, " +
  				"CERTIFICATE_PEM AS CERTIFICATE_PEM, " +
  				"WSADDRESSING_TO AS WSADDRESSING_TO " +
    			"FROM " +
                "MODI_FRUIZIONE_SUBSCRIPTION_SOAP " +
    			"WHERE " +
                "APPLICATION_UUID = ? " +
                "AND ENABLED = '1'";
        try (Connection conn = ModiDBUtil.getConnection();
                PreparedStatement ps =
                        conn.prepareStatement(GET_PK_APP_MAPPING_SQL)) {

            ps.setString(1, appUUID);
            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null && privateKey != null) {
            		if (resultSet.next()) {
            			privateKey.setPrivkey(resultSet.getString("PRIVATE_KEY_PEM"));
            			privateKey.setCertificate(resultSet.getString("CERTIFICATE_PEM"));
            			privateKey.setWsaddressingTo(resultSet.getString("WSADDRESSING_TO"));
            			privateKey.setEnabled(true);
            		}
            	}

            }

        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + appUUID, e);
        }
		return privateKey;
	}

	@Override
	public ModiPKMapping insertPrivateKeySOAP(String applicationUuid, String wsaddressingTo, String privkey,
			String certificate, boolean enabled) throws APIManagementException, APIManagerDatabaseException {
		ModiPKMapping modiPK = new ModiPKMapping();
		try {
			ModiDBUtil.initialize();

			String INSERT_MODI_FRUIZIONE_SUB_SOAP_SQL = "INSERT INTO MODI_FRUIZIONE_SUBSCRIPTION_SOAP (APPLICATION_UUID,WSADDRESSING_TO,PRIVATE_KEY_PEM,CERTIFICATE_PEM,ENABLED)"
					+ " VALUES (?,?,?,?,?)";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(INSERT_MODI_FRUIZIONE_SUB_SOAP_SQL)) {
				ps.setString(1, StringUtils.defaultIfBlank(applicationUuid, null));
				ps.setString(2, StringUtils.defaultIfBlank(wsaddressingTo, null));
				ps.setString(3, StringUtils.defaultIfBlank(privkey, null));
				ps.setString(4, StringUtils.defaultIfBlank(certificate, null));
				ps.setBoolean(5, enabled);

				ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in inserting modi fruizione sub SOAP : ", e);
				throw new APIManagementException("Error in inserting modi fruizione sub SOAP", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return modiPK;
	}

}
