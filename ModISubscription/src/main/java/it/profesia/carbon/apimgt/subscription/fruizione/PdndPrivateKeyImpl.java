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
import it.profesia.carbon.apimgt.subscription.dao.PdndPKMapping;

public class PdndPrivateKeyImpl implements PdndPrivateKey {

	private static final Log log = LogFactory.getLog(PdndPrivateKeyImpl.class);

	@Override
	public PdndPKMapping insertPrivateKey(String applicationUuid, String uri, String kid, String alg, String typ, String iss,
			String sub, String aud, String purposeId, String clientId, String scope, String privkey, Boolean enabled) throws APIManagementException, APIManagerDatabaseException{

		PdndPKMapping pdndPK = new PdndPKMapping();
		try {
			ModiDBUtil.initialize();

			String INSERT_PDND_FRUIZIONE_SUB_SQL = "INSERT INTO PDND_FRUIZIONE_SUBSCRIPTION (APPLICATION_UUID,URI,KID,ALG,TYP,"
					+ "ISS,SUB,AUD,PURPOSE_ID,CLIENTID,SCOPE,PRIVATE_KEY_PEM,ENABLED)"
					+ " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(INSERT_PDND_FRUIZIONE_SUB_SQL)) {
				ps.setString(1, applicationUuid);
				ps.setString(2, StringUtils.defaultIfBlank(uri, null));
				ps.setString(3, StringUtils.defaultIfBlank(kid, null));
				ps.setString(4, StringUtils.defaultIfBlank(alg, null));
				ps.setString(5, StringUtils.defaultIfBlank(typ, null));
				ps.setString(6, StringUtils.defaultIfBlank(iss, null));
				ps.setString(7, StringUtils.defaultIfBlank(sub, null));
				ps.setString(8, StringUtils.defaultIfBlank(aud, null));
				ps.setString(9, StringUtils.defaultIfBlank(purposeId, null));
				ps.setString(10, StringUtils.defaultIfBlank(clientId, null));
				ps.setString(11, StringUtils.defaultIfBlank(scope, null));
				ps.setString(12, StringUtils.defaultIfBlank(privkey, null));
				ps.setBoolean(13, enabled);

				ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in inserting pdnd fruizione sub : ", e);
				throw new APIManagementException("Error in inserting pdnd fruizione sub", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return pdndPK;
	}

	@Override
	public PdndPKMapping getPrivateKey(String appUUID) {
		PdndPKMapping privateKey = new PdndPKMapping();

    	String GET_PK_APP_MAPPING_SQL =
    			"SELECT " +
                        "KID AS KID, " +
                        "ALG AS ALG, " +
    					"TYP AS TYP, " +
    					"ISS AS ISS, " +
    					"SUB AS SUB, " +
    					"AUD AS AUD, " +
    					"URI AS URI, " +
    					"PURPOSE_ID AS PURPOSE_ID, " +
    					"PRIVATE_KEY_PEM AS PRIVATE_KEY_PEM, " +
    					"CLIENTID AS CLIENTID, " +
    					"SCOPE AS SCOPE " +
    					"FROM " +
                        "PDND_FRUIZIONE_SUBSCRIPTION " +
                        "WHERE " +
                        "APPLICATION_UUID = ? " +
                        "AND ENABLED = '1'";
    	log.info("Query getPrivateKey: " + GET_PK_APP_MAPPING_SQL);
        try (Connection conn = ModiDBUtil.getConnection();
                PreparedStatement ps =
                        conn.prepareStatement(GET_PK_APP_MAPPING_SQL)) {

        	log.debug("Query getPrivateKey: " + GET_PK_APP_MAPPING_SQL + "\n  parameter: " + appUUID);
            ps.setString(1, appUUID);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null && privateKey != null) {
                	log.info("Resultset getPrivateKey: " + resultSet);
            		if (resultSet.next()) {
                    	log.info("Resultset row: " + resultSet.getRow());
            			privateKey.setKid(resultSet.getString("KID"));
            			privateKey.setAlg(resultSet.getString("ALG"));
            			privateKey.setTyp(resultSet.getString("TYP"));
            			privateKey.setIss(resultSet.getString("ISS"));
            			privateKey.setSub(resultSet.getString("SUB"));
            			privateKey.setAud(resultSet.getString("AUD"));
            			privateKey.setUri(resultSet.getString("URI"));
            			privateKey.setPurposeId(resultSet.getString("PURPOSE_ID"));
            			privateKey.setPrivkey(resultSet.getString("PRIVATE_KEY_PEM"));
            			log.debug("PRIVATE_KEY_PEM: " + privateKey.getPrivkey());
            			privateKey.setClientId(resultSet.getString("CLIENTID"));
            			privateKey.setScope(resultSet.getString("SCOPE"));
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
	public PdndPKMapping getPrivateKeyByConsumerKey(String consumerKey) {
		PdndPKMapping privateKey = new PdndPKMapping();

		String GET_APPLICATION_ID = "SELECT APP.UUID AS APPUUID "
				+ "FROM AM_APPLICATION_KEY_MAPPING AKM, "
				+ "AM_APPLICATION APP "
				+ "WHERE "
				+ "AKM.APPLICATION_ID = APP.APPLICATION_ID AND "
				+ "AKM.CONSUMER_KEY = ?";
		log.info("query PDND: " + GET_APPLICATION_ID);
        try (Connection conn = APIMgtDBUtil.getConnection();
                PreparedStatement ps =
                        conn.prepareStatement(GET_APPLICATION_ID)) {
        	ps.setString(1, consumerKey);
        	log.debug("Query PDND: " + GET_APPLICATION_ID + "\n  Parameter: " + consumerKey);
            try (ResultSet resultSet = ps.executeQuery()) {
            	log.info("Result PDND: " + resultSet);
            	if (resultSet != null && privateKey != null) {
            		if (resultSet.next()) {
            			String appUUID = resultSet.getString("APPUUID");
            			//setApplicationUUID(appUUID);
            			log.debug("PDND App UUID: " + appUUID);
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
			
			String UPDATE_PDND_FRUIZIONE_SUB_SQL = "UPDATE PDND_FRUIZIONE_SUBSCRIPTION SET ENABLED = '0' "
					+ " WHERE APPLICATION_UUID = ? "
					+ " AND ENABLED = '1' ";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(UPDATE_PDND_FRUIZIONE_SUB_SQL)) {
				ps.setString(1, applicationUuid);

				result = ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in updating pdnd fruizione sub : ", e);
				throw new APIManagementException("Error in updating pdnd fruizione sub", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}

}
