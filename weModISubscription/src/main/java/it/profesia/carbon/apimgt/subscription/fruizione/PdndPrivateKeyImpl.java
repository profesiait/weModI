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
import org.wso2.carbon.apimgt.api.model.Application;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;

import it.profesia.carbon.apimgt.subscription.ModiDBUtil;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;

public class PdndPrivateKeyImpl implements PdndPrivateKey {

	private static final Log log = LogFactory.getLog(PdndPrivateKeyImpl.class);

	@Override
	public PdndPKMapping insertPrivateKey(String applicationUuid, String keyType, String uri, String kid, String alg, String typ, String iss,
			String sub, String aud, String purposeId, String clientId, String scope, String privkey, Boolean enabled) throws APIManagementException, APIManagerDatabaseException{

		PdndPKMapping pdndPK = new PdndPKMapping();
		try {
			ModiDBUtil.initialize();

			String INSERT_PDND_FRUIZIONE_SUB_SQL = "INSERT INTO PDND_FRUIZIONE_SUBSCRIPTION (APPLICATION_UUID,"
					// TODO: aggiungere il campo KEY_TYPE alla tabella
					// + "KEY_TYPE,"
			        + "URI,KID,ALG,TYP,"
					+ "ISS,SUB,AUD,PURPOSE_ID,CLIENTID,SCOPE,PRIVATE_KEY_PEM,ENABLED)"
					+ " VALUES (?,"
					// TODO: aggiungere il campo KEY_TYPE alla tabella
					// + "?,"
					+ "?,?,?,?,?,?,?,?,?,?,?,?)";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(INSERT_PDND_FRUIZIONE_SUB_SQL)) {
				ps.setString(1, applicationUuid);
				// TODO: aggiungere il campo KEY_TYPE alla tabella, allineare gli indeci dei campi successiviv
				// ps.setString(2, StringUtils.defaultIfBlank(keyType, null));
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
			}
		} catch (SQLException | APIManagerDatabaseException e) {
            String msg = "Error in fase di inserimento della chiave privata weModI.";
			log.error(msg, e);
			throw new APIManagementException(msg, e);
		}
		return pdndPK;
	}

	@Override
	public PdndPKMapping getPrivateKey(String appUUID, String keyType) throws APIManagementException {
		PdndPKMapping privateKey = new PdndPKMapping();
		log.debug("Ricerca della chiave privata PDND in base ad Application UUID: " + appUUID);

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
						// TODO: aggiungere il campo nella tabella per gestire le configurazioni degli endpoint di SANDBOX/PRODUCTION
						// "AND KEY_TYPE = ? " +
                        "AND ENABLED = '1'";
    	log.trace("Query getPrivateKey: " + GET_PK_APP_MAPPING_SQL);
        try (Connection conn = ModiDBUtil.getConnection();
                PreparedStatement ps =
                        conn.prepareStatement(GET_PK_APP_MAPPING_SQL)) {

        	log.trace("Query getPrivateKey: " + GET_PK_APP_MAPPING_SQL + "\n  parameter: " + appUUID);
            ps.setString(1, appUUID);
            // TODO: aggiungere il campo nella tabella per gestire le configurazioni degli endpoint di SANDBOX/PRODUCTION
            // ps.setString(2, keyType);

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
			String msg = String.format("Impossibile recuperare la chiave privata PDND in base al Application UUID %s.", appUUID);
            log.error(String.format("%s %s", msg, e.getLocalizedMessage()));
			throw new APIManagementException(msg, e);
        }
		return privateKey;
	}

	@Override
	public PdndPKMapping getPrivateKeyByConsumerKey(String consumerKey) throws APIManagementException {
		PdndPKMapping privateKey = new PdndPKMapping();
		log.debug("Ricerca della chiave privata PDND in base al Client ID: " + consumerKey);

		Application application = APIUtil.getApplicationByClientId(consumerKey);
		String applicationUUID = application.getUUID();
		log.trace("Ottenuto lo UUID dell'application: " + applicationUUID);
        privateKey = getPrivateKey(applicationUUID, application.getKeyType());

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
