package it.profesia.carbon.apimgt.subscription;


import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.apimgt.impl.APIConstants;

public final class ModiDBUtil {

    private static final Log log = LogFactory.getLog(ModiDBUtil.class);

    private static volatile DataSource dataSource = null;

    /**
     * Initializes the data source
     *
     * @throws APIManagementException if an error occurs while loading DB configuration
     */
    public static void initialize() throws APIManagerDatabaseException {
        if (dataSource != null) {
            return;
        }

        synchronized (ModiDBUtil.class) {
            if (dataSource == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Initializing data source");
                }
                String dataSourceName = "jdbc/WSO2MODI_DB";

                if (dataSourceName != null) {
                    try {
                        dataSource = (DataSource) InitialContext.doLookup(dataSourceName);
                    } catch (NamingException e) {
                        throw new APIManagerDatabaseException("Error while looking up the data " +
                                "source: " + dataSourceName, e);
                    }
                } 
            }
        }
    }

    /**
     * Utility method to get a new database connection
     *
     * @return Connection
     * @throws java.sql.SQLException if failed to get Connection
     */
    public static Connection getConnection() throws SQLException {
        if (dataSource != null) {
        	log.debug("ModI dataSource: " + dataSource);
            return dataSource.getConnection();
        }
        try {
			dataSource = (DataSource) InitialContext.doLookup("jdbc/WSO2MODI_DB");
		} catch (NamingException e) {
			throw new SQLException("Data source is not configured properly.", e);
		}
        if (dataSource != null) {
        	log.debug("ModI dataSource: " + dataSource);
            return dataSource.getConnection();
        }
        throw new SQLException("Data source is not configured properly.");
    }

    /**
     * Utility method to close the connection streams.
     * @param preparedStatement PreparedStatement
     * @param connection Connection
     * @param resultSet ResultSet
     */
    public static void closeAllConnections(PreparedStatement preparedStatement, Connection connection,
                                           ResultSet resultSet) {
        closeConnection(connection);
        closeResultSet(resultSet);
        closeStatement(preparedStatement);
    }

    /**
     * Close Connection
     * @param dbConnection Connection
     */
    private static void closeConnection(Connection dbConnection) {
        if (dbConnection != null) {
            try {
                dbConnection.close();
            } catch (SQLException e) {
                log.warn("Database error. Could not close database connection. Continuing with " +
                        "others. - " + e.getMessage(), e);
            }
        }
    }

    /**
     * Close ResultSet
     * @param resultSet ResultSet
     */
    private static void closeResultSet(ResultSet resultSet) {
        if (resultSet != null) {
            try {
                resultSet.close();
            } catch (SQLException e) {
                log.warn("Database error. Could not close ResultSet  - " + e.getMessage(), e);
            }
        }

    }

    /**
     * Close PreparedStatement
     * @param preparedStatement PreparedStatement
     */
    public static void closeStatement(PreparedStatement preparedStatement) {
        if (preparedStatement != null) {
            try {
                preparedStatement.close();
            } catch (SQLException e) {
                log.warn("Database error. Could not close PreparedStatement. Continuing with" +
                        " others. - " + e.getMessage(), e);
            }
        }

    }

    /**
     * Set autocommit state of the connection
     * @param dbConnection Connection
     * @param autoCommit autoCommitState
     */
    public static void setAutoCommit(Connection dbConnection, boolean autoCommit) {
        if (dbConnection != null) {
            try {
                dbConnection.setAutoCommit(autoCommit);
            } catch (SQLException e) {
                log.error("Could not set auto commit back to initial state", e);
            }
        }
    }

    /**
     * Handle connection rollback logic. Rethrow original exception so that it can be handled centrally.
     * @param connection Connection
     * @param error Error message to be logged
     * @param e Original SQLException
     * @throws SQLException
     */
    public static void rollbackConnection(Connection connection, String error, SQLException e) throws SQLException {
        if (connection != null) {
            try {
                connection.rollback();
            } catch (SQLException rollbackException) {
                // rollback failed
                log.error(error, rollbackException);
            }
            // Rethrow original exception so that it can be handled in the common catch clause of the calling method
            throw e;
        }
    }
    
    /*
     * Retrieve the organizations list the user belongs to
     */
    public static String[] getGroupingIdentifierList(String username) {
        APIManagerConfiguration config = ServiceReferenceHolder.getInstance().
                getAPIManagerConfigurationService().getAPIManagerConfiguration();
        String claim = config.getFirstProperty(APIConstants.API_STORE_GROUP_EXTRACTOR_CLAIM_URI);
        if (StringUtils.isBlank(claim)) {
            claim = "http://wso2.org/claims/organization";
        }
        String organization = null;
        String[] groupIdArray = null;
        try {

            RealmService realmService = ServiceReferenceHolder.getInstance().getRealmService();
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
            UserRealm realm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            UserStoreManager manager = realm.getUserStoreManager();
            organization =
                    manager.getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), claim, null);
            if (organization != null) {
                if (organization.contains(",")) {
                    groupIdArray = organization.split(",");
                    for (int i = 0; i < groupIdArray.length; i++) {
                        groupIdArray[i] = groupIdArray[i].toString().trim();
                    }
                } else {
                    organization = organization.trim();
                    groupIdArray = new String[] {organization};
                }
            } else {
                // If claim is null then returning a empty string
                groupIdArray = new String[] {};
            }
        }  catch (Exception e) {
            log.error("Error while checking user existence for " + username, e);
        }

        return groupIdArray;
    }

}

