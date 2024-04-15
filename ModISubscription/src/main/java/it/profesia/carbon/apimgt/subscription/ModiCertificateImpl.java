package it.profesia.carbon.apimgt.subscription;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;

import it.profesia.carbon.apimgt.subscription.dao.CertAppMapping;
import it.profesia.carbon.apimgt.subscription.dao.PdndPKMapping;
import it.profesia.carbon.apimgt.subscription.utils.CertificateMetadata;
import it.profesia.carbon.apimgt.subscription.utils.CertificateUtils;

public class ModiCertificateImpl implements ModiCertificate {
    private static final Log log = LogFactory.getLog(ModiCertificate.class);

    @Override
    public List<CertAppMapping> getCertificates(String appUUID) {
    	List<CertAppMapping> list = new ArrayList<CertAppMapping>();
    	String GET_CERT_APP_MAPPING_SQL =
    			"SELECT " +
                        "   APPLICATION_UUID AS APP_UUID," +
    					"   SERIAL_NUMBER AS SERIAL_NUMBER," +
    					"   ISSUER_DN AS ISSUER_DN," +
    					"   ALIAS AS ALIAS," +
    					"   PDND_PUBLIC_KEY AS PDND_PUBLIC_KEY," +
    					"   PDND_CLIENT_ID AS PDND_CLIENT_ID," +
    					"   PDND_PURPOSEID AS PDND_PURPOSEID," +
    					"   KID_PDND_API AS KID_PDND_API" +
                        " FROM " +
                        "   APP_CERT_MAPPING" +
                        " WHERE " +
                        "   APPLICATION_UUID = ? " +
                        "	AND ENABLED = '1'";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_CERT_APP_MAPPING_SQL)) {

            ps.setString(1, appUUID);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null && list != null) {
                    while (resultSet.next()) {
                    	CertAppMapping cam = new CertAppMapping();
                        cam.setApplicationUUID(resultSet.getString("APP_UUID"));
                        cam.setSerialNumber(resultSet.getString("SERIAL_NUMBER"));
                        cam.setIssuerDN(resultSet.getString("ISSUER_DN"));
                        cam.setAlias(resultSet.getString("ALIAS"));
                        cam.setPdndPublicKey(resultSet.getString("PDND_PUBLIC_KEY"));
                        cam.setPdndPurposeId(resultSet.getString("PDND_PURPOSEID"));
                        cam.setPdndClientId(resultSet.getString("PDND_CLIENT_ID"));
                        cam.setPdndKidApiInterop(resultSet.getString("KID_PDND_API"));
                        list.add(cam);
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + appUUID, e);
        }
        return list;
    }
    
    @Override
    public CertAppMapping getCertificate(String appUUID) {
    	CertAppMapping cam = null;
    	String GET_CERT_APP_MAPPING_SQL =
    			"SELECT " +
                        "   APPLICATION_UUID AS APP_UUID," +
    					"   SERIAL_NUMBER AS SERIAL_NUMBER," +
    					"   ISSUER_DN AS ISSUER_DN," +
    					"   ALIAS AS ALIAS," +
    					"   THUMBPRINT AS THUMBPRINT," +
    					"   THUMBPRINTSHA256 AS THUMBPRINTSHA256," +
    					"   PDND_CLIENT_ID AS PDND_CLIENT_ID," +
    					"   KID_PDND_API AS KID_PDND_API" +
                        " FROM " +
                        "   APP_CERT_MAPPING" +
                        " WHERE " +
                        "   APPLICATION_UUID = ? " +
                        "	AND ENABLED = '1'";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_CERT_APP_MAPPING_SQL)) {

            ps.setString(1, appUUID);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	cam = new CertAppMapping();
                        cam.setApplicationUUID(resultSet.getString("APP_UUID"));
                        cam.setSerialNumber(resultSet.getString("SERIAL_NUMBER"));
                        cam.setIssuerDN(resultSet.getString("ISSUER_DN"));
                        cam.setAlias(resultSet.getString("ALIAS"));
                        cam.setThumbprint(resultSet.getString("THUMBPRINT"));
                        cam.setThumbprintSha256(resultSet.getString("THUMBPRINTSHA256"));
                        cam.setPdndClientId(resultSet.getString("PDND_CLIENT_ID"));
                        cam.setPdndKidApiInterop(resultSet.getString("KID_PDND_API"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + appUUID, e);
        }
        return cam;
    }


	@Override
	public String getString(String value) {
		// TODO Auto-generated method stub
		return "Hello "+value;
	}

	@Override
	public CertAppMapping getAliasWithThumbprint(String thumbprint) {
		CertAppMapping cam = null;
    	String GET_CERT_APP_MAPPING_SQL =
    			"SELECT " +
    					"   ALIAS AS ALIAS" +
                        " FROM " +
                        "   APP_CERT_MAPPING" +
                        " WHERE " +
                        "   (THUMBPRINT = ? " +
                        "   OR " +
                        "   THUMBPRINTSHA256 = ?) " +
                        "	AND ENABLED = '1'";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_CERT_APP_MAPPING_SQL)) {

            ps.setString(1, thumbprint);
            ps.setString(2, thumbprint);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	cam = new CertAppMapping();
                        cam.setAlias(resultSet.getString("ALIAS"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving alias with thumbprint : " + thumbprint, e);}
        return cam;
	}


	@Override
	public String insertCertificate(String appUUID, String createdBy,
			String alias,  String pdndPublicKey, String pdndClientId,
			String pdndPurposeId, String privatekey, String pdndKidApiInterop) throws APIManagementException, APIManagerDatabaseException {
		String result = "Row not inserted";
		try {
			//CertAppMapping cam = getAppDetailsFromName(appName, createdBy);
			//CertAppMapping cam = getAppUUID(appName, createdBy);
			ModiDBUtil.initialize();

			UUID uuid = UUID.randomUUID();

			String INSERT_CERT_APP_MAPPING_SQL = "INSERT INTO APP_CERT_MAPPING (ID,APPLICATION_UUID,SERIAL_NUMBER,ISSUER_DN,ALIAS,"
					+ "THUMBPRINT,THUMBPRINTSHA256,PDND_PUBLIC_KEY,PDND_CLIENT_ID,PDND_PURPOSEID,ENABLED,KID_PDND_API)"
					+ " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";
				try (Connection conn = ModiDBUtil.getConnection();
						PreparedStatement ps = conn.prepareStatement(INSERT_CERT_APP_MAPPING_SQL)) {
					ps.setString(1, uuid.toString());
					//ps.setString(2, cam.getApplicationUUID());
					ps.setString(2, appUUID);
					ps.setString(3, CertificateUtils.getSerialNumber(privatekey));
					ps.setString(4, CertificateUtils.getIssuerDN(privatekey));
					ps.setString(5, StringUtils.defaultIfBlank(alias, null));
					ps.setString(6, CertificateUtils.getThumbprint(privatekey));
					ps.setString(7, CertificateUtils.getThumbprint256(privatekey));
					ps.setString(8, pdndPublicKey);
					ps.setString(9, StringUtils.defaultIfBlank(pdndClientId, null));
					ps.setString(10, StringUtils.defaultIfBlank(pdndPurposeId, null));
					ps.setBoolean(11, true);
					ps.setString(12, StringUtils.defaultIfBlank(pdndKidApiInterop, null));
	
					ps.executeUpdate();
					result = "Row inserted correctly";
				} catch (SQLException e) {
					log.error("Error in inserting cert app mapping : ", e);
					throw new APIManagementException("Error in inserting cert app mapping", e);
				}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public String insertCertificateDetails(String appUUID, String serialNumber, String issuerDN, String alias, String thumbprint, String thumbprintSha256, String pdndClientId, String pdndKidApiInterop) throws APIManagementException, APIManagerDatabaseException {
		String result = "Row not inserted";
		try {
			ModiDBUtil.initialize();

			UUID uuid = UUID.randomUUID();

			String INSERT_CERT_APP_MAPPING_SQL = "INSERT INTO APP_CERT_MAPPING (ID,APPLICATION_UUID,SERIAL_NUMBER,ISSUER_DN,ALIAS,"
					+ "THUMBPRINT,THUMBPRINTSHA256,PDND_CLIENT_ID,ENABLED,KID_PDND_API)"
					+ " VALUES (?,?,?,?,?,?,?,?,?,?)";
				try (Connection conn = ModiDBUtil.getConnection();
						PreparedStatement ps = conn.prepareStatement(INSERT_CERT_APP_MAPPING_SQL)) {
					ps.setString(1, uuid.toString());
					ps.setString(2, appUUID);
					ps.setString(3, StringUtils.defaultIfBlank(serialNumber, null));
					ps.setString(4, StringUtils.defaultIfBlank(issuerDN, null));
					ps.setString(5, StringUtils.defaultIfBlank(alias, null));
					ps.setString(6, StringUtils.defaultIfBlank(thumbprint, null));
					ps.setString(7, StringUtils.defaultIfBlank(thumbprintSha256, null));
					ps.setString(8, StringUtils.defaultIfBlank(pdndClientId, null));
					ps.setBoolean(9, true);
					ps.setString(10, StringUtils.defaultIfBlank(pdndKidApiInterop, null));
	
					ps.executeUpdate();
					result = "Row inserted correctly";
				} catch (SQLException e) {
					log.error("Error in inserting cert app mapping : ", e);
					throw new APIManagementException("Error in inserting cert app mapping", e);
				}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}


	@Override
	public CertAppMapping getAppDetailsFromName(String appName, String createdBy) {
		CertAppMapping cam = null;
    	String GET_APP_DETAILS_SQL =
    			"SELECT " +
    					"   UUID AS UUID" +
                        " FROM " +
                        "   AM_APPLICATION" +
                        " WHERE " +
                        "   NAME = ? " +
                        "   AND " +
                        "   CREATED_BY = ? ";

        try (Connection conn = APIMgtDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_APP_DETAILS_SQL)) {

            ps.setString(1, appName);
            ps.setString(2, createdBy);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	cam = new CertAppMapping();
                        cam.setApplicationUUID(resultSet.getString("UUID"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving app details", e);
            }
        return cam;
	}
	
	/*
	 * Retrieve the UUID of the applications created by the logged user
	 * or shared with it in the same organization
	 */
	private CertAppMapping getAppUUID(String appName, String username) {
		CertAppMapping cam = null;
		
		String[] organizations = ModiDBUtil.getGroupingIdentifierList(username);
		String listOfOrgs = "";
		for(int i = 0; i<organizations.length; i++)
		{
			log.info("organization: "+organizations[i]);
			if(i == organizations.length - 1)
				listOfOrgs = listOfOrgs + "?";
			else
				listOfOrgs = listOfOrgs + "?,";	
		}
		
		String GET_APP_DETAILS_SQL =
    			"SELECT " +
    					"   UUID AS UUID" +
                        " FROM " +
                        "   AM_APPLICATION A" +
                        "   INNER JOIN AM_APPLICATION_GROUP_MAPPING B ON" +
                        "   A.APPLICATION_ID = B.APPLICATION_ID" +
                        " WHERE " +
                        "   A.NAME = ? " +
                        "   AND " +
                        "   B.GROUP_ID IN ("+
                        listOfOrgs +
                           ")";

        try (Connection conn = APIMgtDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_APP_DETAILS_SQL)) {
        	
        	/*createArrayOf is not supported by org.h2.Driver
        	Array organizationsArray = conn.createArrayOf("varchar", organizations);
        	ps.setArray(2, organizationsArray);*/

        	int j = 1;
            ps.setString(1, appName);
            for(String org : organizations)
            	ps.setString(++j, org);
            

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	cam = new CertAppMapping();
                        cam.setApplicationUUID(resultSet.getString("UUID"));
                        log.info("UUID: "+resultSet.getString("UUID"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving app details", e);
            }
        return cam;
	}
	
	@Override
	public List<String> getAllApplicationsCreators() {
		List<String> users = new ArrayList<String>();
    	String GET_USERS_SQL =
    			"SELECT DISTINCT " +
    					"   CREATED_BY AS CREATED_BY" +
                        " FROM " +
                        "   AM_APPLICATION";

        try (Connection conn = APIMgtDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_USERS_SQL)) {


            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	users.add(resultSet.getString("CREATED_BY"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving users", e);
            }
        return users;
	}
	
	@Override
	public List<String> getApplicationsCreatedByUser(String user) {
		List<String> applications = new ArrayList<String>();
    	String GET_APPLICATIONS_SQL =
    			"SELECT " +
    					"   NAME AS NAME" +
                        " FROM " +
                        "   AM_APPLICATION" +
                        " WHERE " +
                        "   CREATED_BY = ? ";

        try (Connection conn = APIMgtDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_APPLICATIONS_SQL)) {
        	
        	ps.setString(1, user);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	applications.add(resultSet.getString("NAME"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving applications", e);
            }
        return applications;
	}
	
	@Override
	public List<CertAppMapping> getApplicationsFromSameOrg(String username) {
		String GET_APP_DETAILS_SQL = "SELECT " +
					"   UUID AS UUID," +
					"   NAME AS NAME," +
					"   CREATED_BY AS CREATED_BY" +
                   " FROM " +
                   "   AM_APPLICATION A" +
                   " WHERE " +
                   "   A.CREATED_BY = ?";
		List<CertAppMapping> applications = new ArrayList<CertAppMapping>();
		String[] organizations = ModiDBUtil.getGroupingIdentifierList(username);
		String listOfOrgs = "";
		for(int i = 0; i<organizations.length; i++)
		{
			log.info("organization: "+organizations[i]);
			if(i == organizations.length - 1)
				listOfOrgs = listOfOrgs + "?";
			else
				listOfOrgs = listOfOrgs + "?,";	
		}
		
		if(!(listOfOrgs.equals("")))
		{
			GET_APP_DETAILS_SQL =
	    			"SELECT " +
	    					"   A.UUID AS UUID," +
	    					"   A.NAME AS NAME," +
	    					"   A.CREATED_BY AS CREATED_BY" +
	                        " FROM " +
	                        "   AM_APPLICATION A," +
	                        "   AM_APPLICATION_GROUP_MAPPING B" +
	                        " WHERE " +
	                        "   A.APPLICATION_ID = B.APPLICATION_ID" +
	                        "   AND" +
	                        "   B.GROUP_ID IN ("+
	                        listOfOrgs +
	                           ")" +
	                           " UNION " +
	                  "SELECT " +
	       					"   UUID AS UUID," +
	       					"   NAME AS NAME," +
	       					"   CREATED_BY AS CREATED_BY" +
	                           " FROM " +
	                           "   AM_APPLICATION A" +
	                           " WHERE " +
	                           "   A.CREATED_BY = ?";
		}
                        

        try (Connection conn = APIMgtDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_APP_DETAILS_SQL)) {
        	
        	/*createArrayOf is not supported by org.h2.Driver
        	Array organizationsArray = conn.createArrayOf("varchar", organizations);
        	ps.setArray(2, organizationsArray);*/

        	int j = 0;
            for(String org : organizations)
            	ps.setString(++j, org);
            ps.setString(++j, username);
            

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	CertAppMapping cam = new CertAppMapping();
                    	cam.setApplicationName(resultSet.getString("NAME"));
                    	cam.setApplicationUUID(resultSet.getString("UUID"));
                    	cam.setApplicationCreator(resultSet.getString("CREATED_BY"));
                    	applications.add(cam);
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving applications", e);
            }
        return applications;
	}


	@Override
	public List<CertAppMapping> getCertificatesSOAP(String appUUID) {
		List<CertAppMapping> list = new ArrayList<CertAppMapping>();
    	String GET_CERT_APP_MAPPING_SQL =
    			"SELECT " +
                        "   APPLICATION_UUID AS APP_UUID," +
    					"   SERIAL_NUMBER AS SERIAL_NUMBER," +
    					"   ISSUER_DN AS ISSUER_DN," +
    					"   ISSUER_NAME AS ISSUER_NAME," +
    					"   ALIAS AS ALIAS," +
    					"   THUMBPRINT AS THUMBPRINT" +
                        " FROM " +
                        "   APP_CERT_MAPPING_SOAP" +
                        " WHERE " +
                        "   APPLICATION_UUID = ? " +
                        "	AND ENABLED = '1'";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_CERT_APP_MAPPING_SQL)) {

            ps.setString(1, appUUID);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null && list != null) {
                    while (resultSet.next()) {
                    	CertAppMapping cam = new CertAppMapping();
                        cam.setApplicationUUID(resultSet.getString("APP_UUID"));
                        cam.setSerialNumber(resultSet.getString("SERIAL_NUMBER"));
                        cam.setIssuerDN(resultSet.getString("ISSUER_DN"));
                        cam.setIssuerName(resultSet.getString("ISSUER_NAME"));
                        cam.setAlias(resultSet.getString("ALIAS"));
                        cam.setThumbprint(resultSet.getString("THUMBPRINT"));
                        list.add(cam);
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + appUUID, e);
        }
        return list;
	}
	
	@Override
	public CertAppMapping getCertificateDetailsSOAP(String appUUID) {
		CertAppMapping cam = null;
    	String GET_CERT_APP_MAPPING_SQL =
    			"SELECT " +
                        "   APPLICATION_UUID AS APP_UUID," +
    					"   SERIAL_NUMBER AS SERIAL_NUMBER," +
    					"   ISSUER_DN AS ISSUER_DN," +
    					"   ISSUER_NAME AS ISSUER_NAME," +
    					"   ALIAS AS ALIAS," +
    					"   THUMBPRINT AS THUMBPRINT," +
    					"   THUMBPRINTSHA256 AS THUMBPRINTSHA256," +
    					"   SUBJECT_KEY_IDENTIFIER AS SUBJECT_KEY_IDENTIFIER," +
    					"   CERTIFICATE_PEM AS CERTIFICATE_PEM" +
                        " FROM " +
                        "   APP_CERT_MAPPING_SOAP" +
                        " WHERE " +
                        "   APPLICATION_UUID = ? " +
                        "	AND ENABLED = '1'";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_CERT_APP_MAPPING_SQL)) {

            ps.setString(1, appUUID);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	cam = new CertAppMapping();
                        cam.setApplicationUUID(resultSet.getString("APP_UUID"));
                        cam.setSerialNumber(resultSet.getString("SERIAL_NUMBER"));
                        cam.setIssuerDN(resultSet.getString("ISSUER_DN"));
                        cam.setIssuerName(resultSet.getString("ISSUER_NAME"));
                        cam.setAlias(resultSet.getString("ALIAS"));
                        cam.setThumbprint(resultSet.getString("THUMBPRINT"));
                        cam.setThumbprintSha256(resultSet.getString("THUMBPRINTSHA256"));
                        cam.setSubjectKeyIndentifier(resultSet.getString("SUBJECT_KEY_IDENTIFIER"));
                        cam.setCertificate(resultSet.getString("CERTIFICATE_PEM"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in loading cert app mapping for the application : " + appUUID, e);
        }
        return cam;
	}
	
	public CertAppMapping getCertificateSOAP(String whereClauseParam1, String whereClauseParam2) {
		CertAppMapping cam = null;
    	String GET_CERT_APP_MAPPING_SQL =
    			"SELECT " +
    					"   CERTIFICATE_PEM AS CERTIFICATE_PEM" +
                        " FROM " +
                        "   APP_CERT_MAPPING_SOAP" +
                        " WHERE " +
                        "   (THUMBPRINT = ? " +
                        "   OR " +
                        "   SUBJECT_KEY_IDENTIFIER = ? " +
                        "   OR " +
                        "   (ISSUER_NAME = ? AND SERIAL_NUMBER = ?)) " +
                        "	AND ENABLED = '1'";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_CERT_APP_MAPPING_SQL)) {

            ps.setString(1, whereClauseParam1);
            ps.setString(2, whereClauseParam1);
            ps.setString(3, whereClauseParam1);
            ps.setString(4, whereClauseParam2);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	cam = new CertAppMapping();
                        cam.setCertificate(resultSet.getString("CERTIFICATE_PEM"));
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving certificate", e);}
        return cam;
	}


	@Override
	public String insertCertificateSOAP(String appUUID, String alias, String certificate)
			throws APIManagementException, APIManagerDatabaseException {
		String result = "Row not inserted";
		try {
			ModiDBUtil.initialize();

			UUID uuid = UUID.randomUUID();

			String INSERT_CERT_APP_MAPPING_SOAP_SQL = "INSERT INTO APP_CERT_MAPPING_SOAP (ID,APPLICATION_UUID,SERIAL_NUMBER,ISSUER_DN,ISSUER_NAME,ALIAS,"
					+ "THUMBPRINT,THUMBPRINTSHA256,SUBJECT_KEY_IDENTIFIER,CERTIFICATE_PEM,ENABLED)"
					+ " VALUES (?,?,?,?,?,?,?,?,?,?,?)";
				try (Connection conn = ModiDBUtil.getConnection();
						PreparedStatement ps = conn.prepareStatement(INSERT_CERT_APP_MAPPING_SOAP_SQL)) {
					ps.setString(1, uuid.toString());
					ps.setString(2, appUUID);
					ps.setString(3, CertificateUtils.getSerialNumber(certificate));
					ps.setString(4, CertificateUtils.getIssuerDN(certificate));
					ps.setString(5, CertificateUtils.getIssuerName(certificate));
					ps.setString(6, StringUtils.defaultIfBlank(alias, null));
					ps.setString(7, CertificateUtils.getThumbprintSOAP(certificate));
					ps.setString(8, CertificateUtils.getThumbprint256SOAP(certificate));
					ps.setString(9, CertificateUtils.getSubjectKeyIdentifierSOAP(certificate));
					ps.setString(10, certificate);
					ps.setBoolean(11, true);
	
					ps.executeUpdate();
					result = "Row inserted correctly";
				} catch (SQLException e) {
					log.error("Error in inserting cert app mapping SOAP : ", e);
					throw new APIManagementException("Error in inserting cert app mapping SOAP", e);
				}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public String insertCertificateDetailsSOAP(String appUUID, String serialNumber, String issuerDN, String issuerName, String alias, String thumbprint, String thumbprintSha256, String subjectKeyIndentifier, String certificate)
			throws APIManagementException, APIManagerDatabaseException {
		String result = "Row not inserted";
		try {
			ModiDBUtil.initialize();

			UUID uuid = UUID.randomUUID();

			String INSERT_CERT_APP_MAPPING_SOAP_SQL = "INSERT INTO APP_CERT_MAPPING_SOAP (ID,APPLICATION_UUID,SERIAL_NUMBER,ISSUER_DN,ISSUER_NAME,ALIAS,"
					+ "THUMBPRINT,THUMBPRINTSHA256,SUBJECT_KEY_IDENTIFIER,CERTIFICATE_PEM,ENABLED)"
					+ " VALUES (?,?,?,?,?,?,?,?,?,?,?)";
				try (Connection conn = ModiDBUtil.getConnection();
						PreparedStatement ps = conn.prepareStatement(INSERT_CERT_APP_MAPPING_SOAP_SQL)) {
					ps.setString(1, uuid.toString());
					ps.setString(2, appUUID);
					ps.setString(3, StringUtils.defaultIfBlank(serialNumber, null));
					ps.setString(4, StringUtils.defaultIfBlank(issuerDN, null));
					ps.setString(5, StringUtils.defaultIfBlank(issuerName, null));
					ps.setString(6, StringUtils.defaultIfBlank(alias, null));
					ps.setString(7, StringUtils.defaultIfBlank(thumbprint, null));
					ps.setString(8, StringUtils.defaultIfBlank(thumbprintSha256, null));
					ps.setString(9, StringUtils.defaultIfBlank(subjectKeyIndentifier, null));
					ps.setString(10, certificate);
					ps.setBoolean(11, true);
	
					ps.executeUpdate();
					result = "Row inserted correctly";
				} catch (SQLException e) {
					log.error("Error in inserting cert app mapping SOAP : ", e);
					throw new APIManagementException("Error in inserting cert app mapping SOAP", e);
				}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public PdndPKMapping getSubscriptionDetails(String subscriptionUUID)
            throws APIManagementException {
			PdndPKMapping pdndPK = new PdndPKMapping();

            String sqlQuery = " SELECT " +
                    " AUD AS AUD, " +
                    " ISS AS ISS, " +
                    " PURPOSE_ID AS PURPOSE_ID " +
                    " FROM " +
                    "   PDND_SUBSCRIPTION_MAPPING " +
                    " WHERE " +
                    "   SUBSCRIPTION_UUID = ? " +
            		"   AND ENABLED = '1' ";
            try(Connection connection = ModiDBUtil.getConnection();
            PreparedStatement ps = connection.prepareStatement(sqlQuery))
            {
            	ps.setString(1, subscriptionUUID);
                try(ResultSet result = ps.executeQuery())
                {
                	 while (result.next()) {
                		 pdndPK.setAud(result.getString("AUD"));
                		 pdndPK.setIss(result.getString("ISS"));
                		 pdndPK.setPurposeId(result.getString("PURPOSE_ID"));
                		 pdndPK.setEnabled(true);
                     }	
                }
            }
            catch (SQLException e) {
        	String msg = "Error occurred while retrieving subscription details for " + subscriptionUUID;
        	log.error(msg, e);
        	throw new APIManagementException(msg, (Throwable)e);
        } 
        return pdndPK;
    }
	
	@Override
	public String addSubscriptionMapping(String subscriptionUUID, String pdndAud, String pdndIss, String pdndPurposeId) throws APIManagementException, APIManagerDatabaseException {
		String result = "Row not inserted";
		try {
			
			ModiDBUtil.initialize();
			
			String ADD_SUBSCRIPTION_MAPPING_SQL = "INSERT INTO PDND_SUBSCRIPTION_MAPPING (SUBSCRIPTION_UUID,AUD,ISS,PURPOSE_ID,ENABLED)"
					+ " VALUES (?,?,?,?,?)";
				try (Connection conn = ModiDBUtil.getConnection();
						PreparedStatement ps = conn.prepareStatement(ADD_SUBSCRIPTION_MAPPING_SQL)) {
					ps.setString(1, subscriptionUUID);
					ps.setString(2, pdndAud);
					ps.setString(3, pdndIss);
					ps.setString(4, pdndPurposeId);
					ps.setBoolean(5, true);
	
					ps.executeUpdate();
					result = "Row inserted correctly";
				} catch (SQLException e) {
					log.error("Error in adding subscription mapping : ", e);
					throw new APIManagementException("Error in adding subscription mapping", e);
				}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public int updateSubscriptionMapping(String subscriptionUUID) throws APIManagementException, APIManagerDatabaseException {
		int result = 0;
		try {
			
			ModiDBUtil.initialize();
			
			String UPDATE_SUBSCRIPTION_MAPPING_SQL = "UPDATE PDND_SUBSCRIPTION_MAPPING SET ENABLED = '0' " + 
					"WHERE SUBSCRIPTION_UUID = ? " + 
					" AND ENABLED = '1' ";
				try (Connection conn = ModiDBUtil.getConnection();
						PreparedStatement ps = conn.prepareStatement(UPDATE_SUBSCRIPTION_MAPPING_SQL)) {
					ps.setString(1, subscriptionUUID);
					result = ps.executeUpdate();
				} catch (SQLException e) {
					log.error("Error in updating subscription mapping : ", e);
					throw new APIManagementException("Error in updating subscription mapping", e);
				}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public int updateCertificate(String applicationUuid) throws APIManagementException, APIManagerDatabaseException{

		int result = 0;
		try {
			ModiDBUtil.initialize();
			
			String UPDATE_APP_CERT_MAPPING_SQL = "UPDATE APP_CERT_MAPPING SET ENABLED = '0' "
					+ " WHERE APPLICATION_UUID = ? "
					+ " AND ENABLED = '1' ";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(UPDATE_APP_CERT_MAPPING_SQL)) {
				ps.setString(1, applicationUuid);

				result = ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in updating app cert mapping : ", e);
				throw new APIManagementException("Error in updating app cert mapping", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
	public int updateCertificateSOAP(String applicationUuid) throws APIManagementException, APIManagerDatabaseException{

		int result = 0;
		try {
			ModiDBUtil.initialize();
			
			String UPDATE_APP_CERT_MAPPING_SOAP_SQL = "UPDATE APP_CERT_MAPPING_SOAP SET ENABLED = '0' "
					+ " WHERE APPLICATION_UUID = ? "
					+ " AND ENABLED = '1' ";

			try (Connection conn = ModiDBUtil.getConnection();
					PreparedStatement ps = conn.prepareStatement(UPDATE_APP_CERT_MAPPING_SOAP_SQL)) {
				ps.setString(1, applicationUuid);

				result = ps.executeUpdate();
			} catch (SQLException e) {
				log.error("Error in updating app cert mapping soap : ", e);
				throw new APIManagementException("Error in updating app cert mapping soap", e);
			}
		} catch (APIManagerDatabaseException e) {
			log.error("Error initializing data source : ", e);
			throw new APIManagerDatabaseException("Error initializing data source", e);
		}
		return result;
	}
	
	@Override
    public String getApplicationUUIDByKid(String kidPdndApi) {
		String applicationUUID = "";
    	String GET_CERT_APP_MAPPING_SQL =
    			"SELECT " +
                        "   APPLICATION_UUID AS APP_UUID" +
                        " FROM " +
                        "   APP_CERT_MAPPING" +
                        " WHERE " +
                        "   KID_PDND_API = ? " +
                        "	AND ENABLED = '1'";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(GET_CERT_APP_MAPPING_SQL)) {

            ps.setString(1, kidPdndApi);

            try (ResultSet resultSet = ps.executeQuery()) {
            	if (resultSet != null) {
                    while (resultSet.next()) {
                    	applicationUUID = resultSet.getString("APP_UUID");
                    }
                }
            }
        } catch (SQLException e) {
            log.error("Error in retrieving application uuid from kid : " + kidPdndApi, e);
        }
        return applicationUUID;
    }
}
