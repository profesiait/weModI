package it.profesia.carbon.apimgt.configurationApi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIManagerDatabaseException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import it.profesia.wemodi.subscriptions.dao.CertAppMapping;
import it.profesia.carbon.apimgt.subscription.ModiCertificate;
import it.profesia.carbon.apimgt.subscription.ModiCertificateImpl;
import it.profesia.carbon.apimgt.subscription.ModiDBUtil;
import it.profesia.wemodi.subscriptions.dao.ModiPKMapping;
import it.profesia.carbon.apimgt.subscription.fruizione.ModiPrivateKey;
import it.profesia.carbon.apimgt.subscription.fruizione.ModiPrivateKeyImpl;
import it.profesia.wemodi.subscriptions.dao.PdndPKMapping;
import it.profesia.carbon.apimgt.subscription.fruizione.PdndPrivateKey;
import it.profesia.carbon.apimgt.subscription.fruizione.PdndPrivateKeyImpl;

import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;

@Path("/configurationservice")
public class ModIConfigurationAPI {

    private static final Log log = LogFactory.getLog(ModIConfigurationAPI.class);
	private static final ObjectMapper mapper = new ObjectMapper();

    ModiCertificate modiCertificate = new ModiCertificateImpl();
	ModiPrivateKey modiPrivateKey = new ModiPrivateKeyImpl();
	PdndPrivateKey pdndPrivateKey = new PdndPrivateKeyImpl();

    private boolean enabledCache;
    private String expiryTimeInSecondsCache;

    @POST
    @Consumes({"multipart/form-data"})
    @Produces({"application/json"})
    @Path("certificateInbound")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificato inserito.", response = ObjectNode.class)
    })
    public Response insertCertificateInbound(@Multipart("modi") InputStream certificateInputStream, @Multipart("json") CertAppMapping cam) {
    	log.info("###insertCertificateInbound###");
        ObjectNode json = mapper.createObjectNode();
        String result = "Error";
        StringBuilder certificateBuilder = new StringBuilder();
        try (Reader reader = new BufferedReader(new InputStreamReader
                (certificateInputStream, StandardCharsets.UTF_8))) {
        	int c = 0;
            while ((c = reader.read()) != -1) {
            	certificateBuilder.append((char) c);
            }
            String certificate = certificateBuilder.toString();
            certificate = certificate.replace("-----BEGIN CERTIFICATE-----", "").replaceAll("(\r|\n)", "").replace("-----END CERTIFICATE-----", "");
            CertAppMapping certificateMetadata = modiCertificate.getCertificate(cam.getApplicationUUID());
            if(certificateMetadata != null)
            {
            	int numOfRows = modiCertificate.updateCertificate(cam.getApplicationUUID());
                log.info(numOfRows + " row/s updated");
                if(certificate.equals(""))
                	result = modiCertificate.insertCertificateDetails(certificateMetadata.getApplicationUUID(), certificateMetadata.getSerialNumber(), certificateMetadata.getIssuerDN(), cam.getAlias(), certificateMetadata.getThumbprint(), certificateMetadata.getThumbprintSha256(), cam.getPdndClientId(), cam.getPdndKidApiInterop());
                else
                	result = modiCertificate.insertCertificate(cam.getApplicationUUID(), "", cam.getAlias(), "", cam.getPdndClientId(), "", certificate, cam.getPdndKidApiInterop());
            }
            else
            	result = modiCertificate.insertCertificate(cam.getApplicationUUID(), "", cam.getAlias(), "", cam.getPdndClientId(), "", certificate, cam.getPdndKidApiInterop());
			json.put("result", result);
		} catch (APIManagementException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		} catch (APIManagerDatabaseException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		}
		catch(IOException e)
        {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
        }
        return Response.status(200).entity(json).build();
    }
    
    @POST
    @Consumes({"multipart/form-data"})
    @Produces({"application/json"})
    @Path("certificateSOAPInbound")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Certificato inserito.", response = ObjectNode.class)
    })
    public Response insertCertificateSOAPInbound(@Multipart("modi") InputStream certificateInputStream, @Multipart("json") CertAppMapping cam) {
    	log.info("###insertCertificateSOAPInbound###");
        String result = "Error";
        ObjectNode json = mapper.createObjectNode();
        StringBuilder certificateBuilder = new StringBuilder();
		try(Reader reader = new BufferedReader(new InputStreamReader
                (certificateInputStream, StandardCharsets.UTF_8)))
		{
			int c = 0;
            while ((c = reader.read()) != -1) {
            	certificateBuilder.append((char) c);
            }
            String certificate = certificateBuilder.toString();
            CertAppMapping certificateMetadata = modiCertificate.getCertificateDetailsSOAP(cam.getApplicationUUID());
            if(certificateMetadata != null)
            {
            	int numOfRows = modiCertificate.updateCertificateSOAP(cam.getApplicationUUID());
                log.info(numOfRows + " row/s updated");
                if(certificate.equals(""))
                	result = modiCertificate.insertCertificateDetailsSOAP(certificateMetadata.getApplicationUUID(), certificateMetadata.getSerialNumber(), certificateMetadata.getIssuerDN(), certificateMetadata.getIssuerName(), cam.getAlias(), certificateMetadata.getThumbprint(), certificateMetadata.getThumbprintSha256(), certificateMetadata.getSubjectKeyIndentifier(), certificateMetadata.getCertificate());
                else
                	result = modiCertificate.insertCertificateSOAP(cam.getApplicationUUID(), cam.getAlias(), certificate);
            }
            else
            	result = modiCertificate.insertCertificateSOAP(cam.getApplicationUUID(), cam.getAlias(), certificate);
			json.put("result", result);
		} catch (APIManagementException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		} catch (APIManagerDatabaseException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		}
		catch(IOException e)
        {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
        }
        return Response.status(200).entity(json).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("applicationsCreators")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Applications.", response = List.class)
    })
    public Response getAllApplicationsCreators() {
    	log.info("####getAllApplicationsCreators###");
        List<String> listOfCreators = modiCertificate.getAllApplicationsCreators();
        return Response.status(200).entity(listOfCreators).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("applicationsCreatedByUser")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Applications.", response = List.class)
    })
    public Response getApplicationsCreatedByUser(@QueryParam("userName") String userName) {
    	log.info("####getApplicationsCreatedByUser###");
        List<String> listOfApplications = modiCertificate.getApplicationsCreatedByUser(userName);
        if(listOfApplications.size() == 0)
        	RestApiUtil.handleResourceNotFoundError("No application found for the specified user", log);
        return Response.status(200).entity(listOfApplications).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("applicationsFromSameOrg")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Applications.", response = List.class)
    })
    public Response getApplicationsFromSameOrg(@QueryParam("userName") String userName) {
    	log.info("####getApplicationsFromSameOrg###");
        List<CertAppMapping> listOfApplications = modiCertificate.getApplicationsFromSameOrg(userName);
        if(listOfApplications.size() == 0)
        	RestApiUtil.handleResourceNotFoundError("No application found for the specified user", log);
        return Response.status(200).entity(listOfApplications).build();
    }
    
    @POST
    @Consumes({"multipart/form-data"})
    @Produces({"application/json"})
    @Path("certificateOutboundModi/{appUUID}")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificato inserito.", response = ObjectNode.class)
    })
    public Response insertCertificateOutboundModi(@PathParam("appUUID") String appUUID, @Multipart("modiPrivKey") InputStream privateKeyInputStream, @Multipart("modiPubKey") InputStream publicKeyInputStream, @Multipart("modiCert") InputStream certificateInputStream, @Multipart("json") ModiPKMapping modiPkMapping) {
    	log.info("###insertCertificateOutboundModi###");
    	String result = "Row inserted correctly";
    	ObjectNode json = mapper.createObjectNode();
        StringBuilder privateKeyBuilder = new StringBuilder();
        StringBuilder publicKeyBuilder = new StringBuilder();
        StringBuilder certificateBuilder = new StringBuilder();
        try(Reader privateKeyReader = new BufferedReader(new InputStreamReader
                (privateKeyInputStream, StandardCharsets.UTF_8));
        	Reader publicKeyReader = new BufferedReader(new InputStreamReader
                        (publicKeyInputStream, StandardCharsets.UTF_8));
        	Reader certificateReader = new BufferedReader(new InputStreamReader
                        (certificateInputStream, StandardCharsets.UTF_8))) 
        {
        	int c = 0;
            while ((c = privateKeyReader.read()) != -1) {
            	privateKeyBuilder.append((char) c);
            }
            c = 0;
            while ((c = publicKeyReader.read()) != -1) {
            	publicKeyBuilder.append((char) c);
            }
            c = 0;
            while ((c = certificateReader.read()) != -1) {
            	certificateBuilder.append((char) c);
            }
            String privateKey = "", publicKey = "", certificate = "";
            String privateKeyFromInput = (!(privateKeyFromInput = privateKeyBuilder.toString()).equals("null")) ? privateKeyFromInput : "";
            String publicKeyFromInput = (!(publicKeyFromInput = publicKeyBuilder.toString()).equals("null")) ? publicKeyFromInput : "";
            String certificateFromInput = (!(certificateFromInput = certificateBuilder.toString()).equals("null")) ? certificateFromInput : "";
            ModiPKMapping certificateMetadata = modiPrivateKey.getPrivateKey(appUUID);
            if(certificateMetadata.isEnabled() != null && certificateMetadata.isEnabled())
            {
            	int numOfRows = modiPrivateKey.updatePrivateKey(appUUID);
                log.info(numOfRows + " row/s updated");
                privateKey = !(privateKeyFromInput.equals("")) ? privateKeyFromInput : certificateMetadata.getPrivkey();
                publicKey = !(publicKeyFromInput.equals("")) ? publicKeyFromInput : certificateMetadata.getPublickey();
                certificate = !(certificateFromInput.equals("")) ? certificateFromInput : certificateMetadata.getCertificate();
                modiPkMapping = modiPrivateKey.insertPrivateKey(appUUID, modiPkMapping.getTyp(), modiPkMapping.getIss(), modiPkMapping.getSub(), modiPkMapping.getAud(), modiPkMapping.getKid(), privateKey, publicKey, certificate, true);
            }
            else
            	modiPkMapping = modiPrivateKey.insertPrivateKey(appUUID, modiPkMapping.getTyp(), modiPkMapping.getIss(), modiPkMapping.getSub(), modiPkMapping.getAud(), modiPkMapping.getKid(), privateKeyFromInput, publicKeyFromInput, certificateFromInput, true);
        	json.put("result", result);
		} catch (APIManagementException | APIManagerDatabaseException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		} 
        catch(IOException e)
        {
        	RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
        }
		
        return Response.status(200).entity(json).build();
    }
    
    @POST
    @Consumes({"multipart/form-data"})
    @Produces({"application/json"})
    @Path("certificateSOAPOutbound/{appUUID}")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificato inserito.", response = ObjectNode.class)
    })
    public Response insertCertificateSOAPOutboundModi(@PathParam("appUUID") String appUUID, @Multipart("modiPrivKey") InputStream privateKeyInputStream, @Multipart("modiCert") InputStream certificateInputStream, @Multipart("json") ModiPKMapping modiPkMapping) {
    	log.info("###insertCertificateSOAPOutboundModi###");
    	String result = "Row inserted correctly";
    	ObjectNode json = mapper.createObjectNode();
        StringBuilder privateKeyBuilder = new StringBuilder();
        StringBuilder certificateBuilder = new StringBuilder();
        try(Reader privateKeyReader = new BufferedReader(new InputStreamReader
                (privateKeyInputStream, StandardCharsets.UTF_8));
        	Reader certificateReader = new BufferedReader(new InputStreamReader
                        (certificateInputStream, StandardCharsets.UTF_8)))  
        {
        	int c = 0;
            while ((c = privateKeyReader.read()) != -1) {
            	privateKeyBuilder.append((char) c);
            }
            c = 0;
            while ((c = certificateReader.read()) != -1) {
            	certificateBuilder.append((char) c);
            }
            String privateKey = "", certificate = "";
            String privateKeyFromInput = (!(privateKeyFromInput = privateKeyBuilder.toString()).equals("null")) ? privateKeyFromInput : "";
            String certificateFromInput = (!(certificateFromInput = certificateBuilder.toString()).equals("null")) ? certificateFromInput : "";
            ModiPKMapping certificateMetadata = modiPrivateKey.getPrivateKeySOAP(appUUID);
            if(certificateMetadata.isEnabled() != null && certificateMetadata.isEnabled())
            {
            	int numOfRows = modiPrivateKey.updatePrivateKeySOAP(appUUID);
                log.info(numOfRows + " row/s updated");
                privateKey = !(privateKeyFromInput.equals("")) ? privateKeyFromInput : certificateMetadata.getPrivkey();
                certificate = !(certificateFromInput.equals("")) ? certificateFromInput : certificateMetadata.getCertificate();
                modiPkMapping = modiPrivateKey.insertPrivateKeySOAP(appUUID, modiPkMapping.getWsaddressingTo(), privateKey, certificate, true);
            }
            else
            	modiPkMapping = modiPrivateKey.insertPrivateKeySOAP(appUUID, modiPkMapping.getWsaddressingTo(), privateKeyFromInput, certificateFromInput, true);
        	json.put("result", result);
		} catch (APIManagementException | APIManagerDatabaseException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		}
        catch(IOException e)
        {
        	RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
        }
		
        return Response.status(200).entity(json).build();
    }
    
    @POST
    @Consumes({"multipart/form-data"})
    @Produces({"application/json"})
    @Path("certificateOutboundPdnd/{appUUID}")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificato inserito.", response = ObjectNode.class)
    })
    public Response insertCertificateOutboundPdnd(@PathParam("appUUID") String appUUID, @Multipart("pdndPrivKey") InputStream privateKeyInputStream, @Multipart("json") PdndPKMapping pdndPKMapping) {
    	log.info("###insertCertificateOutboundPdnd###");
    	String result = "Row inserted correctly";
    	ObjectNode json = mapper.createObjectNode();
        StringBuilder privateKeyBuilder = new StringBuilder();
        try(Reader privateKeyReader = new BufferedReader(new InputStreamReader
                (privateKeyInputStream, StandardCharsets.UTF_8))) 
        {
        	int c = 0;
            while ((c = privateKeyReader.read()) != -1) {
            	privateKeyBuilder.append((char) c);
            }
            String privateKey = "";
            String privateKeyFromInput = (!(privateKeyFromInput = privateKeyBuilder.toString()).equals("null")) ? privateKeyFromInput : "";
            String keyType = (StringUtils.isNotBlank(pdndPKMapping.getKeyType()) ? pdndPKMapping.getKeyType() : "PRODUCTION");
            PdndPKMapping certificateMetadata = pdndPrivateKey.getPrivateKey(appUUID, keyType);
            if(certificateMetadata.isEnabled() != null && certificateMetadata.isEnabled())
            {
            	int numOfRows = pdndPrivateKey.updatePrivateKey(appUUID);
                log.info(numOfRows + " row/s updated");
                privateKey = !(privateKeyFromInput.equals("")) ? privateKeyFromInput : certificateMetadata.getPrivkey();
                pdndPKMapping = pdndPrivateKey.insertPrivateKey(appUUID, keyType, pdndPKMapping.getUri(), pdndPKMapping.getKid(), pdndPKMapping.getAlg(), pdndPKMapping.getTyp(), pdndPKMapping.getIss(), pdndPKMapping.getSub(), pdndPKMapping.getAud(), "", pdndPKMapping.getClientId(), pdndPKMapping.getScope(), privateKey, true);
            }
            else
            	pdndPKMapping = pdndPrivateKey.insertPrivateKey(appUUID, keyType, pdndPKMapping.getUri(), pdndPKMapping.getKid(), pdndPKMapping.getAlg(), pdndPKMapping.getTyp(), pdndPKMapping.getIss(), pdndPKMapping.getSub(), pdndPKMapping.getAud(), "", pdndPKMapping.getClientId(), pdndPKMapping.getScope(), privateKeyFromInput, true);
        	json.put("result", result);
		} catch (APIManagementException | APIManagerDatabaseException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		}
        catch(IOException e)
        {
        	RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
        }
		
        return Response.status(200).entity(json).build();
    }
    
    @POST
    @Consumes({"application/json"})
    @Produces({"application/json"})
    @Path("subscriptionDetails/{subscriptionUUID}")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Mapping PDND creato.", response = ObjectNode.class)
    })
    public Response insertSubscriptionMappingPdnd(@PathParam("subscriptionUUID") String subscriptionUUID, PdndPKMapping pdndPK) {
    	log.info("###insertSubscriptionMappingPdnd###");
    	String result = "";
    	ObjectNode json = mapper.createObjectNode();
    	try {
    		int numOfRows = modiCertificate.updateSubscriptionMapping(subscriptionUUID);
    		log.info(numOfRows + " row/s updated");
			result = modiCertificate.addSubscriptionMapping(subscriptionUUID, pdndPK.getAud(), pdndPK.getIss(), pdndPK.getPurposeId());
			json.put("result", result);
		} catch (APIManagementException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		} catch (APIManagerDatabaseException e) {
			RestApiUtil.handleInternalServerError(e.getMessage(), (Throwable)e, log);
		}
		
        return Response.status(200).entity(json).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("certificatesInbound")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificati.", response = List.class)
    })
    public Response getCertificatesInboundModi(@QueryParam("applicationUUID") String applicationUUID) {
    	log.info("####getCertificatesInboundModi###");
        List<CertAppMapping> listOfCertificates = modiCertificate.getCertificates(applicationUUID);
        if(listOfCertificates.size() == 0)
        	RestApiUtil.handleResourceNotFoundError("Nessun certificato presente per l'application: " + applicationUUID, log);
        return Response.status(200).entity(listOfCertificates.get(0)).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("certificatesSOAPInbound")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificati.", response = List.class)
    })
    public Response getCertificatesSOAPInboundModi(@QueryParam("applicationUUID") String applicationUUID) {
    	log.info("####getCertificatesSOAPInboundModi###");
        List<CertAppMapping> listOfCertificates = modiCertificate.getCertificatesSOAP(applicationUUID);
        if(listOfCertificates.size() == 0)
        	RestApiUtil.handleResourceNotFoundError("Nessun certificato presente per l'application: " + applicationUUID, log);
        return Response.status(200).entity(listOfCertificates.get(0)).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("certificatesOutboundModi")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Chiave privata ModI.", response = ModiPKMapping.class),
            @ApiResponse(code = 500, message = "Errore generico.")
    })
    public Response getCertificatesOutboundModi(@QueryParam("applicationUUID") String applicationUUID) {
    	log.info("####getCertificatesOutboundModi###");
        Response response = Response.status(Status.NOT_FOUND).entity("certificatesOutboundModi").build();
        try {
            ModiPKMapping modiMetadata = modiPrivateKey.getPrivateKey(applicationUUID);
            if(modiMetadata.isEnabled() == null)
                RestApiUtil.handleResourceNotFoundError("Chiave privata ModI non trovata.", log);
            response = Response.status(Status.OK).entity(modiMetadata).build();
        } catch (APIManagementException e) {
                RestApiUtil.handleInternalServerError(e.getMessage(), e, log);
        }
        return response;
    }
    
    @GET
    @Produces({"application/json"})
    @Path("certificatesSOAPOutbound")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificato.", response = ModiPKMapping.class)
    })
    public Response getCertificatesSOAPOutboundModi(@QueryParam("applicationUUID") String applicationUUID) {
    	log.info("####getCertificatesSOAPOutboundModi###");
    	ModiPKMapping modiMetadata = modiPrivateKey.getPrivateKeySOAP(applicationUUID);
    	if(modiMetadata.isEnabled() == null)
        	RestApiUtil.handleResourceNotFoundError("No valid certificate metadata found for the specified application", log);
        return Response.status(200).entity(modiMetadata).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("certificatesOutboundPdnd")
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Chiave privata PDND.", response = PdndPKMapping.class),
        @ApiResponse(code = 500, message = "Errore generico.")
})
    public Response getCertificatesOutboundPdnd(@QueryParam("applicationUUID") String applicationUUID) {
    	log.info("####getCertificatesOutboundPdnd###");
        Response response = Response.status(Status.NOT_FOUND).entity("certificatesOutboundPdnd").build();
        try {
    	    PdndPKMapping pdndMetadata = pdndPrivateKey.getPrivateKey(applicationUUID);
    	    if(pdndMetadata.isEnabled() == null)
        	    RestApiUtil.handleResourceNotFoundError("Chiave privata PDND non trovata.", log);
            response = Response.status(Status.OK).entity(pdndMetadata).build();
        } catch (APIManagementException e) {
            RestApiUtil.handleInternalServerError(e.getMessage(), e, log);
        }
        return response;
    }
    
    @GET
    @Produces({"application/json"})
    @Path("subscriptionDetails")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Sottoscrizione.", response = PdndPKMapping.class)
    })
    public Response getSubscriptionDetails(@QueryParam("subscriptionUUID") String subscriptionUUID) {
    	log.info("####getSubscriptionDetails###");
    	PdndPKMapping pdndPK = null;
		try {
			pdndPK = modiCertificate.getSubscriptionDetails(subscriptionUUID);
			if(pdndPK.isEnabled() == null)
	        	RestApiUtil.handleResourceNotFoundError("No details found for the specified subscription uuid", log);
		} catch (APIManagementException e) {
			log.error(e);
		}
        return Response.status(200).entity(pdndPK).build();
    }
    
    @DELETE
    @Path("certificate/{tableName}/{clauseName}/{clauseValue}")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Certificato rimosso.")
    })
    public Response deleteCertificate(@PathParam("tableName") String tableName, @PathParam("clauseName") String clauseName, @PathParam("clauseValue") String clauseValue) {
    	String DEL_SQL =
    			"DELETE " +
                        " FROM " +
                        tableName +
                        " WHERE " +
                        clauseName +" = ? ";

        try (Connection conn = ModiDBUtil.getConnection();
             PreparedStatement ps =
                     conn.prepareStatement(DEL_SQL)) {

            ps.setString(1, clauseValue);

            int numOfDelRows = ps.executeUpdate();
            log.info("Number of deleted rows: "+numOfDelRows);
            	
        } catch (SQLException e) {
            log.error("Error in deleting certificate for the application : " + clauseValue, e);
        }
        return Response.status(200).entity("Deletetion Successful").build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("privateKeyByConsumerKeyForPdnd")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Chiave privata PDND.", response = PdndPKMapping.class),
            @ApiResponse(code = 500, message = "Errore generico.")
    })
    public Response getPrivateKeyByConsumerKeyForPdnd(@QueryParam("consumerKey") String consumerKey) {
    	log.info("####privateKeyByConsumerKeyForPdnd###");
        Response response = null;
        try {
            PdndPKMapping pdndPKMapping = pdndPrivateKey.getPrivateKeyByConsumerKey(consumerKey);
            if(pdndPKMapping.isEnabled() == null)
                 RestApiUtil.handleResourceNotFoundError("No details found for the specified consumer key", log);
            response = Response.status(200).entity(pdndPKMapping).build();
        } catch (APIManagementException e) {
            log.error("Recupero chiave privata PDND.", e);
            response = Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
        return response;
    }
    
    @GET
    @Produces({"application/json"})
    @Path("privateKeyByConsumerKeyForSOAP")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificati.", response = ModiPKMapping.class)
    })
    public Response getPrivateKeyByConsumerKeyForSOAP(@QueryParam("consumerKey") String consumerKey) {
    	log.info("####privateKeyByConsumerKeyForSOAP###");
    	ModiPKMapping modiPkMappingSOAP = modiPrivateKey.getPrivateKeyByConsumerKeySOAP(consumerKey);
    	if(modiPkMappingSOAP.isEnabled() == null)
        	RestApiUtil.handleResourceNotFoundError("No details found for the specified consumer key", log);
        return Response.status(200).entity(modiPkMappingSOAP).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("privateKeyByConsumerKeyForModi")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Chiave privata ModI.", response = ModiPKMapping.class),
            @ApiResponse(code = 500, message = "Errore generico.")
    })
    public Response getPrivateKeyByConsumerKeyForModi(@QueryParam("consumerKey") String consumerKey) {
    	log.info("####privateKeyByConsumerKeyForModi###");
        Response response = Response.status(Status.NOT_FOUND).entity("privateKeyByConsumerKeyForModi").build();

        try {
            ModiPKMapping modiPkMapping = modiPrivateKey.getPrivateKeyByConsumerKey(consumerKey);
            if(modiPkMapping.isEnabled() == null)
                RestApiUtil.handleResourceNotFoundError("Chiave privata ModI non trovata.", log);
            response = Response.status(Status.OK).entity(modiPkMapping).build();
        } catch (APIManagementException e) {
            log.error("Recupero chiave privata ModI.", e);
            response = Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
        return response;
    }
    
    @GET
    @Produces({"application/json"})
    @Path("aliasWithThumbprint")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificati.", response = ModiPKMapping.class)
    })
    public Response getAliasWithThumbprint(@QueryParam("thumbprint") String thumbprint) {
    	log.info("####aliasWithThumbprint###");
    	CertAppMapping cam = modiCertificate.getAliasWithThumbprint(thumbprint);
    	if(cam == null)
        	RestApiUtil.handleResourceNotFoundError("No details found for the specified thumbprint", log);
        return Response.status(200).entity(cam).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("certificateSOAP")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificati.", response = CertAppMapping.class)
    })
    public Response getCertificateSOAP(@QueryParam("firstKeyIdentifier") String firstKeyIdentifier, @QueryParam("secondKeyIdentifier") String secondKeyIdentifier) {
    	log.info("####certificateSOAP###");
    	CertAppMapping cam = modiCertificate.getCertificateSOAP(firstKeyIdentifier.replaceAll("\\s", ""), secondKeyIdentifier.replaceAll("\\s", ""));
    	if(cam == null)
        	RestApiUtil.handleResourceNotFoundError("No details found for the specified key identifiers", log);
        return Response.status(200).entity(cam).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("applicationUUIDByKid")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Application UUID", response = String.class)
    })
    public Response getApplicationUUIDByKid(@QueryParam("kidPdndApi") String kidPdndApi) {
    	log.info("####applicationUUIDByKid###");
    	String applicationUUID = modiCertificate.getApplicationUUIDByKid(kidPdndApi);
    	if(applicationUUID.equals(""))
    		log.error("No application found for the specified kid");
        return Response.status(200).entity(applicationUUID).build();
    }
    
    @GET
    @Produces({"application/json"})
    @Path("cacheConfigurations")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Cache Configurations", response = Map.class)
    })
    public Response getCacheConfigurations() {
    	log.info("####cacheConfigurations###");
    	Map<String, Object> cacheConfigurationsList = new HashMap<String, Object>();
    	cacheConfigurationsList.put("enabledCache", isEnabledCache());
    	cacheConfigurationsList.put("expiryTimeInSecondsCache", getExpiryTimeInSecondsCache());
        return Response.status(200).entity(cacheConfigurationsList).build();
    }

    public boolean isEnabledCache() {
		return enabledCache;
	}

	public void setEnabledCache(boolean enabledCache) {
		this.enabledCache = enabledCache;
	}

    public String getExpiryTimeInSecondsCache() {
		return expiryTimeInSecondsCache;
	}

	public void setExpiryTimeInSecondsCache(String expiryTimeInSecondsCache) {
		this.expiryTimeInSecondsCache = expiryTimeInSecondsCache;
	}

}
