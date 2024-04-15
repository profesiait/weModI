package it.profesia.carbon.apimgt.subscriptionApi;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import it.profesia.carbon.apimgt.subscription.dao.CertAppMapping;
import it.profesia.carbon.apimgt.subscription.ModiCertificate;
import it.profesia.carbon.apimgt.subscription.ModiCertificateImpl;
import it.profesia.carbon.apimgt.subscription.dao.ModiPKMapping;
import it.profesia.carbon.apimgt.subscription.fruizione.ModiPrivateKey;
import it.profesia.carbon.apimgt.subscription.fruizione.ModiPrivateKeyImpl;
import it.profesia.carbon.apimgt.subscription.dao.PdndPKMapping;
import it.profesia.carbon.apimgt.subscription.fruizione.PdndPrivateKey;
import it.profesia.carbon.apimgt.subscription.fruizione.PdndPrivateKeyImpl;

import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;


@Path("/subscriptionservice")
public class ModISubscriptionAPI {
	
	private boolean enabledCache;
	private String expiryTimeInSecondsCache;

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

	private static final Log log = LogFactory.getLog(ModISubscriptionAPI.class);

	ModiCertificate modiCertificate = new ModiCertificateImpl();
	ModiPrivateKey modiPrivateKey = new ModiPrivateKeyImpl();
	PdndPrivateKey pdndPrivateKey = new PdndPrivateKeyImpl();

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
            @ApiResponse(code = 200, message = "Certificato.", response = ModiPKMapping.class)
    })
    public Response getCertificatesOutboundModi(@QueryParam("applicationUUID") String applicationUUID) {
    	log.info("####getCertificatesOutboundModi###");
    	ModiPKMapping modiMetadata = modiPrivateKey.getPrivateKey(applicationUUID);
    	if(modiMetadata.isEnabled() == null)
        	RestApiUtil.handleResourceNotFoundError("No valid certificate metadata found for the specified application", log);
        return Response.status(200).entity(modiMetadata).build();
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
            @ApiResponse(code = 200, message = "Certificato.", response = PdndPKMapping.class)
    })
    public Response getCertificatesOutboundPdnd(@QueryParam("applicationUUID") String applicationUUID) {
    	log.info("####getCertificatesOutboundPdnd###");
    	PdndPKMapping pdndMetadata = pdndPrivateKey.getPrivateKey(applicationUUID);
    	if(pdndMetadata.isEnabled() == null)
        	RestApiUtil.handleResourceNotFoundError("No valid certificate metadata found for the specified application", log);
        return Response.status(200).entity(pdndMetadata).build();
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

    @GET
    @Produces({"application/json"})
    @Path("privateKeyByConsumerKeyForPdnd")
    @ApiResponses(value = { 
            @ApiResponse(code = 200, message = "Certificati.", response = PdndPKMapping.class)
    })
    public Response getPrivateKeyByConsumerKeyForPdnd(@QueryParam("consumerKey") String consumerKey) {
    	log.info("####privateKeyByConsumerKeyForPdnd###");
    	PdndPKMapping pdndPKMapping = pdndPrivateKey.getPrivateKeyByConsumerKey(consumerKey);
    	if(pdndPKMapping.isEnabled() == null)
        	RestApiUtil.handleResourceNotFoundError("No details found for the specified consumer key", log);
        return Response.status(200).entity(pdndPKMapping).build();
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
            @ApiResponse(code = 200, message = "Certificati.", response = ModiPKMapping.class)
    })
    public Response getPrivateKeyByConsumerKeyForModi(@QueryParam("consumerKey") String consumerKey) {
    	log.info("####privateKeyByConsumerKeyForModi###");
    	ModiPKMapping modiPkMapping = modiPrivateKey.getPrivateKeyByConsumerKey(consumerKey);
    	if(modiPkMapping.isEnabled() == null)
        	RestApiUtil.handleResourceNotFoundError("No details found for the specified consumer key", log);
        return Response.status(200).entity(modiPkMapping).build();
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

}
