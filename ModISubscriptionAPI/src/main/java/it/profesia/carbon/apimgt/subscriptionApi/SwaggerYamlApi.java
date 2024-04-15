package it.profesia.carbon.apimgt.subscriptionApi;

import java.io.IOException;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Response;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.RESTAPICacheConfiguration;
import org.wso2.carbon.apimgt.impl.definitions.OAS3Parser;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@Path("/swagger.yaml")
@Consumes({"text/yaml"})
@Produces({"text/yaml"})
@Api(value = "/swagger.yaml", description = "the swagger.yaml API")
public class SwaggerYamlApi {
  private static final Log log = LogFactory.getLog(SwaggerYamlApi.class);
  
  private String openAPIDef = null;

@GET
  @Consumes({"text/yaml"})
  @Produces({"text/yaml"})
  @ApiOperation(value = "Get Swagger Definition", notes = "Get Swagger Definition of ModI Subscription API.", response = Void.class)
  @ApiResponses({@ApiResponse(code = 200, message = "OK.\nSwagger Definition is returned."), @ApiResponse(code = 304, message = "Not Modified.\nEmpty body because the client has already the latest version of the requested resource."), @ApiResponse(code = 406, message = "Not Acceptable.\nThe requested media type is not supported")})
  public Response swaggerYamlGet() throws APIManagementException {
    try {
      if (this.openAPIDef == null)
          if (this.openAPIDef == null) {
            String definition = IOUtils.toString(getClass().getResourceAsStream("/weModI-subscription.yaml"), "UTF-8");
            new OAS3Parser();
            this.openAPIDef = OAS3Parser.removeExamplesFromOpenAPI(definition);
          } 
      RESTAPICacheConfiguration restapiCacheConfiguration = APIUtil.getRESTAPICacheConfig();
      if (restapiCacheConfiguration.isCacheControlHeadersEnabled()) {
        CacheControl cacheControl = new CacheControl();
        cacheControl.setMaxAge(restapiCacheConfiguration.getCacheControlHeadersMaxAge());
        cacheControl.setPrivate(true);
        return Response.ok().entity(this.openAPIDef).cacheControl(cacheControl).build();
      } 
      return Response.ok().entity(this.openAPIDef).build();
    } catch (IOException e) {
      String errorMessage = "Error while retrieving the OAS of the ModI Subscription API";
      RestApiUtil.handleInternalServerError(errorMessage, e, log);
      return null;
    } 
  }
}
