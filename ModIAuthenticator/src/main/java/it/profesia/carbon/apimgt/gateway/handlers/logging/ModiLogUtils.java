package it.profesia.carbon.apimgt.gateway.handlers.logging;

import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.ThreadContext;
import org.apache.synapse.MessageContext;
import org.apache.synapse.api.ApiUtils;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.utils.GatewayUtils;
import org.wso2.carbon.apimgt.keymgt.model.entity.API;

import it.profesia.wemodi.logging.WeModiLogUtils;

public class ModiLogUtils extends WeModiLogUtils {

    /**
	 * Recupera i dati dal message context:
	 * <ul>
	 * <li>Correlation ID</li>
	 * <li>API</li>
	 * <li>API version</li>
	 * <li>Context</li>
	 * </ul>
	 * 
	 * @param context Message context
	 */
	public static void initialize(MessageContext context) {
        WeModiLogUtils.initialize(context);

		String apiId = "";
		String apiName = "";
		String apiContext = "";
		String apiVersion = "";
		String resourceName = "";

		log.debug("Initialization of Message Context");

        org.apache.axis2.context.MessageContext axis2MessageCtx =
                ((Axis2MessageContext) context).getAxis2MessageContext();
        if (axis2MessageCtx == null) {
        	log.warn("Cannot get Axis2 Message Context.\n\t" + context);
        	return;
        }

        @SuppressWarnings("rawtypes")
		Map transportHeaders = (Map) axis2MessageCtx.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
		if(transportHeaders != null) {

	        String path = ApiUtils.getFullRequestPath(context);
	        TreeMap<String, API> selectedApis = Utils.getSelectedAPIList(path, GatewayUtils.getTenantDomain());
			if (selectedApis.size() > 0) {
	            String selectedPath = selectedApis.firstKey();
	            API selectedApi = selectedApis.get(selectedPath);

	            apiId = selectedApi.getUuid();
	    		apiName = selectedApi.getApiName();
	    		apiVersion = selectedApi.getApiVersion();
	    		apiContext = selectedApi.getContext();
	    		String address = context.getTo().getAddress();
	            if (StringUtils.isNotBlank(address)) {
	                resourceName = address.replaceFirst(apiContext, "");
	            }
	            log.debug("ModI log metadata:\n\tapiId: "+ apiId +"\n\tapiName: " + apiName + "\n\tapiContext: " + apiContext + "\n\tresourceName:" + resourceName);
			} else {
				log.warn("Cannot retrieve API metadata for: " + path + "\n\t" + context);
				return;
			}
		} else {
			log.warn("Cannot retrieve Axis Transport Headers.\n\t" + axis2MessageCtx);
			return;
		}

        ThreadContext.put("apiId", apiId);
        ThreadContext.put("apiName", apiName);
        ThreadContext.put("apiVersion", apiVersion);
        ThreadContext.put("apiContext", apiContext);
        ThreadContext.put("resourceName", resourceName);
	}

}
