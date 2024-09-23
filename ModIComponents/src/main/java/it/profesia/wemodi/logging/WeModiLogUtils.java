package it.profesia.wemodi.logging;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.ThreadContext;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.apimgt.impl.APIConstants;

public abstract class WeModiLogUtils {
	
	protected static final Log log = LogFactory.getLog(WeModiLogUtils.class);
	public static final String FRUIZIONE_INIT_START = "Fruizione ModI init - Inizio";
	public static final String FRUIZIONE_INIT_FINISH = "Fruizione ModI init - Fine";
	public static final String FRUIZIONE_START = "Fruizione ModI - Inizio";
	public static final String FRUIZIONE_FINISH = "Fruizione ModI - Fine";
	public static final String EROGAZIONE_START = "Erogazione ModI - Inizio";
	public static final String EROGAZIONE_FINISH = "Erogazione ModI - Fine";
	public static final String PDND_GET_METADATA_START =  "Recupero metadati PDND - Inizio";
	public static final String PDND_GET_METADATA_FINISH = "Recupero metadati PDND - Fine";
	public static final String ACCESS_TOKEN_PDND = "Ottenuto voucher PDND";
	public static final String MODI_GET_METADATA_START =  "Recupero metadati ModI - Inizio";
	public static final String MODI_GET_METADATA_FINISH =  "Recupero metadati ModI - Fine";
	public static final String JWT_MODI = "Generato token ModI";
	public static final String PDND_ENABLED = "PDND abilitato";
	public static final String PDND_TOKEN_REQUEST_START = "Richiesta voucher PDND - Inizio";
	public static final String PDND_TOKEN_REQUEST_FINISH = "Richiesta voucher PDND - Fine";
	public static final String MODI_ENABLED = "ModI enabled";
	public static final String MODI_TOKEN_GENERATION_START = "Generazione token ModI - Inizio";
	public static final String MODI_TOKEN_GENERATION_FINISH = "Generazione token ModI - Fine";
	public static final String PDND_INIT_METADATA_START = "Recupero metadati PDND - Inizio";
	public static final String PDND_INIT_METADATA_FINISH = "Recupero metadati PDND - Fine";
	public static final String MODI_INIT_METADATA_START = "Recupero metadati ModI - Inizio";
	public static final String MODI_INIT_METADATA_FINISH = "Recupero metadati ModI - Fine";
	public static final String EROGAZIONE_AUTH_ERROR = "Authentication weModI fallita";
	public static final String JWS_AUDIT_START = "Generazione JWS audit - Inizio";
	public static final String JWS_AUDIT_FINISH = "Generazione JWS audit - Fine";

	/**
	 * Recupera i Correlation ID message context
	 * 
	 * @param context Message context
	 */
	public static void initialize(MessageContext context) {
		String correlationID = "";

		org.apache.axis2.context.MessageContext axis2MessageCtx = ((Axis2MessageContext) context).getAxis2MessageContext();

		if (axis2MessageCtx == null) {
        	log.warn("Cannot get Axis2 Message Context.\n\t" + context);
        	return;
        }

		Map transportHeaders = (Map) axis2MessageCtx.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
		if(transportHeaders != null) {

			correlationID = (String) transportHeaders.get(APIConstants.ACTIVITY_ID);
		}
		ThreadContext.put("correlationID", correlationID);

	}

    /**
     * Gets a message for authentication failure
     *
     * @param messageContext Message context
     * @return Message
     */
    public static String AuthFailure(org.apache.synapse.MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MsgContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        String statusCode = String.valueOf(axis2MsgContext.getProperty("HTTP_SC"));

    	String errorCode = "", errorMsg = "";
    	errorCode = String.valueOf(messageContext.getProperty(SynapseConstants.ERROR_CODE));
    	errorMsg = (String) messageContext.getProperty(SynapseConstants.ERROR_MESSAGE);
    	String details = errorCode + " " + errorMsg;

    	return "Autenticazione fallita\n\t" + "Codice: " + statusCode + "\n\t" + details;
    }

	public static void release() {
		ThreadContext.clearAll();
	}

}
