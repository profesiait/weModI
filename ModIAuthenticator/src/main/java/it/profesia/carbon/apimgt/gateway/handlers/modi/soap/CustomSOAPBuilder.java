package it.profesia.carbon.apimgt.gateway.handlers.modi.soap;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

import javax.xml.stream.XMLStreamException;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.OMNodeEx;
import org.apache.axiom.om.impl.builder.StAXBuilder;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.util.StAXParserConfiguration;
import org.apache.axiom.om.util.StAXUtils;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.builder.Builder;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CustomSOAPBuilder implements Builder{
	
	private static final Log log = LogFactory.getLog(CustomSOAPBuilder.class);
	
    public OMElement processDocument(InputStream inputStream, String contentType, MessageContext messageContext) throws AxisFault {
    	SOAPEnvelope soapEnvelope = null;
    	SOAPFactory soapFactory = null;

        PushbackInputStream pushbackInputStream = new PushbackInputStream(inputStream);

        try {
            int byteVal = pushbackInputStream.read();
            if (byteVal != -1) {
                pushbackInputStream.unread(byteVal);
                
            	/*OMXMLParserWrapper builder = OMXMLBuilderFactory.createSOAPModelBuilder(pushbackInputStream,
                		(String) messageContext.getProperty(Constants.Configuration.CHARACTER_SET_ENCODING));
                soapEnvelope = (SOAPEnvelope) builder.getDocumentElement();*/
              
                //SOAPFactory soapFactory = OMAbstractFactory.getSOAP11Factory();
                
                if (contentType != null) {
                    if (contentType.indexOf("application/soap+xml") > -1) {
                    	log.info("SOAP 1.2");
                        soapFactory = OMAbstractFactory.getSOAP12Factory();
                    } else if (contentType.indexOf("text/xml") > -1) {
                    	log.info("SOAP 1.1");
                        soapFactory = OMAbstractFactory.getSOAP11Factory();
                    }
                }
                
            	soapEnvelope = soapFactory.getDefaultEnvelope();
            	javax.xml.stream.XMLStreamReader xmlReader = StAXUtils.createXMLStreamReader(StAXParserConfiguration.SOAP,
                        pushbackInputStream, (String) messageContext.getProperty(Constants.Configuration.CHARACTER_SET_ENCODING));
                StAXBuilder builder = new StAXOMBuilder(xmlReader);
                OMNodeEx documentElement = (OMNodeEx) builder.getDocumentElement();
                documentElement.setParent(null);
                SOAPBody body = soapEnvelope.getBody();
                body.addChild(documentElement);
            }
        } catch (IOException e) {
        	throw AxisFault.makeFault(e);
        } catch (XMLStreamException e) {
        	throw AxisFault.makeFault(e);
        }

        return soapEnvelope;
    }
}
