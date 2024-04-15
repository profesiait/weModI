package it.profesia.carbon.apimgt.gateway.handlers.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.apache.axis2.engine.AxisConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.utils.CarbonUtils;

public class APIUtilCustom {
	
	private static final Log log = LogFactory.getLog(APIUtilCustom.class);
	
	 public static HttpClient getHttpClient(int port, String protocol) {
		 
		 APIManagerConfiguration configuration = ServiceReferenceHolder.getInstance().
	                getAPIManagerConfigurationService().getAPIManagerConfiguration();
		 
		 	String proxyEnabled = configuration.getFirstProperty("ProxyConfig.Enable");
		 	log.info("proxyEnabled: "+proxyEnabled);
	        String proxyHost = configuration.getFirstProperty("ProxyConfig.Host");
	        log.info("proxyHost: "+proxyHost);
	        String proxyPort = configuration.getFirstProperty("ProxyConfig.Port");
	        log.info("proxyPort: "+proxyPort);
	        String proxyUsername = "";
	        String proxyPassword = "";
	        String nonProxyHosts = configuration.getFirstProperty("ProxyConfig.NonProxyHosts");
	        log.info("nonProxyHosts: "+nonProxyHosts);
	        String proxyProtocol = configuration.getFirstProperty("ProxyConfig.Protocol");
	        log.info("proxyProtocol: "+proxyProtocol);
		 

	        /*String maxTotal = configuration
	                .getFirstProperty(APIConstants.HTTP_CLIENT_MAX_TOTAL);
	        String defaultMaxPerRoute = configuration
	                .getFirstProperty(APIConstants.HTTP_CLIENT_DEFAULT_MAX_PER_ROUTE);*/
	        
		 	/*String proxyEnabled = "true";
	        String proxyHost = "proxy.preit.aws.vip";
	        String proxyPort = "3128";
	        String proxyUsername = "";
	        String proxyPassword = "";
	        String nonProxyHosts = "localhost|10\\..*|.*\\.local|.*\\.integrazione\\.lispa\\.it|.*\\.aws\\.vm|.*\\.aws\\.vip";
	        String proxyProtocol = "http";*/

	        if (proxyProtocol != null) {
	            protocol = proxyProtocol;
	        }

	        PoolingHttpClientConnectionManager pool = null;
	        try {
	            pool = getPoolingHttpClientConnectionManager(protocol);
	        } catch (APIManagementException e) {
	            log.error("Error while getting http client connection manager", e);
	        }
	        /*pool.setMaxTotal(Integer.parseInt(maxTotal));
	        pool.setDefaultMaxPerRoute(Integer.parseInt(defaultMaxPerRoute));*/

	        RequestConfig params = RequestConfig.custom().build();
	        HttpClientBuilder clientBuilder = HttpClients.custom().setConnectionManager(pool)
	                .setDefaultRequestConfig(params);

	        if (Boolean.parseBoolean(proxyEnabled)) {
	            HttpHost host = new HttpHost(proxyHost, Integer.parseInt(proxyPort), protocol);
	            DefaultProxyRoutePlanner routePlanner;
	            /*if (!StringUtils.isBlank(nonProxyHosts)) {
	                routePlanner = new ExtendedProxyRoutePlanner(host, configuration);
	            } else {
	                routePlanner = new DefaultProxyRoutePlanner(host);
	            }*/
	            routePlanner = new DefaultProxyRoutePlanner(host);
	            clientBuilder = clientBuilder.setRoutePlanner(routePlanner);
	            if (!StringUtils.isBlank(proxyUsername) && !StringUtils.isBlank(proxyPassword)) {
	                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
	                credentialsProvider.setCredentials(new AuthScope(proxyHost, Integer.parseInt(proxyPort)),
	                        new UsernamePasswordCredentials(proxyUsername, proxyPassword));
	                clientBuilder = clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
	            }
	        }
	        return clientBuilder.build();
	    }
	 
	 private static PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager(String protocol)
	            throws APIManagementException {

	        PoolingHttpClientConnectionManager poolManager;
	        if (APIConstants.HTTPS_PROTOCOL.equals(protocol)) {
	            SSLConnectionSocketFactory socketFactory = createSocketFactory();
	            org.apache.http.config.Registry<ConnectionSocketFactory> socketFactoryRegistry =
	                    RegistryBuilder.<ConnectionSocketFactory>create()
	                            .register(APIConstants.HTTPS_PROTOCOL, socketFactory).build();
	            poolManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
	        } else {
	            poolManager = new PoolingHttpClientConnectionManager();
	        }
	        //poolManager = new PoolingHttpClientConnectionManager();
	        return poolManager;
	    }
	 
	 private static SSLConnectionSocketFactory createSocketFactory() throws APIManagementException {
	        SSLContext sslContext;
	        KeyStore keyStore;
	        String keyStorePath = null;
	        String keyStorePassword;

	        try {
	        	
	        	keyStorePath = CarbonUtils.getServerConfiguration().getFirstProperty("Security.KeyStore.Location");
	        	log.info("keyStorePath: "+keyStorePath);
	            keyStorePassword = CarbonUtils.getServerConfiguration()
	                    .getFirstProperty("Security.KeyStore.Password");
	            log.info("keyStorePassword: "+keyStorePassword);
	            keyStore = KeyStore.getInstance("JKS");
	            log.info("keyStore type: "+keyStore.getType());
	            keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
	        	
	            sslContext = SSLContexts.custom().loadTrustMaterial(keyStore).build();

	            X509HostnameVerifier hostnameVerifier;
	            String hostnameVerifierOption = System.getProperty("httpclient.hostnameVerifier");
	            log.info("hostnameVerifierOption: "+hostnameVerifierOption);

	            if ("AllowAll".equalsIgnoreCase(hostnameVerifierOption)) {
	                hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
	            } else if ("Strict".equalsIgnoreCase(hostnameVerifierOption)) {
	                hostnameVerifier = SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
	            } else {
	                hostnameVerifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
	            }
	            log.info("hostnameVerifier: "+hostnameVerifier);

	            return new SSLConnectionSocketFactory(sslContext, hostnameVerifier);
	        } catch (KeyStoreException e) {
	            handleException("Failed to read from Key Store", e); 
	        }
	        catch (CertificateException e) {
	            handleException("Failed to read Certificate", e);
	        }
	        catch (IOException e) {
	            handleException("Key Store not found in " + keyStorePath, e);
	        }
	        catch (NoSuchAlgorithmException e) {
	            handleException("Failed to load Key Store from " + keyStorePath, e);
	        } catch (KeyManagementException e) {
	            handleException("Failed to load key from" + keyStorePath, e);
	        }

	        return null;
	    }
	 
	 public static void handleException(String msg, Throwable t) throws APIManagementException {

	        log.error(msg, t);
	        throw new APIManagementException(msg, t);
	    }

}
