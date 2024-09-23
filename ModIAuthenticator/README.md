# Librerie weModI per la produzione e validazione dei JWT ModI e PDND


* [Prerequisiti](#prerequisiti)
* [Installazione](#installazione)
* [Configurazione istanza WSO2](#configurazione-istanza-wso2)
  * [Proxy](#proxy-opzionale)
  * [ModI - PDND application attributes](#modi---pdnd-application-attributes)
  * [Logger weModI](#logger-wemodi)
* [Generazione JWKS per test PDND](#generazione-jwks-per-test-pdnd)
* [ModI - PDND API properties](#modi---pdnd-api-properties)
* [Mediatore di autenticazione in fruizione](#mediatore-di-autenticazione-in-fruizione)
* [Handler di autorizzazione in erogazione](#handler-di-autorizzazione-in-erogazione)

## Prerequisiti
Richiede WSO2 API Manager 4.1 o superiore<br>

## Installazione
Per le configurazioni API Manager distribuito su diversi [profili](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/distributed-deployment/understanding-the-distributed-deployment-of-wso2-api-m/) deploiare questa libreria nel profilo Gateway di WSO2 API Manager. 

Compilare il [Multi-Project maven weModI](../README.md#compilazione), deploiare il jar nella directory lib ```cp target/it.profesia.wemodi.authenticator-<version>.jar <WSO2AM_HOME>/repository/components/lib/```

## Configurazione istanza WSO2
Una volta installata la libreria occorre configurare l'istanza WSO2 API Manager (profilo control-plane)

### Proxy (opzionale)

Aggiungere le seguenti configurazioni nel file `deployment.toml` dei profili Control Plane e Gateway:

> **Proxy configuration for the PassThrough transport**

> In the APIM server, the service/API invocation happens based on the PassThrough transport mechanism. If you need to configure the APIM server to connect to the backend services via a proxy server, it requires configuring HTTP proxy profiles by adding the relevant configurations in the deployment.toml file for each protocol (HTTP/HTTPS).

**HTTP**

```
[[transport.http.proxy_profile]]
target_hosts = ["example.com", ".*.sample.com"]
proxy_host = "localhost"
proxy_port = "3128"
proxy_username = "squidUser"
proxy_password = "password"
bypass_hosts = ["xxx.sample.com"]
```


**HTTPS**
```
[[transport.http.secured_proxy_profile]]
target_hosts = ["example.com", ".*.sample.com"]
proxy_host = "localhost"
proxy_port = "3128"
proxy_username = "squidUser"
proxy_password = "password"
bypass_hosts = ["xxx.sample.com"]
```

> ****

> **Proxy configuration for the HTTP Servlet transport - (non-blocking HTTP transport)**

> In APIM, the communication between internal components, external service calls (endpoint validation), and some of the mediator transport (OAuth mediator) happen based on the HTTP servlet transport mechanism. In order to configure a proxy for the HTTP Servlet transport, we need to add the following proxy configurations in the deployment.toml file.


```
[apim.proxy_config]
enable = true
host = "iahlproxy.logistics.corp"
port = "3128"
nonProxyHosts = "wso2am.*service|.*\\.logistics\\.corp|localhost"
protocol = "http"
```

### ModI - PDND application attributes
Aggiungere la configurazione nel file ```deployment.toml```:
```
[[apim.devportal.application_attributes]]
required=false
hidden=false
name="wemodi_connessione"
description="Valori ammessi: fruizione, erogazione"
```

### Logger weModI
Aggiungere le configurazioni per WEMODI_LOGFILE come specificato nel log4j2.properties sotto src/main/resources

Configurazione del file di log di destinazione:
```
# WEMODI_LOGFILE
appender.WEMODI_LOGFILE.type = RollingFile
appender.WEMODI_LOGFILE.name = WEMODI_LOGFILE
appender.WEMODI_LOGFILE.fileName = ${sys:carbon.home}/repository/logs/weModI.log
appender.WEMODI_LOGFILE.filePattern = ${sys:carbon.home}/repository/logs/weModI-%d{MM-dd-yyyy}-%i.log.gz
appender.WEMODI_LOGFILE.layout.type = PatternLayout
appender.WEMODI_LOGFILE.layout.pattern = TID: [%tenantId] [%appName] [%d] [%X{correlationID} %X{apiName} %X{apiVersion} %X{apiContext} %X{resourceName}] %5p {%c} - %m%ex%n
appender.WEMODI_LOGFILE.policies.type = Policies
appender.WEMODI_LOGFILE.policies.time.type = TimeBasedTriggeringPolicy
appender.WEMODI_LOGFILE.policies.time.interval = 1
appender.WEMODI_LOGFILE.policies.time.modulate = true
appender.WEMODI_LOGFILE.policies.size.type = SizeBasedTriggeringPolicy
appender.WEMODI_LOGFILE.policies.size.size = 100MB
appender.WEMODI_LOGFILE.strategy.type = DefaultRolloverStrategy
appender.WEMODI_LOGFILE.strategy.max = nomax
appender.WEMODI_LOGFILE.filter.threshold.type = ThresholdFilter
appender.WEMODI_LOGFILE.filter.threshold.level = TRACE
```
Le variabili `correlationID`, `apiName`, `apiVersion`, `apiContext` e `resourceName` vengono impostate all'interno degli handler ModI, inserire `WEMODI_LOGGER` nell'elenco degli `appenders`.

Configurare il logger `WEMODI`:

```
logger.WEMODI.name = it.profesia
logger.WEMODI.level = DEBUG
logger.WEMODI.appenderRef.WEMODI_LOGFILE.ref=WEMODI_LOGFILE
```
Il package `it.profesia` contiene tutte le classi ModI, inserire il logger `WEMODI` nell'elenco dei `loggers`.

## Generazione JWKS per test PDND
Per la generazione del JWKS, sarà necessaria la chiave pubblica, da estrarre dal certificato con il seguente comando:
```
openssl x509 -in certificate.pem -pubkey -noout
```
Utilizzare la chiave pubblica ottenuta per invocare il servizio presente a questo URL:
```
https://russelldavies.github.io/jwk-creator/
```
Il Key ID dovrà corrispondere al kid presente nel PDND JWT.

## ModI - PDND API properties
| FRUIZIONE  | VALORI | NOTE |
| ------------- | ------------- |------------- |
| pdnd_fruizione  | true, false  | Usata da sola o in combinazione con modi_fruizione |
| modi_fruizione  | true, false  | Usata da sola o in combinazione con pdnd_fruizione |
| id_auth_rest_01  | true, false  | Usata da sola o in combinazione con integrity_rest_01 |
| id_auth_rest_02  | true, false  | Usata da sola o in combinazione con integrity_rest_01 |
| integrity_rest_01  | true, false  | Usata in combinazione con id_auth_rest_02 o id_auth_rest_01 |
| integrity_rest_02  | true, false  | Richiede modi_fruizione settata a true |
| id_auth_soap_01  | true, false  | Usata da sola o in combinazione con integrity_soap_01 |
| id_auth_soap_02  | true, false  | Usata da sola o in combinazione con integrity_soap_01 |
| integrity_soap_01  | true, false  | Usata in combinazione con id_auth_soap_01 o id_auth_soap_02 |
| audit_rest_01_modi  | true, false  | Trust diretto fruitore erogatore |
| audit_rest_01_pdnd  | true, false  | Trust gestito da PDND |
| audit_rest_02  | true, false  | Richiede pdnd_fruizione settata a true |
| key_identifier_type  | BST_DIRECT_REFERENCE, X509_KEY_IDENTIFIER, ISSUER_SERIAL, THUMBPRINT_IDENTIFIER, SKI_KEY_IDENTIFIER  | Usata solo per SOAP |
| reference_certificate_type  | x5t, x5t#S256, x5c  | Per la gestione dell' x5u, la property deve essere settata con il valore di un URL |
| jwt_header_name  | Dinamico  | il cliente setta il nome dell'header |

| EROGAZIONE  | VALORI | NOTE |
| ------------- | ------------- |------------- |
| modi_auth  | true, false  | Usata da sola o in combinazione con pdnd_auth |
| pdnd_auth  | true, false  | Usata da sola o in combinazione con modi_auth |
| id_auth_rest_01  | true, false  | Usata da sola o in combinazione con integrity_rest_01 |
| id_auth_rest_02  | true, false  | Usata da sola o in combinazione con integrity_rest_01 |
| integrity_rest_01  | true, false  | Usata in combinazione con id_auth_rest_02 o id_auth_rest_01 |
| pdnd_jwks_url  | Dinamico  | La property deve essere settata con l'URL fornito da PDND |
| integrity_rest_02  | true, false  | Richiede modi_auth settata a true |
| audit_rest_01_modi  | true, false  | Trust diretto fruitore erogatore |
| audit_rest_01_pdnd  | true, false  | Trust gestito da PDND |
| audit_rest_02  | true, false  | Richiede pdnd_auth settata a true |
| jwt_header_name  | Dinamico  | il cliente setta il nome dell'header |


## Mediatore di autenticazione in fruizione
In fase di fruizione viene richiesta la generazione di appositi JWT generati direttamente dall'ente Fruitore (pattern ModI) o rilasciati dal server PDND (Voucher PagoPA).
La classe [`WeModIMediator`](./src/main/java/it/profesia/wemodi/mediator/WeModIMediator.java) implementa le logiche di generazione dei diversi JWT a seconda dei pattern definiti a livello di API (API properties).
Per poter integrare questo mediatore occorre modificare il [template velocity](./src/main/resources/velocity_template.xml) aggiungendo
```
 ## custom weModI Mediator
 
 
 #else
 #if($endpointsecurity.type == "weModI")
 <class name="it.profesia.wemodi.mediator.WeModIMediator">
         <property name="customParameters" value="$util.escapeXml($endpointsecurity.customParameters)" type="STRING"/>
 </class>
 #end
 
 
 ## custom weModI Mediator
```

La creazione dell'API deve avvenire inviando le informazioni relative al tipo di sicurezza richiesta per l'endpoint usando le [API Reference di WSO2](https://apim.docs.wso2.com/en/latest/reference/product-apis/publisher-apis/publisher-v4/publisher-v4/#tag/APIs/operation/updateAPI)
```
   "endpointConfig":{
      "endpoint_type":"http",
      "sandbox_endpoints":{
         "url":"http://api"
      },
      "production_endpoints":{
         "url":"http://api"
      },
      "endpoint_security":{
         "production":{
            "customParameters":{
               "modi_auth":"false",
               "pdnd_auth":"true",
               "modi_fruizione":"false",
               "pdnd_fruizione":"true",
               "id_auth_channel_01":"false",
               "id_auth_channel_02":"false",
               "id_auth_rest_01":"false",
               "id_auth_rest_02":"false",
               "id_auth_soap_01":"false",
               "id_auth_soap_02":"false",
               "integrity_rest_01":"false",
               "integrity_rest_02":"false",
               "integrity_soap_01":"false",
               "audit_rest_01_modi":"false",
               "audit_rest_01_pdnd":"false",
               "audit_rest_02":"false",
               "pdnd_jwks_url":"",
               "reference_certificate_type":"",
               "jwt_header_name":"",
               "key_identifier_type":"",
               "apiType":"Fruizione",
               "pdnd_api_url":"",
               "api_aud":""
            },
            "type":"weModI",
            "enabled":true
         },
         "sandbox":{
            "customParameters":{
               "modi_auth":"false",
               "pdnd_auth":"true",
               "modi_fruizione":"false",
               "pdnd_fruizione":"true",
               "id_auth_channel_01":"false",
               "id_auth_channel_02":"false",
               "id_auth_rest_01":"false",
               "id_auth_rest_02":"false",
               "id_auth_soap_01":"false",
               "id_auth_soap_02":"false",
               "integrity_rest_01":"false",
               "integrity_rest_02":"false",
               "integrity_soap_01":"false",
               "audit_rest_01_modi":"false",
               "audit_rest_01_pdnd":"false",
               "audit_rest_02":"false",
               "pdnd_jwks_url":"",
               "reference_certificate_type":"",
               "jwt_header_name":"",
               "key_identifier_type":" ",
               "apiType":"Fruizione",
               "pdnd_api_url":"",
               "api_aud":""
            },
            "type":"weModI",
            "enabled":true
         }
      }
   },
```

`"type":"weModI"` è necessario per mediare la richiesta tramite [weModI](#mediatore-di-autenticazione-in-fruizione), i `customParameters` sono elencanti nelle [properties di fruizione](#modi---pdnd-api-properties)

## Handler di autorizzazione in erogazione
In fase di erogazione avviene la validazione dei Voucher PDND e dei JWT ModI secondo i pattern dichiarati dall'e-service, la classe [ModiAuthenticationHandler](./src/main/java/it/profesia/carbon/apimgt/gateway/handlers/security/ModiAuthenticationHandler.java) implementa le logiche di autorizzazione, viene istanziata per mezzo del [Velocity Template](./src/main/resources/velocity_template.xml) in base alle [properties](#modi---pdnd-api-properties) definite nell'API di erogazione.