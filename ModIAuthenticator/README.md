# Integrazione dei pattern ModI all'interno di WSO2 API Manager

Richiede WSO2 API Manager 4.1

```sh
mv clean package

cp target/ModiAuthenticator-1.0.0-SNAPSHOT.jar <WSO2AM-4.1.0_HOME>/repository/components/lib/
```

## Configurazione del DB weModI
Aggiungere la seguente configurazione nel deployment.toml

```
[datasource.WSO2MODI_DB]
type = "mysql"
id = "WSO2MODI_DB"
url = "jdbc:mysql://localhost:3306/WSO2MODI_DB?useSSL=false"
username = "apimadmin"
password = "apimadmin"
driver="com.mysql.cj.jdbc.Driver"
pool_options.maxActive = 50
pool_options.maxWait = 30000
```

Assicurarsi che a runtime il master-datasources.xml venga correttamente aggiornato:

```
<datasource>
            <name>WSO2MODI_DB</name>
            <description>The datasource used for Modi database</description>
            <jndiConfig>
                <name>jdbc/WSO2MODI_DB</name>
            </jndiConfig>
            <definition type="RDBMS">
                <configuration>
                    <url>jdbc:mysql://localhost:3306/WSO2MODI_DB?useSSL=false</url>
                    <username>apimadmin</username>
                    <password>apimadmin</password>
                    <driverClassName>com.mysql.cj.jdbc.Driver</driverClassName>
                    <validationQuery>SELECT 1</validationQuery>
                    <maxWait>30000</maxWait>
                    <maxActive>50</maxActive>
            </configuration>
            </definition>
        </datasource>
```

## Configurazione del proxy (opzionale)

Aggiungere le seguenti configurazioni nel file `deployment.toml`:

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

## Logger ModI
Aggiungere le configurazioni per MODI_LOGFILE come specificato nel log4j2.properties sotto src/main/resources

Configurazione del file di log di destinazione:
```
# MODI_LOGFILE
appender.MODI_LOGFILE.type = RollingFile
appender.MODI_LOGFILE.name = MODI_LOGFILE
appender.MODI_LOGFILE.fileName = ${sys:carbon.home}/repository/logs/modi.log
appender.MODI_LOGFILE.filePattern = ${sys:carbon.home}/repository/logs/modi-%d{MM-dd-yyyy}-%i.log.gz
appender.MODI_LOGFILE.layout.type = PatternLayout
appender.MODI_LOGFILE.layout.pattern = TID: [%tenantId] [%appName] [%d] [%X{correlationID} %X{apiName} %X{apiVersion} %X{apiContext} %X{resourceName}] %5p {%c} - %m%ex%n
appender.MODI_LOGFILE.policies.type = Policies
appender.MODI_LOGFILE.policies.time.type = TimeBasedTriggeringPolicy
appender.MODI_LOGFILE.policies.time.interval = 1
appender.MODI_LOGFILE.policies.time.modulate = true
appender.MODI_LOGFILE.policies.size.type = SizeBasedTriggeringPolicy
appender.MODI_LOGFILE.policies.size.size = 100MB
appender.MODI_LOGFILE.strategy.type = DefaultRolloverStrategy
appender.MODI_LOGFILE.strategy.max = nomax
appender.MODI_LOGFILE.filter.threshold.type = ThresholdFilter
appender.MODI_LOGFILE.filter.threshold.level = DEBUG
```
Le variabili `correlationID`, `apiName`, `apiVersion`, `apiContext` e `resourceName` vengono impostate all'interno degli handler ModI, inserire `MODI_LOGGER` nell'elenco degli `appenders`.

Configurare il logger `MODI`:

```
logger.MODI.name = it.profesia
logger.MODI.level = INFO
logger.MODI.appenderRef.CARBON_LOGFILE.ref = MODI_LOGFILE
```
Il package `it.profesia` contiene tutte le classi ModI, inserire il logger `MODI` nell'elenco dei `loggers`.

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

## ModI - PDND application attributes
Add the following configuration in the deployment.toml:
```
[[apim.devportal.application_attributes]]
required=false
hidden=false
name="wemodi_connessione"
description="Possible values are fruizione/erogazione"
```

## Mediatore di autenticazione in fruizione [in fase di sviluppo]
In fase di fruizione viene richiesta la generazione di appositi JWT generati direttamente dall'ente Fruitore (pattern ModI) o rilasciati dal server PDND (Voucher PagoPA).
La classe `WeModIMediator` implementa le logiche di generazione dei diversi JWT a seconda dei pattern definiti a livello di API (API properties).
Per poter integrare questo mediatore occorre modificare il template velocity aggiungendo
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

La creazione dell'API deve avvenire inviando le informazioni relative al tipo di sicurezza richiesta per l'endpoint
```
      "endpoint_security": {
            "sandbox": {
                "type": "weModI",
                "enabled": true,
                "customParameters": {
                    "isPDND": true,
                    "siModI": false
                   },
                "additionalProperties": {
                    "PDND": {
                        "tokenUrl": "HTTPS://my.url"
                        },
                        "ID_AUT_REST_02": false,
                        "AUDIT_REST_01": true,
                        "INTEGRITY_REST_02": true
                }
            },
            "production": {
                "password": null,
                "tokenUrl": "",
                "clientId": null,
                "clientSecret": null,
                "customParameters": {},
                "type": "NONE",
                "grantType": "",
                "enabled": false,
                "username": ""
            }
        }
    },
```
