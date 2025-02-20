# weModI plugin WSO2 per l'interoperabilità ModI e PDND

Il progetto si compone dei moduli elencati di seguito, la [compilazione dei pacchetti](#compilazione) viene effettuata a partire dal [Multi-Project maven corrente](./pom.xml).

Il deploy dei singoli pacchetti è descritto all'interno del file README.md di ogni progetto.

* [weModISubscription](#wemodisubscription) Bundle per la configurazione dei dati di fruizione ed erogazione
* [weModIAuthenticator](#wemodiauthenticator) Libreria JAR per la produzione e validazione dei JWT
* [weModISubscriptionAPI](#wemodisubscriptionapi) API per le configurazioni weModI delle API ed Application di erogazione e fruizione
* [weModIKeyManager](#weModIkeymanager) Estensione Key Manager WSO2 per la sottoscrizione delle API PDND
* [PDND Provider JWT](#pdnd-provider-jwt) Libreria per la generazione dei voucher PDND
* [ModIComponents](#modicomponents)
* [Compilazione](#compilazione)
* [Configurazione weModI](#configurazione-wemodi)
* [Upgrade dalla versione 1.x](#upgrade-dalla-versione-1x)


## [weModISubscription](./weModISubscription/README.md)


## [weModIAuthenticator](./weModIAuthenticator/README.md)


## [weModISubscriptionAPI](./weModISubscriptionAPI/README.md)


## [weModIKeymanager](./weModIKeyManager/README.md)


## [PDND Provider JWT](./PDNDProviderJWT/README.md)


## [ModIComponents](./ModIComponents/README.md)


## Compilazione
Eseguire il comando ```mvn clean package``` per eseguire la compilazione di tutti i moduli definiti all'interno del [pom.xml](./pom.xml) elencati precedentemente. Questo comando crea i pacchetti per la [versione corrente di WSO2 API Manager](https://apim.docs.wso2.com/en/latest/) (4.3).

Il prodotto richiede una compilazione condizionale per le diverse versioni di WSO2 API Manager tramite l'utilizzo dei profili:

### [Versione 4.1](https://apim.docs.wso2.com/en/4.1.0/)
Utilizzare il profilo APIM-4.1 ed escludere il submodule [KeyManager](#keymanager) con il comando: ```mvn clean package -P APIM-4.1 -pl -KeyManager```

### [Versione 4.2](https://apim.docs.wso2.com/en/4.2.0/)
Utilizzare il profilo APIM-4.2 con il comando: ```mvn clean package -P APIM-4.2```

### [Versione 4.3](https://apim.docs.wso2.com/en/4.3.0/)
Utilizzare il profilo APIM-4.3 con il comando: ```mvn clean package -P APIM-4.3```

Per la creazione dei jar a partire da uno specifico tag, eseguire i seguenti comandi:
```
git -c http.sslVerify=false clone --recurse-submodules https://git.profesia.it/interoperabilita/ModI/weModI.git
cd weModI
git checkout tags/<tag-name>
git -c http.sslVerify=false submodule update --init --recursive
mvn clean package -P APIM-4.3
```

## Configurazione weModI
Le API pubblicate su WSO2 API Manager tramite il portale Publisher vengono configurate come API di Fruizione o di Erogazione. Le API di Fruizione si occupano della produzione del Voucher PDND e dei JWT ModI secondo i pattern definiti da parte dell'ente erogatore; le API di Erogazione validano i Voucher e JWT inoltrati nella request da parte dell'ente fruitore.

Gli attributi dell'ente fruitore per la produzione dei JWT richiesti dall'ente erogatore sono associati ad una Application che assume l'attributo di Application di Fruizione, parallelamente i dati relativi all'ente che vuole fruire di un'API erogata sono asosciati ad una Application di Erogazione.

### API di Fruizione
1. Collegarsi alla console [Publisher](https://apim.docs.wso2.com/en/latest/get-started/apim-architecture/#api-publisher) ed autenticarsi con credenziali per la creazione di API
2. [Creare una API](https://apim.docs.wso2.com/en/latest/design/create-api/create-rest-api/create-a-rest-api-from-an-openapi-definition/) a partire dalla definizione Swagger/OpenAPI rilasciata dall'erogratore
3. [Pubblicare l'API di Fruzione](ModIAuthenticator/README.md#mediatore-di-autenticazione-in-fruizione) indicando i pattern richiesti dall'ente erogatore

### Application di Fruizione
1. Collegarsi alla console [Developer Portal](https://apim.docs.wso2.com/en/latest/get-started/apim-architecture/#api-developer-portal) ed autenticarsi con credenziali per la creazione di Application
2. [Creare un'application](https://apim.docs.wso2.com/en/latest/consume/manage-application/create-application/) di Fruizione
3. Sottoscrivere l'[API pubblicata](#api-di-fruizione)
4. Inserire le configurazioni nel database di weModI
   - Dati di generazione della JWT assertione per la richiesta del voucher PDND
     > INSERT INTO PDND_FRUIZIONE_SUBSCRIPTION (APPLICATION_UUID, URI, KID, ALG, TYP, ISS, SUB, AUD, CLIENTID, SCOPE, PURPOSE_ID, PRIVATE_KEY_PEM, ENABLED) VALUES('6b91exe1-3a42-779c-93mc-e3xa75aaf9ib', 'https://auth.uat.interop.pagopa.it/token.oauth2', 'A41ebY_k8J8E9IGppI##############-kouabc', 'JWT', 'RS256', '99930bed-88de-YYYY-9d34-576ca3eb0a77', '99930bed-88de-YYYY-9d34-576ca3eb0a77', 'auth.uat.interop.pagopa.it/client-assertion', '99930bed-88de-YYYY-9d34-576ca3eb0a77', NULL, '99cexxxc-ff19-4e32-8910-a47b9510b2hh', '-----BEGIN PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQE...-----END PRIVATE KEY-----', 1);
   - Claim del JWT di asserzione specifici per la fruizione
     > INSERT INTO PDND_SUBSCRIPTION_MAPPING (SUBSCRIPTION_UUID, AUD, ISS, PURPOSE_ID, ENABLED) VALUES('8888cd7b-9faa-4df0-ac53-abc41f9ed877', 'aud', 'uat.interop.pagopa.it', '81cefabc-zz19-7a99-8910-a43b9517y5z0', 1);

### API di Erogazione
1. Collegarsi alla console [Publisher](https://apim.docs.wso2.com/en/latest/get-started/apim-architecture/#api-publisher) ed autenticarsi con credenziali per la creazione di API
2. [Creare una API](https://apim.docs.wso2.com/en/latest/design/create-api/create-rest-api/create-a-rest-api-from-an-openapi-definition/) a partire dalla definizione Swagger/OpenAPI rilasciata dall'e-service
3. [Pubblicare l'API di Erogazione](ModIAuthenticator/README.md#*#handler-di-autorizzazione-in-erogazione) inserendo le properties richieste dai pattern di sicurezzza

### Application di Erogazione
1. Collegarsi alla console [Developer Portal](https://apim.docs.wso2.com/en/latest/get-started/apim-architecture/#api-developer-portal) ed autenticarsi con credenziali per la creazione di Application
2. [Creare un'application](https://apim.docs.wso2.com/en/latest/consume/manage-application/create-application/) di Erogazione
3. Sottoscrivere l'[API pubblicata](#api-di-erogazione)
   - Validazione offline del voucher weModI senza interazione con le API PDND:
     
     Inserire le configurazioni nel database di weModI
     > INSERT INTO APP_CERT_MAPPING (APPLICATION_UUID, SERIAL_NUMBER, ISSUER_DN, ALIAS, THUMBPRINT, THUMBPRINTSHA256, PDND_PUBLIC_KEY, PDND_CLIENT_ID, PDND_PURPOSEID, ENABLED, KID_PDND_API) VALUES('5f79b0d3-ae68-4670-1234-d0bfb27d2zzz', NULL, NULL, NULL, NULL, NULL, '12345bed-83da-4ada-9d34-576ca3fb0s10', NULL, 1, NULL);
   - Validazione del voucher tramite le API PDND
     - Creare un Client API Interop sul portale PDND
     - Inserire il record per la richiesta del Voucher Interop
       > INSERT INTO wso2modi_db.pdnd_fruizione_subscription
(APPLICATION_UUID, URI, KID, ALG, TYP, ISS, SUB, AUD, PURPOSE_ID, PRIVATE_KEY_PEM, ENABLED, CLIENTID, `SCOPE`, `KEY_TYPE`)
VALUES('5f79b0d3-ae68-4670-1234-d0bfb27d2zzz', 'https://auth.uat.interop.pagopa.it/token.oauth2', 'ABCXO7st1XX5hQMjB7luzzP2PxxvH9pkcmKQFxYJslA', 'RS256', 'JWT', 'b76df546-41fc-XXXX-a0b2-597aYYYcf989', 'b76df546-41fc-XXXX-a0b2-597aYYYcf989', 'auth.uat.interop.pagopa.it/client-assertion', NULL, '---BEGIN PRIVATE KEY---', true, 'b76df546-41fc-XXXX-a0b2-597aYYYcf989', null, '');
 questo sostituisce il punto 4.


## Upgrade dalla versione 1.x
In caso di aggiornamento dalle versioni 1.x della componente weModI, occorre eseguire i seguenti passaggi:
1. Aggiornamento del DBMS ([MySql](./weModISubscription/src/main/resources/dbscripts/ModI/mysql/upgrade-from-1.x.sql), [Oracle](./weModISubscription/src/main/resources/dbscripts/ModI/oracle/upgrade-from-1.x.sql), [Postgres](./weModISubscription/src/main/resources/dbscripts/ModI/postgres/upgrade-from-1.x.sql))
