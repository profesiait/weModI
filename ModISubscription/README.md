# Gestione delle configurazioni weModI

* [Prerequisiti](#prerequisiti)
* [Installazione](#installazione)
* [Configurazioni](#configurazioni)
  * [Data Model](#data-model)
  * [Application](#application)

Bundle WSO2 per la gestione delle configurazioni ModI e PDND delle API ed Application di fruizione ed erogazione.

## Prerequisiti
Richiede WSO2 API Manager 4.1 o superiore.

## Installazione
1. Creare le tabelle di configurazione weModI tramite gli script presenti nella directory [dbscripts](./src/main/resources/dbscripts/).
2. Compilare il [Multi-Project maven weModI](../README.md#compilazione), il bundle viene incluso nelle webapp da deploiare nelle istanze WSO2 API Manager per il profilo Control Plane

## Configurazioni
Le configurazioni weModI sono contenute in un apposito DataBase che fa riferimento ai dati pubblicati in WSO2 API Manager

## Data model
Le tabelle contengono le informazioni per la produzione e la validazione dei JWT

#### MODI_FRUIZIONE_SUBSCRIPTION_SOAP
Configurazioni SOAP della subscription di una API di Fruizione, contente i dati di firma dell'ente fruitore

`SUBSCRIPTION_ID` Primary Key\
`APPLICATION_UUID` UUID della Application di fruizione Oauth creata nel Developer Portal\
`WSADDRESSING_TO` valore da impostare nel relativo campo della busta SOAP\
`PRIVATE_KEY_PEM` Private Key in formato PEM di firma\
`CERTIFICATE_PEM` Certificato in formato dell'ente fruitore PEM\
`ENABLED` Flag per abilitare o disabilitare la configurazione\


#### APP_CERT_MAPPING_SOAP
Configurazione di validazione della subscrition di un API SOAP di Erogazione, contiene i dati di identificazione dell'ente erogatore

`ID VARCHAR` Primary Key\
`APPLICATION_UUID` UUID della Application di erogazione Oauth creata nel Developer Portal\
`SERIAL_NUMBER` Serial Number del certificato\
`ISSUER_DN` DN censito nel certificato\
`ISSUER_NAME` Issuer Name del certificato\
`ALIAS` alias di riferimento del JKS\
`THUMBPRINT` Thumbprint del certificato\
`THUMBPRINTSHA256` Thumbrint in formato SHA 256\
`SUBJECT_KEY_IDENTIFIER` Identificativo riferito al subject\
`CERTIFICATE_PEM` Certificato in formato PEM\
`ENABLED BOOLEAN` Flag per abilitare o disabilitare la configurazione\

#### APP_CERT_MAPPING
Configurazione dei dati riferiti al client che identifica l'ente fruitore

`ID VARCHAR` Primary Key\
`APPLICATION_UUID` UUID della Application di erogazione Oauth creata nel Developer Portal\
`SERIAL_NUMBER` Serial Number del certificato\
`ISSUER_DN` DN censito nel certificato\
`ALIAS` alias di riferimento del JKS
`THUMBPRINT` Thumbprint del certificato\
`THUMBPRINTSHA256` Thumbprint in formato SHA 256\
`PDND_PUBLIC_KEY` Public Key rilasciata da PDND\
`PDND_CLIENT_ID` Client ID censito in PDND\
`PDND_PURPOSEID` Purpose ID creato in PDND\
`KID_PDND_API` Kid dichiarato in PDND\
`ENABLED` Flag per abilitare o disabilitare la configurazione\

#### MODI_FRUIZIONE_SUBSCRIPTION
Configurazione di generazione del token ModI

`SUBSCRIPTION_ID` Primary Key\
`APPLICATION_UUID` UUID della Application di erogazione Oauth creata nel Developer Portal\
`KEY_TYPE` tipo di chiave referenziata nel JWT\
`TYP` claim typ\
`ISS` claim iss\
`SUB` claim sub\
`AUD` calim aud\
`PRIVATE_KEY_PEM` chiave privata in formato PEM\
`PUBLIC_KEY_PEM` chiave pubblica in formato PEM\
`CERTIFICATE_PEM` certificato in formaot PEM\
`KID` kid di riferimento\
`ENABLED` Flag per abilitare o disabilitare la configurazione\

#### PDND_FRUIZIONE_SUBSCRIPTION
Configurazione per la richiesta del voucher PDND tramite JWT assertion

`SUBSCRIPTION_ID` Primary Key\
`APPLICATION_UUID` UUID della Application di erogazione Oauth creata nel Developer Portal\
`KEY_TYPE` Tipo di chiave di firma\
`URI` claim uri\
`KID` claim kid\
`ALG` claim alg\
`TYP` claim typ\
`ISS` claim iss\
`SUB` claim sub\
`AUD` claim aud\
`CLIENTID` Client Id creato nel portale PDND\
`SCOPE` scope Oauth\
`PURPOSE_ID` Purpose Id definito in PDND\
`PRIVATE_KEY_PEM` Private Key in formato PEM\
`ENABLED` Flag per abilitare o disabilitare la configurazione\

#### PDND_SUBSCRIPTION_MAPPING
`ID` Primary Key\
`SUBSCRIPTION_UUID` UUID della sottoscrizione creata nel Developer Portal\
`AUD` claim aud\
`ISS` claim iss\
`PURPOSE_ID` Purpose ID definito in PDND\
`ENABLED` Flag per abilitare o disabilitare la configurazione\

### Application
Ogni application identifica un ente o un client censito sul portale PDND

#### Fruizione
L'application di Fruizione contiene le informazioni per generare i token ModI e/o PDND richiesti dai pattern di sicurezza definiti dall'ente erogatore, le informazioni venogno lette dal [Mediatore di autenticazione in fruizione](../ModIAuthenticator/README.md#mediatore-di-autenticazione-in-fruizione)

#### Erogazione
L'application di Erogazione contiene le informazioni per validare i token ModI e/o PDND allegati alla richiesta da parte degli enti fruitori negli header HTTP previsti, le informaizoni vengono lette dall'[Handler di autorizzazione in erogazione](../ModiAuthenticator/README.md#handler-di-autorizzazione-in-erogazione)
