# WSO2 API Manager - weModI Subscription API (v4)
Questa webapp espone le API di configurazione weModI (ModI e PDND) per le API pubblicate in WSO2 API Manager.

* [Prerequisiti](#prerequisiti)
* [Installazione](#installazione)
* [Configurazione](#configurazione)

La classe [ModISubscriptionAPI](./src/main/java/it/profesia/carbon/apimgt/subscriptionApi/ModISubscriptionAPI.java) espone i metodi per il recupero dei dati necessari al corretto funzionamento del modulo weModI.

## Prerequisiti
Richiede WSO2 API Manager 4.1 o superiore<br>

## Installazione
Per le configurazioni API Manager distribuito su diversi [profili](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/distributed-deployment/understanding-the-distributed-deployment-of-wso2-api-m/) deployare il war nel profilo Control Plane di WSO2 API Manager.

All'interndo del war, verrà generato anche lo swagger weModI-subscription.yaml.

Compilare il [Multi-Project maven weModI](../README.md#compilazione), deploiare il war nella directory webapps ```cp target/api#am#wemodi#subscription.war <WSO2AM_HOME>/repository/deployment/server/webapps```

## Configurazione
La classe SwaggerYamlApi permette di recupare lo swagger delle API in formato openapi 3.0.1 della web application.
Aggiungere nel ```deployment.toml``` dell'api manager la seguente configurazione per invocare la swagger api senza autenticazione:
```
[[apim.rest_api.allowed_uri]]
uri_path = "/api/am/modi/swagger.yaml"
http_method = "GET,HEAD"
```

