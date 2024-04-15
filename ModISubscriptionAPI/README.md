# WSO2 API Manager - ModI Subscription API (v4)
La classe ModISubscriptionAPI espone i metodi per l'inserimento/aggiornamento/recupero dei dati necessari per il corretto funzionamento del modulo weModI.

La classe SwaggerYamlApi permette di recupare lo swagger in formato openapi 3.0.1 della web application.
Aggiungere nel deployment.toml dell'api manager la seguente configurazione per invocare la swagger api senza autenticazione:
```
[[apim.rest_api.allowed_uri]]
uri_path = "/api/am/modi/swagger.yaml"
http_method = "GET,HEAD"
```
Per creare il war, lanciare dalla cartella weModI il comando
```
mvn clean package
```
Insieme al war, verrà generato anche lo swagger weModI-subscription.yaml