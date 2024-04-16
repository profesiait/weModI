# weModI plugin WSO2 per l'interoperabilità ModI e PDND


* [ModiSubscription](#modisubscription) Bundle per la configurazione dei dati di fruizione ed erogazione
* [ModiAuthenticator](#modiauthenticator) Libreria JAR per la produzione e validazione dei JWT
* [ModiSubscriptionAPI](#modisubscriptionapi) API per la configurazione delle API ed Application di erogazione e fruizione
* [Upgrade dalla versione 1.x](#upgrade-dalla-versione-1x)


## [ModiSubscription](./ModISubscription/README.md)


## [ModiAuthenticator](./ModIAuthenticator/README.md)


## [ModiSubscriptionAPI](./ModISubscriptionAPI/README.md)


## Upgrade dalla versione 1.x
In caso di aggiornamento dalle versioni 1.x della componente weModI, occorre eseguire i seguenti passaggi:
1. Aggiornamento del DBMS ([MySql](./ModISubscription/src/main/resources/dbscripts/ModI/mysql/upgrade-from-1.x.sql), [Oracle](./ModISubscription/src/main/resources/dbscripts/ModI/oracle/upgrade-from-1.x.sql), [Postgres](./ModISubscription/src/main/resources/dbscripts/ModI/postgres/upgrade-from-1.x.sql))
