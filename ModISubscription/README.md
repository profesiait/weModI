# Gestione dei certificati ModI

L'implementazione si basa su quanto descritto qui: https://wso2.com/library/tutorials/2014/03/how-to-write-a-wso2-carbon-component/

WSO2 Admin Services: https://apim.docs.wso2.com/en/latest/reference/wso2-admin-services/

Richiede WSO2 API Manager 4.1

```sh
mv clean install

cp target/ModiSubscription-0.0.1-SNAPSHOT.jar <WSO2AM-4.1.0_HOME>/repository/components/dropins/
```

Una volta deplyato il componente è possibile ottenere il WSDL dei servizi:

`curl https://localhost:8243/services/ModiSubscription?wsdl -k`

`curl https://localhost:8243/services/ModiFruizione?wsdl -k`

`curl https://localhost:8243/services/PdndFruizione?wsdl -k`