* [Token Issuer WSO2 per PDND (in fase di sviluppo)](#token-issuer-wso2-per-pdnd)
* [Custom grants PDND (in fase di sviluppo)](#custom-grants-pdnd)

## Token Issuer WSO2 per PDND

Richiesta del token PDND tramite la creazione di un Service Provider WSO2

1. Nel file `<WSO2_HOME>/repository/conf/deployment.toml` inserire la seguente configurazione
```conf
[[oauth.extensions.token_types]]
name="PDND"
issuer="it.profesia.wemodi.identity.oauth2.token.PDNDTokenIssuer"
```
2. Creare un Service Provider e selezionare come Token Issuer `PDND`
3. Invocare l'endpoint token con le opportune credenziali
```sh
curl -X POST https://localhost:9443/oauth2/token -d "grant_type=client_credentials" -H "Authorization: Basic SkFpQzNQVGZOSGFaSDY4YXJWZjZHa19vOElBYTpmYTJWaDdpY1BhS3JHd0JWX3NPZFU5Qk1MSXNh"
```

## Custom grants PDND
Per gestire parametri aggiuntivi nel token PDND

### ID_AUDIT_REST_01
Per ottenere il JWT Tracking Evidence

```conf
[[oauth.custom_grant_type]]
name="id_audit_rest_01"
grant_handler="it.profesia.wemodi.identity.oauth2.token.IdAuditRest01Grant"
grant_validator="it.profesia.wemodi.identity.oauth2.token.IdAuditRest01GrantValidator"
```

```sh
curl -X POST https://localhost:9443/oauth2/token -d "grant_type=id_auth_rest_01&scope=none&digest=SHA256-9804598" -H "Authorization: Basic QnFFWDI2S3Z4am5TYlcwb1FyUkV5VUs3aHJzYTpqeGNZVjVaUjFMTGR3elVkSlFmNHpBTF9SXzBh"
```