CREATE TABLE IF NOT EXISTS APP_CERT_MAPPING (
            ID VARCHAR (255) NOT NULL,
            APPLICATION_UUID VARCHAR (255),
            SERIAL_NUMBER VARCHAR (255),
            ISSUER_DN VARCHAR(255),
            ALIAS VARCHAR (255),
            THUMBPRINT VARCHAR (255),
            THUMBPRINTSHA256 VARCHAR (255),
            PDND_PUBLIC_KEY VARCHAR (2048),
            PDND_CLIENT_ID VARCHAR (255),
            PDND_PURPOSEID VARCHAR (255),
            ENABLED BOOLEAN,
            KID_PDND_API VARCHAR (255),
            PRIMARY KEY (ID)
);

CREATE TABLE IF NOT EXISTS MODI_FRUIZIONE_SUBSCRIPTION (
            SUBSCRIPTION_ID INTEGER NOT NULL AUTO_INCREMENT,
            APPLICATION_UUID VARCHAR (255),
            KEY_TYPE VARCHAR (255),
            TYP VARCHAR (255),
            ISS VARCHAR (255),
            SUB VARCHAR (255),
            AUD VARCHAR (255),
            PRIVATE_KEY_PEM VARCHAR (2048),
            PUBLIC_KEY_PEM VARCHAR (2048),
            CERTIFICATE_PEM VARCHAR (2048),
            KID VARCHAR (255),
            ENABLED BOOLEAN,
            PRIMARY KEY (SUBSCRIPTION_ID)
);

CREATE TABLE PDND_FRUIZIONE_SUBSCRIPTION (
            SUBSCRIPTION_ID INTEGER NOT NULL AUTO_INCREMENT,
            APPLICATION_UUID VARCHAR (255),
            KEY_TYPE VARCHAR (255),
            URI VARCHAR (255),
            KID VARCHAR (255),
            ALG VARCHAR (255),
            TYP VARCHAR (255),
            ISS VARCHAR (255),
            SUB VARCHAR (255),
            AUD VARCHAR (255),
            CLIENTID VARCHAR (255),
            SCOPE VARCHAR (255),
            PURPOSE_ID VARCHAR (255),
            PRIVATE_KEY_PEM VARCHAR (2048),
            ENABLED BOOLEAN,
            PRIMARY KEY (SUBSCRIPTION_ID)
);

CREATE TABLE IF NOT EXISTS PDND_SUBSCRIPTION_MAPPING (
            ID INTEGER NOT NULL AUTO_INCREMENT,
            SUBSCRIPTION_UUID VARCHAR (255),
            AUD VARCHAR (255),
            ISS VARCHAR (255),
            PURPOSE_ID CHARACTER VARYING(255),
            ENABLED BOOLEAN,
            PRIMARY KEY (ID)
);