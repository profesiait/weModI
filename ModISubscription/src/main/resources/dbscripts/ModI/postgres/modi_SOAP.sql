CREATE SEQUENCE MODI_FRUIZIONE_SUBSCRIPTION_SOAP_SUBSCRIPTION_ID;

CREATE TABLE IF NOT EXISTS MODI_FRUIZIONE_SUBSCRIPTION_SOAP (
            SUBSCRIPTION_ID INTEGER NOT NULL DEFAULT nextval('MODI_FRUIZIONE_SUBSCRIPTION_SOAP_SUBSCRIPTION_ID'),
            APPLICATION_UUID VARCHAR (255),
			WSADDRESSING_TO VARCHAR (255),
            PRIVATE_KEY_PEM VARCHAR (2048),
            CERTIFICATE_PEM VARCHAR (2048),
            ENABLED BOOLEAN,
            PRIMARY KEY (SUBSCRIPTION_ID)
);

ALTER SEQUENCE MODI_FRUIZIONE_SUBSCRIPTION_SOAP_SUBSCRIPTION_ID
OWNED BY MODI_FRUIZIONE_SUBSCRIPTION_SOAP.SUBSCRIPTION_ID;

CREATE TABLE IF NOT EXISTS APP_CERT_MAPPING_SOAP (
            ID VARCHAR (255) NOT NULL,
            APPLICATION_UUID VARCHAR (255),
            SERIAL_NUMBER VARCHAR (255),
            ISSUER_DN VARCHAR(255),
			ISSUER_NAME VARCHAR(255),
            ALIAS VARCHAR (255),
            THUMBPRINT VARCHAR (255),
            THUMBPRINTSHA256 VARCHAR (255),
            SUBJECT_KEY_IDENTIFIER VARCHAR (255),
            CERTIFICATE_PEM VARCHAR (2048),
            ENABLED BOOLEAN,
            PRIMARY KEY (ID)
);

