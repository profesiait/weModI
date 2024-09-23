package it.profesia.wemodi.handlers.security;

import java.util.HashMap;
import org.apache.commons.lang3.StringUtils;
import com.nimbusds.jose.Payload;

public class IntegrityRest01 extends IntegrityRest {
		protected IdAuthRest idAuthRest = null;

		public IntegrityRest01 () {
            super();
			log.trace("Pattern di accesso al soggetto fruitre non definito, viene impostato di default ID_AUTH_REST01.");
			this.idAuthRest = new IdAuthRest01();
		}

		public IntegrityRest01 (IdAuthRest idAuthRest) {
            super();
			if (idAuthRest == null) {
				log.trace("Pattern di accesso al soggetto fruitre non definito, viene impostato di default ID_AUTH_REST01.");
				this.idAuthRest = new IdAuthRest01();
				return;
			}
			this.idAuthRest = idAuthRest;
		}

        @Override
        protected void InitHeaderClaimsMap() {
        	super.InitHeaderClaimsMap();
        }

        @Override
        protected void InitPayloadClaimsMap() {
        	super.InitPayloadClaimsMap();
            InnerModiJWTValidator validatorObject = this;
            payloadClaimsMap = new HashMap<String, ClaimValidator>() {
                {
                    put(SIGNED_HEADERS, new ClaimValidator(true, validatorObject, "checkSignedHeaders"));
                };
            };
        }

		@Override
		public Boolean validatePayload(Payload payload) {
			if (idAuthRest.validatePayload(payload)){
                return super.validatePayload(payload);
            }
            return false;
		}

        private Boolean checkContentType(String contentType) {
            String headerContentType = headers.get("content-type");
            if (StringUtils.isNotEmpty(headerContentType)) {
               return contentType.equals(headerContentType);
            }

			return true;
		}


	}