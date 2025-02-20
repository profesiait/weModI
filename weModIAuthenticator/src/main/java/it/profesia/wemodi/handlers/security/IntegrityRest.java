package it.profesia.wemodi.handlers.security;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;

import net.minidev.json.JSONObject;

public abstract class IntegrityRest extends IdAuthRest01 {
    public static final String KID = "kid";
    public static final String SIGNED_HEADERS = "signed_headers";

    protected Map<String, String> headers = new HashMap<String, String>();

    
    	//WSO2 4.1 - 4.2
        protected Boolean checkSignedHeaders(String claimName, net.minidev.json.JSONArray signedHeaders) {
        boolean isValid = false;
        String digest = null;
        String contentType = null;
        String contentEncoding = null;

        for (int i = 0; i < signedHeaders.size(); i++) {
            try {
            	net.minidev.json.JSONObject header = (JSONObject) signedHeaders.get(i);
                if (StringUtils.isBlank(digest)) {
                    if (header.containsKey("digest")) {
                        digest = header.getAsString("digest");
                    } 
                }
                if (StringUtils.isBlank(contentType)) {
                    if (header.containsKey("content-type")) {
                        contentType = header.getAsString("content-type");
                    }
                }
                if (StringUtils.isBlank(contentEncoding)) {
                    if (header.containsKey("content-encoding")) {
                        contentEncoding = header.getAsString("content-encoding");
                    }
                }                    
            } catch (JSONException e) {
                log.debug(String.format("L'elemento signed_header {%s} non è nel formato corretto.", signedHeaders.get(i)));
            }
        }

        String hDigest = headers.get("digest");
        if (StringUtils.equals(digest, hDigest)) {
            isValid = true;
        } else {
            log.error(String.format("L'header digest della request: <%s> ed il digest del claim signed_headers: <%s> non corrispondono", hDigest, digest));
            return false;
        }

        String hContentType = headers.get("content-type");
        if (StringUtils.equals(contentType, hContentType)) {
            isValid = true;
        } else {
            log.error(String.format("L'header content-type della request: <%s> ed il content-type del claim signed_headers: <%s> non corrispondono", hContentType, contentType));
            return false;
        }

        String hContentEncoding = headers.get("content-encoding");
        if (StringUtils.equals(contentEncoding, hContentEncoding)) {
            isValid = true;
        } else {
            log.error(String.format("L'header content-encoding della request: <%s> ed il content-encoding del claim signed_headers: <%s> non corrispondono", hContentEncoding, contentEncoding));
            return false;
        }

        return isValid;
    }
        //WSO2 4.3
        protected Boolean checkSignedHeaders(String claimName, java.util.ArrayList signedHeaders) {
            boolean isValid = false;
            String digest = null;
            String contentType = null;
            String contentEncoding = null;

            for (int i = 0; i < signedHeaders.size(); i++) {
                try {
                	Map header = (Map) signedHeaders.get(i);
                    if (StringUtils.isBlank(digest)) {
                        if (header.containsKey("digest")) {
                            digest = header.get("digest").toString();
                        } 
                    }
                    if (StringUtils.isBlank(contentType)) {
                        if (header.containsKey("content-type")) {
                            contentType = header.get("content-type").toString();
                        }
                    }
                    if (StringUtils.isBlank(contentEncoding)) {
                        if (header.containsKey("content-encoding")) {
                            contentEncoding = header.get("content-encoding").toString();
                        }
                    }                    
                } catch (JSONException e) {
                    log.debug(String.format("L'elemento signed_header {%s} non è nel formato corretto.", signedHeaders.get(i)));
                }
            }

            String hDigest = headers.get("digest");
            if (StringUtils.equals(digest, hDigest)) {
                isValid = true;
            } else {
                log.error(String.format("L'header digest della request: <%s> ed il digest del claim signed_headers: <%s> non corrispondono", hDigest, digest));
                return false;
            }

            String hContentType = headers.get("content-type");
            if (StringUtils.equals(contentType, hContentType)) {
                isValid = true;
            } else {
                log.error(String.format("L'header content-type della request: <%s> ed il content-type del claim signed_headers: <%s> non corrispondono", hContentType, contentType));
                return false;
            }

            String hContentEncoding = headers.get("content-encoding");
            if (StringUtils.equals(contentEncoding, hContentEncoding)) {
                isValid = true;
            } else {
                log.error(String.format("L'header content-encoding della request: <%s> ed il content-encoding del claim signed_headers: <%s> non corrispondono", hContentEncoding, contentEncoding));
                return false;
            }

            return isValid;
        }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }
}
