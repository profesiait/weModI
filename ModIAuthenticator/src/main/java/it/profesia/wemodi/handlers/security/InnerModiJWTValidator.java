package it.profesia.wemodi.handlers.security;

import java.security.PublicKey;
import java.security.cert.Certificate;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;

public interface InnerModiJWTValidator {
    public Boolean validateHeader(JWSHeader jwtHeader);
    public Boolean validatePayload(Payload payload);
    public void setCertificate(Certificate certificate);
    public Certificate getCertificate();
    public PublicKey getPublicKey();
    public void setPublicKey(PublicKey publicKey);
    
    public void setExp(Long exp);
    public Long getExp();
    public void setIat(Long iat);
    public Long getIat();
    public void setNbf(Long nbf);
    public Long getNbf();
}
