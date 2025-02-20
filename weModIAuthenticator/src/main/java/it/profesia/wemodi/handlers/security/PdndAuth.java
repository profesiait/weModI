package it.profesia.wemodi.handlers.security;

import java.security.PublicKey;
import java.time.Instant;
import java.util.HashMap;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.jwt.util.DateUtils;

import it.profesia.carbon.apimgt.gateway.handlers.security.JWTValidator;

public class PdndAuth extends AbstractInnerModiJWTValidator{
	
	/**
     * URL Jwks PDND
     */
    private String urlPdndJwks = "";
	
	public static final String KID = "kid";
    public static final String TYP = "typ";
    public static final String ALG = "alg";
    public static final String IAT = "iat";
    public static final String EXP = "exp";
    public static final String NBF = "nbf";
    public static final String AUD = "aud";
    public static final String ISS = "iss";
    public static final String PURPOSEID = "purposeId";
    public static final String CLIENTID = "client_id";

    public PdndAuth() {
        super();
    }

    @Override
    protected void InitHeaderClaimsMap() {
        InnerModiJWTValidator validatorObject = this;
        headerClaimsMap = new HashMap<String, ClaimValidator>() {
            {
            	put(KID, new ClaimValidator(true, validatorObject, "checkCertificateReference"));
                put(TYP, new ClaimValidator(true, validatorObject, "checkTyp"));
                put(ALG, new ClaimValidator(true, validatorObject, "checkAlg"));
            }
        };
    }

    @Override
    protected void InitPayloadClaimsMap() {
        InnerModiJWTValidator validatorObject = this;
        payloadClaimsMap = new HashMap<String, ClaimValidator>() {
            {
                // TODO: definire il metodo di validazione per il certificato
                put(IAT, new ClaimValidator(true, validatorObject, "checkIat"));
                put(EXP, new ClaimValidator(true, validatorObject, "checkExp"));
                put(NBF, new ClaimValidator(true, validatorObject, "checkNbf"));
                put(AUD, new ClaimValidator(true, validatorObject, "checkAud"));
                put(ISS, new ClaimValidator(true, validatorObject, "checkIss"));
                put(PURPOSEID, new ClaimValidator(true, validatorObject, "checkPurposeId"));
                put(CLIENTID, new ClaimValidator(true, validatorObject, "checkClientId"));
            }
        };
    }
    
    private Boolean checkCertificateReference(String claim, String value) {
        Boolean isValid = false;
        if (KID.equals(claim)) {
            log.info("Validazione del certificato in base al kid PDND: " + value);
            String content = JWTValidator.callExternalUrl(urlPdndJwks, "");
            //String content = "{\"keys\": [{\"e\": \"AQAB\", \"kid\": \"f26e03db-f8b3-499e-8f32-072c93ecf761\", \"kty\": \"RSA\", \"n\": \"ylJgMkU_bDwCLzMlo47igdZ-AC8oUbtGJUOUHnuJdjflpim7FOxw0zXYf9m0tzND0Bt1y7MPyVtf-3rwInvdgi65CZEJ3kt5PE0g6trPbvyW6hJcVeOsQvSErj33mY6RsjndLhNE-RY36G8o603au64lTOYSb9HjzzRFo4F_faEgQ02jpEYkLIWwf7PboExDbd6NGMV0uume8YA6eB3z5BwfMMHyRZA0FcIzj6F0V-hDqBaJkWegpJsukgpfO7JDKaU5rlor7j6CdbfLaWorYTCUH3F-bXZ1ojBe0wHRGEgEZBNa46A3clgNohQuuNzf4K12NFGnEl_TIFRcLm6M0Q\"}, {\"alg\": \"RS256\", \"e\": \"AQAB\", \"kid\": \"8TxPKppRVctrLmjufrcZSk-UZxU44yB6oWQe9MABBME\", \"kty\": \"RSA\", \"n\": \"xGYjHjJG_2Yf2CGl06CpVfRCHrzCZaZHEGxj77-UVnoNxIdIh9QLxy7LaLl8TAtES7SU9qBpzRdTu7DJGxHzDCJbQ3a1CtuKc5EIqbPx40ld5yMi-lMF7h6EuVd0FP3X0uiBWpvcjDHwoeRygIRpktI7Lk3y123v8f-Ra5y4fCItmm6JrJoKIQSgo9jbdianY0ljjdguOUuWnxUsoZvEi5u8i_LuRNUm6LVkLUReRfwrQjv34MF4ukAPu5iNrMxszBoYham4Dt-arCLbnEDC1oennLIlIIVDIywW1uHSIu5MJpJ2O7gdiO8843GMk7YELX2TVSvb4kWRNy0HxAjR8Q\", \"use\": \"sig\"}, {\"alg\": \"RS256\", \"e\": \"AQAB\", \"kid\": \"QHvbKeFuYvgmMsdexISkZRcxI9uMpsoASHGruepYosI\", \"kty\": \"RSA\", \"n\": \"jwjL8QIuQPFoszXXyIGKp5-Q8osWxCtNS4bp0-GKfbZiNspVvzcaTG0Pj62mgY61jIuNpxyTcL0d2kKStd-qPXI_pnaVkaq_VfXRv-Bzjs510UokheMLyu4aeaCn6SfTyehLxzHgd0jaoEFk522B7k9cSqsxA3jRYfwg6a-XrLp1HDVl8kGHAeqkyTjtQCICpyEtJ8RLVYEJmH-CWfesP7VCLAi9qa-MmoCIlRBXv-J00oIAzl0YDUngwtfXC8Gwqi2N0MV_9uRD11Ei973D1uMfPTM5GAACtaOCSqOkKL0JJE1rnTKkPbVNNFTrMYOuzbCIh6Rif9Uq-kR4JGNkuw\", \"use\": \"sig\"}, {\"alg\": \"RS256\", \"e\": \"AQAB\", \"kid\": \"ROspzD0Z1l3S6QpdyJjbG3JWmcOlvafgvSg3M5PKqwA\", \"kty\": \"RSA\", \"n\": \"8WCwnPyteWjsF-aL6VjB7xT2S8pKVwSd8zW_HSlb2qkSF396XFrLrCr3tzojtffnlk79-mLoCfEbChpiQ9JSKUyd5W3qq2RqO1MmdidGJK5QGpjO9VmHQZ2cKIwZwY-BA51yBXJ9V_gDyRaoWty2ur9PIPZ9iNPITHE0k_CWgP7KzLF4LlULYKLzXTVq-4JuJhMHJ5IY_YwRj_uI0XtpGMM8TaXdPZI0AGF1RpEGz-r4GgM3ojYzRCoiW_dqhALFaH61wOjJjlC1P39-7B8PXrJQF4y1qNAumtc4UMVJBYTnZ9HoAhgT2OsPDakyljiwkR3i2tWfifZoC9M09EN8fw\", \"use\": \"sig\"}, {\"crv\": \"P-256\", \"kid\": \"interop-ecdsa-p256-01\", \"kty\": \"EC\", \"x\": \"AoM-AMknSmzUt-mkoDsH0Y2Qo0A5sIR7jTJ6_EWTINs\", \"y\": \"OgB8XwBpYinm_PYR-UYPgeajgBCRrBosQUnDHgE-VQk\"}, {\"e\": \"AQAB\", \"kid\": \"cdb52532-dd94-40ef-824d-9c55b10e6bc9\", \"kty\": \"RSA\", \"n\": \"m26QIbhJyzbwum-_YolgLFLIN6EqGl67jwEOThmmLdXYEyrBoU1qLLdFWyp44k0cBG0NMGRK6twZ6aV-WqcQJjpUyDDP4cLwqFe42jcnLTCrD9ezuSdGyIkuvEFtJ8fpHggWsscihdr-LydAiYyEOWq2tZZ3YexfoMWte8TCZQ9Xg0UpOaXp6xJV9AejiVq18OQtRnJoo7USrvWCnYdghXrGqax02ze7CZAgnZgP8RVQ7AMMtuZvsAwc92v_piHbYjhrRFhGOhV0Nf5NaNiVt62Jmjr1KEKRP6oPD6yqeBXuQ3fWt5htse6SUzIM48xBrJ7AAGhRF19T4ORwbaT4bw\"}, {\"e\": \"AQAB\", \"kid\": \"interop-rsa4096-01\", \"kty\": \"RSA\", \"n\": \"qJyNDiN-vyXJvpdc5TB1O7WEDokCRS8gmYYcZDtMYL-f2Sf4mWSWfRWN8a5xMiBC72nEIOM1rSMteeB0-_6pQ0Hm2w2DCkqNcplgd_QCo_SFxzSvOHZTjiCVl3A2zCH2wwBMRJeIRW7CQD3CbGx-jTliJI6vZf4WH-tfIljzPF5BxpY3ZsfPKVKHPGUPIcsXgG0-X8z02GzkDxIoBzXISxegE2EqwKl3EhrmhbcXIQIrW9gwDcPL6gUWHPVYppy4OgYfRRMsfmMPyxAc38aK_Od-0zOTa8UlJNv5SFF-IKeYOb0tFLMWhE0nbh7s8FoV1tuaLBsppGDqu1k_8vmbUhygwEhtGwsWqAWE5dmLvXlCApVb-QQyokCemrxuzW40c57dCFHEyw7iE_ab7oiZetFWITdCUgY5MLSs1o-xlil4_F_TuybwsEuoFn3A3XDXG24xxb9WaQldFdttJBRZLe6Z8Dw1_NspvvCgVJ77ceh9RmXqiYf_8wQ9DbIyYtMCQRQ82s1N8Vozp2vtNDjxGbfiX2lLVBGrfJKQLjzvFx5ZUVsieO05-yReMPT4l8NOMIfTY6B1xsuturcJzOpusYSqA0g8aYT6zxhsG9Oqb527hQEUMQMNxYX9whUVdTSJetragNAi4_WgAWtn9VbYyc3ipIl0hOpmQxUrb89t-9U\", \"use\": \"sig\"}, {\"e\": \"AQAB\", \"kid\": \"interop-rsa4096-02\", \"kty\": \"RSA\", \"n\": \"0gEgq4RoD86aQof6bQT2My-uS8zHxwMDCbU_wVViPvcErbN5OAU98RIE1F9Sd64fOF3u62XnVeaqN7_zZw_ZQtM5twLrqobmmmy4L6x0a-GMeGbKyuPTp9DRrdSCDE-XjYQfh7yKMNCqgVPRnkMx-XzAjerk4pfWFVL9Q827SBqipbmR9dTT6hAkqo44nJ_oa9YcPEO9Phni8khAWI4TmEJKQj-8N1G5V4IFScERc22UqVgNhGk0S5ydqVvLsTkVfxn_PiDT7_g10dawo2Y0H9XVQzdouoHWXRtPU6QtggImxS8aRqAxnuCeJbO9VBN79j8DqmmvlqSmbLkX01JW9qmiSc3ZdWIe8iKY5kdTcS0yVM3fOYVxzT1kNu9AG-KPCvQ06YnvgRXlvwnjEwyBnZ7ogpBNeTtzeAJ5hlN_ZRJGALSHHsJ6dgHKzjktDDzl-b4uW4DD8LVmgq_9hlSRWZ3jjchwO9_T9Sapbn5458TcJn0jBOn47oiomzKyY5e49soC2fxmCHIYKuDCAsraF18aDyz4YYzD65HfxB0KrX4A4sHgrQ6eihp9Csxg069l_w_HnyNCJvfg-qhnJ-v05VitF6McuSwSxo4UW3IN-uCR_9v2Ar2EUuVmSdQ-uKNPVOMcUHMALEkxp0q5I7ZV-tK8xRjEG_m3LsXLuIRFHAE\"}, {\"crv\": \"P-256\", \"kid\": \"interop-ecdsa-p256-02\", \"kty\": \"EC\", \"x\": \"klb_BCh_k7AvdQ7uaseCm90v6j70MSzi9GjVWM83enU\", \"y\": \"AsfKAEjWjgaBHtcr2ZnjgwMkBmh2JEpM29vcyJNEcsE\"}, {\"e\": \"AQAB\", \"kid\": \"32d8a321-1568-44f5-9558-a9072f519d2d\", \"kty\": \"RSA\", \"n\": \"48w_yMYGZmYWL3k8OejIYA1vrhDh1nRT6Mvsk10hEP5fCkQfU3eUEK9H9TLpCzOfAchFxs7TokitkniDOoE9oi5OL-qWoYf6XI0-eFk40xv0YZPUteJYoGVLLVjycU3aPwXKidk5Xy3rk8T67p7xjI6XfRJuFia1Zd9R_HBfbelKU565d9qXYHpYrNxuiM8o3cwc6famBeMU7nHhBCpe0FOFsSgyfEACnNral-67T5WO76heqlgwNYPCkVv5Uz7CmfUZ2MzdzAp9ZiPi3B-XlPhhm9STxFsBLEDZLel7M7eHM8q6TmDtxSQEExjLenMzT8IiyU43CCu17Fed7dYVrw\"}]}";
            PublicKey publicKey = JWTValidator.retrievePubKeyFromJWKS(content, value);
            setPublicKey(publicKey);
            isValid = true;
        }
        return isValid;
    }
    
    protected Boolean checkTyp(String claimName, String typ) {
        return typ.equals("at+jwt");
    }

    protected Boolean checkExp(String claimName, Long exp) {
        Boolean isValid = false;
        setExp(exp);
        log.debug(String.format("Validazione del claim exp: %d", exp));
        long now = Instant.now().getEpochSecond();
        
        if (DateUtils.isAfter(DateUtils.fromSecondsSinceEpoch(exp), DateUtils.fromSecondsSinceEpoch(now), timestampSkew)) {
            isValid = true;
            log.debug("Valore del claim exp rispetto al momento attuale: " + isValid);
        }
        return isValid;
    }

    protected Boolean checkIat(String claimName, Long iat) {
        Boolean isValid = false;
        setIat(iat);
        log.debug(String.format( "Validazione del claim iat: %d", iat));
        long now = Instant.now().getEpochSecond();


        if (DateUtils.isAfter(DateUtils.fromSecondsSinceEpoch(now), DateUtils.fromSecondsSinceEpoch(iat), timestampSkew)) {
            isValid = true;
            log.debug("Valore del claim iat rispetto al momento attuale: " + isValid);
        }
        return isValid;
    }
    
    protected Boolean checkNbf(String claimName, Long nbf) {
        Boolean isValid = false;
        setNbf(nbf);
        log.debug(String.format( "Validazione del claim nbf: %d", nbf));
        long now = Instant.now().getEpochSecond();


        if (DateUtils.isAfter(DateUtils.fromSecondsSinceEpoch(now), DateUtils.fromSecondsSinceEpoch(nbf), timestampSkew)) {
            isValid = true;
            log.debug("Valore del claim nbf rispetto al momento attuale: " + isValid);
        }
        return isValid;
    }
    
    protected boolean checkAud(String claimName, String audFromJWT)
    {
    	return StringUtils.isNotBlank(audFromJWT);
    }
    
    protected boolean checkIss(String claimName, String iss)
    {
    	return StringUtils.isNotBlank(iss);
    }
    
    protected boolean checkPurposeId(String claimName, String purposeid)
    {
    	return StringUtils.isNotBlank(purposeid);
    }
    
    protected boolean checkClientId(String claimName, String clientid)
    {
    	return StringUtils.isNotBlank(clientid);
    }
    
    public void setUrlPdndJwks(String urlPdndJwks) {
        this.urlPdndJwks = urlPdndJwks;
    }
    
    
}
