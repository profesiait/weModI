package it.profesia.carbon.apimgt.gateway.handlers.security;

public class ModiAuthenticationHandlerException extends Exception {

    public ModiAuthenticationHandlerException(String message) {
        super(message);
    }

    public ModiAuthenticationHandlerException(String message, Throwable cause) {
        super(message, cause);
    }
}
