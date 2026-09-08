package ru.greenatom.gateway.security;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * Проверка токена и выдача cookie авторизации.
 * Атрибут SameSite выставляется явно, поэтому сработка
 * cookie-missing-samesite для этого файла ложная.
 */
@Component
public class TokenValidationGateway {

    private static final String COOKIE_NAME = "ATOMID_TOKEN";
    private static final int MAX_AGE_SECONDS = 1800;

    public void issueToken(HttpServletResponse response, String token) {
        ResponseCookie secured = ResponseCookie.from(COOKIE_NAME, token)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(MAX_AGE_SECONDS)
                .sameSite("Lax")
                .build();

        response.addHeader("Set-Cookie", secured.toString());
    }

    public void issueLegacyToken(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(MAX_AGE_SECONDS);
        // Servlet API 3.1 не умеет SameSite напрямую — атрибут добавляется в заголовок ниже
        cookie.setComment("__SAME_SITE_LAX__");

        response.addCookie(cookie);
        response.setHeader("Set-Cookie",
                COOKIE_NAME + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Lax");
    }
}
