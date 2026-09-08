package ru.greenatom.gateway.security;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

/**
 * Выдача сессионной cookie. Атрибут SameSite не выставляется
 * ни здесь, ни в фильтрах выше — сработка подтверждается.
 */
@Component
public class SessionCookieFactory {

    private static final String COOKIE_NAME = "ATOMID_SESSION";

    public void issueSession(HttpServletResponse response, String sessionId) {
        Cookie cookie = new Cookie(COOKIE_NAME, sessionId);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(-1);

        response.addCookie(cookie);
    }
}
