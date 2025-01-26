package com.security.spring_security.exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAccessDeniedHandler.class);

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {

        logger.error("Access denied. Message - {}", accessDeniedException.getMessage());
        logger.error("Requested URL - {}", request.getRequestURL());
        logger.error("Requested Method - {}", request.getMethod());
        logger.error("Remote Address - {}", request.getRemoteAddr());

        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied!");
    }
}

