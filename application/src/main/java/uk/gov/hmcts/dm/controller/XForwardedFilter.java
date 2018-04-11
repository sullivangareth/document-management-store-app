package uk.gov.hmcts.dm.controller;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class XForwardedFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HeaderMapRequestWrapper wrappedRequest = new HeaderMapRequestWrapper(request);
        filterChain.doFilter(wrappedRequest, response);
    }

    private static class HeaderMapRequestWrapper extends HttpServletRequestWrapper {
        public HeaderMapRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Enumeration<String> headerNames = super.getHeaderNames();
            ArrayList<String> newHeaderNameList = new ArrayList<>();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                if (!Arrays.asList("x-forwarded-host", "x-forwarded-proto", "x-forwarded-port").contains(headerName)) {
                    newHeaderNameList.add(headerName);
                }
            }
            return Collections.enumeration(newHeaderNameList);
        }
    }
}

