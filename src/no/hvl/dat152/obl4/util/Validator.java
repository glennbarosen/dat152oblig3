package no.hvl.dat152.obl4.util;
// use lang.StringEscapeUtils to escape SQL
// import org.apache.commons.lang.StringEscapeUtils;

import org.apache.commons.codec.binary.Base64;
// use text.StringEscapeUtils to espace HTML since escapeHtml from commong.lang is deprecated
import org.apache.commons.text.StringEscapeUtils;

import java.security.SecureRandom;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class Validator {

	public static String validString(String parameter) {

		// Changing this to escapeSql til to escape sql.
		return parameter != null ? StringEscapeUtils.escapeHtml4(parameter) : "null";
		//return parameter != null ? StringEscapeUtils.escapeSql(parameter) : "null";
	}
	
	public static boolean validPassword(String password){
		return password.length() >= 8;
	}

	public static String validHTML(String s) { 
		return s != null ? StringEscapeUtils.escapeHtml4(s) : "null";
	}
	
	public static void generateCSRFToken(HttpServletRequest request) {
        SecureRandom sr = new SecureRandom();
        byte[] csrf = new byte[16];
        sr.nextBytes(csrf);
        String token = Base64.encodeBase64URLSafeString(csrf);
        request.getSession().setAttribute("csrftoken", token);
    }

    public static boolean isCSRFTokenMatch(HttpServletRequest request) {
        HttpSession session = request.getSession();
        // get the token from the session
        String sessionToken = (String) session.getAttribute("csrftoken");
        // get the token submitted with the form
        String requestToken = request.getParameter("csrftoken");
        // check whether they match
        if (sessionToken.equals(requestToken))
            return true;
        else {
            return false;
        }
    }
	
}
