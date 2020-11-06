package no.hvl.dat152.obl4.controller;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import no.hvl.dat152.obl4.database.AppUser;
import no.hvl.dat152.obl4.database.AppUserDAO;
import no.hvl.dat152.obl4.dictionary.DictionaryDAO;
import no.hvl.dat152.obl4.util.Role;
import no.hvl.dat152.obl4.util.Validator;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private int sessionTimeoutLength = 300;

	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		request.getRequestDispatcher("login.jsp").forward(request, response);
	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		request.removeAttribute("message");
		request.removeAttribute("usernames");
		request.removeAttribute("updaterole");

		boolean successfulLogin = false;

		String username = request.getParameter("username");
		String password = request.getParameter("password");

		if (username != null && password != null) {

			AppUserDAO userDAO = new AppUserDAO();
			AppUser authUser = userDAO.getAuthenticatedUser(username, password);

			if (authUser != null) {
				successfulLogin = true;
				request.getSession().setAttribute("user", authUser);
				request.getSession().setAttribute("updaterole", "");
				request.getSession().setMaxInactiveInterval(sessionTimeoutLength);

				// admin issues
				if (authUser.getRole().equals(Role.ADMIN.toString())) {
                    List<String> usernames = userDAO.getUsernames();
                    request.getSession().setAttribute("usernames", usernames);
                    request.getSession().setAttribute("updaterole", "<a href=\"updaterole.jsp\">Update Role</a>");
                    // check that the dicturl cookie is set for the admin. If not, set the dictionary url cookie
                    String dictcookie = response.getHeader("dicturl");
                    if (dictcookie == null) {
                        response.setHeader("Set-Cookie", "dicturl=" + DictionaryDAO.DEFAULT_DICT_URL + "; " + "Max-Age=1000000");
                    }
                }
                response.addHeader("Set-Cookie", "SameSite=Strict");

                Validator.generateCSRFToken(request);
			}
		}

		if (successfulLogin) {
			response.sendRedirect("searchpage");

		} else {
			request.setAttribute("message", "Username " + username
					+ ": Login failed!");
			request.getRequestDispatcher("login.jsp")
					.forward(request, response);
		}
	}
}
