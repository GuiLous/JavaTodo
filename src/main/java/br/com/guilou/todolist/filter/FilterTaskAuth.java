package br.com.guilou.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.guilou.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    var servletPath = request.getServletPath();

    if (servletPath.startsWith("/tasks/")) {
      var authorization = request.getHeader("Authorization");

      String authEncoded = authorization.split(" ")[1];

      byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

      String authString = new String(authDecoded);

      var username = authString.split(":")[0];
      var password = authString.split(":")[1];

      var user = this.userRepository.findByUsername(username);

      if (user == null) {
        response.sendError(401, "Usuário sem autoriação");
        return;
      }

      var passwordMatch = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

      if (passwordMatch.verified == false) {
        response.sendError(401, "Usuário sem autoriação");
        return;
      }

      request.setAttribute("idUser", user.getId());
    }

    filterChain.doFilter(request, response);
  }
}
