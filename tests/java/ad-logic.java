package ctf;

import java.util.Random;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import io.jsonwebtoken.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.auth0.jwt.algorithms.Algorithm;

class Security {
    void configure(HttpSecurity http) throws Exception {
        // ruleid: java-spring-permitall-sensitive-path
        registry.requestMatchers("/admin/**").permitAll();
        // ok: java-spring-permitall-sensitive-path
        registry.requestMatchers("/login").permitAll();
        // ruleid: java-spring-csrf-disabled
        http.csrf().disable();
    }
}

class Tokens {
    String issue(String user) {
        // ruleid: java-jwt-hardcoded-key
        return Jwts.builder().setSubject(user).signWith(SignatureAlgorithm.HS256, "secret").compact();
    }

    // ruleid: java-jwt-hardcoded-key
    Algorithm alg = Algorithm.HMAC256("changeme");

    String reset() {
        // ruleid: java-weak-random-token
        return String.valueOf(new Random(System.currentTimeMillis()).nextInt(999999));
    }

    boolean check(String apiToken, String given) {
        // ruleid: java-timing-unsafe-secret-compare
        return apiToken.equals(given);
    }

    boolean isAdmin(String role) {
        // ruleid: java-string-reference-compare
        return role == "admin";
    }

    void mapper(ObjectMapper m) {
        // ruleid: java-jackson-polymorphic-typing
        m.enableDefaultTyping();
    }
}

@RestController
class UserController {
    // ruleid: java-spring-mass-assignment
    @PostMapping("/users")
    public User create(@RequestBody User u) {
        return repo.save(u);
    }

    @GetMapping("/local")
    public String local(HttpServletRequest req) {
        // ruleid: java-ip-based-auth-spoofable
        String ip = req.getHeader("X-Forwarded-For");
        return "127.0.0.1".equals(ip) ? flag : "no";
    }

    // ruleid: java-cookie-based-authorization
    @GetMapping("/admin")
    public String admin(@CookieValue("role") String role) {
        return "admin".equals(role) ? flag : "no";
    }
}

@Controller
class PageController {
    // ruleid: java-spring-view-name-injection
    @GetMapping("/page")
    public String page(@RequestParam String lang) {
        return "welcome_" + lang;
    }

    // ok: java-spring-view-name-injection
    @GetMapping("/home")
    public String home(@RequestParam String lang) {
        return "home";
    }
}
