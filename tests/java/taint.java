package ctf;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.sql.*;
import javax.servlet.http.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.yaml.snakeyaml.Yaml;
import org.apache.velocity.app.Velocity;
import javax.naming.directory.DirContext;

@RestController
public class NotesController {
    private Connection conn;
    private RestTemplate rest = new RestTemplate();

    @GetMapping("/note")
    public String note(@RequestParam("id") String id) throws Exception {
        Statement st = conn.createStatement();
        String q = "SELECT body FROM notes WHERE id = '" + id + "'";
        // ruleid: java-taint-sqli
        ResultSet rs = st.executeQuery(q);
        // ok: java-taint-sqli
        PreparedStatement ps = conn.prepareStatement("SELECT body FROM notes WHERE id = ?");
        ps.setString(1, id);
        return rs.getString(1);
    }

    @GetMapping("/byid")
    public String byId(@RequestParam int id) throws Exception {
        Statement st = conn.createStatement();
        // ok: java-taint-sqli
        ResultSet rs = st.executeQuery("SELECT body FROM notes WHERE id = " + id);
        return rs.getString(1);
    }

    @PostMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        // ruleid: java-taint-command-injection
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return "ok";
    }

    @PostMapping("/calc")
    public Object calc(@RequestBody String expr) {
        SpelExpressionParser parser = new SpelExpressionParser();
        // ruleid: java-taint-code-injection
        return parser.parseExpression(expr).getValue();
    }

    @GetMapping("/file/{name}")
    public byte[] file(@PathVariable String name) throws Exception {
        // ruleid: java-taint-path-traversal
        Path p = Paths.get("/srv/files", name);
        // ok: java-taint-path-traversal
        Path ok = Paths.get("/srv/files").resolve(Paths.get(name).getFileName());
        return Files.readAllBytes(p);
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        // ruleid: java-taint-ssrf
        return rest.getForObject(url, String.class);
    }

    @PostMapping("/import")
    public Object importYaml(@RequestBody String body) {
        // ruleid: java-taint-deserialization
        return new Yaml().load(body);
    }

    public void legacy(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        // ruleid: java-taint-xss
        resp.getWriter().write("<h1>Hello " + name + "</h1>");
        // ruleid: java-taint-open-redirect
        resp.sendRedirect(req.getParameter("next"));
    }

    @GetMapping("/tpl")
    public void tpl(@RequestParam String t, Writer w) {
        // ruleid: java-taint-ssti
        Velocity.evaluate(ctx, w, "x", t);
    }

    @GetMapping("/ldap")
    public Object ldap(@RequestParam String user, DirContext ctx) throws Exception {
        String filter = "(uid=" + user + ")";
        // ruleid: java-taint-ldap-xpath-injection
        return ctx.search("ou=people,dc=ctf", filter, null);
    }
}
