using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class Startup
{
    public void Configure(IServiceCollection services, IApplicationBuilder app)
    {
        services.AddAuthentication().AddJwtBearer(o =>
        {
            o.TokenValidationParameters = new TokenValidationParameters
            {
                // ruleid: cs-jwt-validation-disabled
                ValidateIssuerSigningKey = false,
                // ruleid: cs-jwt-validation-disabled
                ValidateLifetime = false,
                // ruleid: cs-hardcoded-signing-key
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("super_secret_key_123"))
            };
        });
        // ruleid: cs-dev-exception-page-or-open-cors
        app.UseDeveloperExceptionPage();
    }
}

public class Tokens
{
    public object Load(byte[] data)
    {
        // ruleid: cs-insecure-deserializer
        var bf = new BinaryFormatter();
        return bf.Deserialize(new MemoryStream(data));
    }

    public string Reset()
    {
        // ruleid: cs-weak-random-token
        return new Random().Next(100000, 999999).ToString();
    }

    public bool Check(string apiToken, string given)
    {
        // ruleid: cs-timing-unsafe-secret-compare
        return apiToken == given;
    }
}

public class NotesController : Controller
{
    public IActionResult Search(string q)
    {
        // ruleid: cs-ef-raw-sql-interpolation
        var r = _db.Notes.FromSqlRaw($"SELECT * FROM Notes WHERE Title LIKE '%{q}%'").ToList();
        // ok: cs-ef-raw-sql-interpolation
        var s = _db.Notes.FromSqlInterpolated($"SELECT * FROM Notes WHERE Title LIKE {q}").ToList();
        return Ok(r);
    }

    // ruleid: cs-mass-assignment-entity-binding
    public IActionResult Create([FromBody] User user)
    {
        _db.Users.Add(user);
        _db.SaveChanges();
        return Ok();
    }

    public IActionResult Admin()
    {
        // ruleid: cs-ip-or-cookie-based-auth
        if (Request.Cookies["role"] == "admin") return Ok(Flag);
        return Forbid();
    }
}

public class Client
{
    public HttpClient Make()
    {
        var h = new HttpClientHandler();
        // ruleid: cs-tls-validation-disabled
        h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
        return new HttpClient(h);
    }

    public XmlReaderSettings Xml()
    {
        var s = new XmlReaderSettings();
        // ruleid: cs-xxe-unsafe-xml
        s.DtdProcessing = DtdProcessing.Parse;
        return s;
    }
}
