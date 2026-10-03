using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

public class NotesController : Controller
{
    private readonly SqlConnection _conn;
    private readonly AppDb _db;
    private readonly HttpClient _http;

    public IActionResult Get([FromQuery] string title)
    {
        var sql = "SELECT * FROM Notes WHERE Title = '" + title + "'";
        // ruleid: cs-taint-sqli
        var cmd = new SqlCommand(sql, _conn);
        // ruleid: cs-taint-sqli
        var notes = _db.Notes.FromSqlRaw(sql).ToList();
        // ok: cs-taint-sqli
        var cmd2 = new SqlCommand("SELECT * FROM Notes WHERE Title = @t", _conn);
        return Ok(notes);
    }

    public IActionResult Ping([FromQuery] string host)
    {
        // ruleid: cs-taint-command-injection
        Process.Start("/bin/sh", "-c \"ping -c 1 " + host + "\"");
        return Ok();
    }

    public IActionResult Download([FromRoute] string name)
    {
        // ruleid: cs-taint-path-traversal
        var path = Path.Combine("/srv/files", name);
        // ruleid: cs-taint-path-traversal
        return PhysicalFile(path, "application/octet-stream");
    }

    public IActionResult DownloadSafe([FromRoute] string name)
    {
        var safe = Path.GetFileName(name);
        // ok: cs-taint-path-traversal
        return PhysicalFile("/srv/files/" + safe, "application/octet-stream");
    }

    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        // ruleid: cs-taint-ssrf
        var body = await _http.GetStringAsync(url);
        return Ok(body);
    }

    public IActionResult Import([FromBody] string json)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        // ruleid: cs-taint-deserialization
        var obj = JsonConvert.DeserializeObject(json, settings);
        return Ok(obj);
    }

    public IActionResult Render([FromBody] string template)
    {
        // ruleid: cs-taint-ssti
        var html = Engine.Razor.RunCompile(template, "k", null, new { });
        return Ok(html);
    }

    public IActionResult Back([FromQuery] string returnUrl)
    {
        // ruleid: cs-taint-open-redirect
        return Redirect(returnUrl);
    }

    public IActionResult Hello([FromQuery] string name)
    {
        // ruleid: cs-taint-xss
        return Content("<h1>Hello " + name + "</h1>", "text/html");
    }
}
