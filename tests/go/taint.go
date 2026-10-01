package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

func getUser(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	q := "SELECT id FROM users WHERE name = '" + name + "'"
	// ruleid: go-taint-sqli
	rows, _ := db.Query(q)
	// ok: go-taint-sqli
	rows2, _ := db.Query("SELECT id FROM users WHERE name = $1", name)
	id, _ := strconv.Atoi(r.FormValue("id"))
	// ok: go-taint-sqli
	rows3, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
	_, _, _ = rows, rows2, rows3
}

func ping(c *gin.Context) {
	host := c.Query("host")
	// ruleid: go-taint-command-injection
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	c.String(200, string(out))
}

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	p := filepath.Join("/srv/files", name)
	// ruleid: go-taint-path-traversal
	data, _ := os.ReadFile(p)
	// ok: go-taint-path-traversal
	data2, _ := os.ReadFile(filepath.Join("/srv/files", filepath.Base(name)))
	w.Write(append(data, data2...))
}

func fetch(c *gin.Context) {
	target := c.Query("url")
	// ruleid: go-taint-ssrf
	resp, err := http.Get(target)
	if err == nil {
		resp.Body.Close()
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	// ruleid: go-taint-xss
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
	// ruleid: go-taint-xss
	_ = template.HTML("<b>" + name + "</b>")
}

func render(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("tpl")
	// ruleid: go-taint-ssti
	t, _ := template.New("x").Parse(body)
	t.Execute(w, currentUser(r))
}

func next(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-taint-open-redirect
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

func login(w http.ResponseWriter, r *http.Request) {
	var filter map[string]interface{}
	json.NewDecoder(r.Body).Decode(&filter)
	// ruleid: go-taint-nosqli
	res := users.FindOne(r.Context(), filter)
	_ = res
}
