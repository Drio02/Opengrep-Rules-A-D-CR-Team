class NotesController < ApplicationController
  def index
    q = params[:q]
    # ruleid: ruby-taint-sqli
    @notes = Note.where("title LIKE '%#{q}%'")
    # ok: ruby-taint-sqli
    @notes = Note.where("title LIKE ?", "%#{q}%")
    # ok: ruby-taint-sqli
    @notes = Note.where(title: q)
    # ruleid: ruby-taint-sqli
    @sorted = Note.order(params[:sort])
    # ok: ruby-taint-sqli
    @limited = Note.limit(params[:n].to_i)
  end

  def ping
    host = params[:host]
    # ruleid: ruby-taint-command-injection
    system("ping -c 1 #{host}")
    # ok: ruby-taint-command-injection
    system("ping", "-c", "1", host)
  end

  def call
    # ruleid: ruby-taint-code-injection
    current_user.send(params[:action_name])
    # ruleid: ruby-taint-code-injection
    params[:type].constantize.new
  end

  def download
    name = params[:file]
    # ruleid: ruby-taint-path-traversal
    send_file(File.join("/srv/files", name))
    # ok: ruby-taint-path-traversal
    send_file(File.join("/srv/files", File.basename(name)))
  end

  def fetch
    # ruleid: ruby-taint-ssrf
    body = Net::HTTP.get(URI(params[:url]))
    render plain: body
  end

  def restore
    data = Base64.decode64(cookies[:prefs])
    # ruleid: ruby-taint-deserialization
    prefs = Marshal.load(data)
    # ok: ruby-taint-deserialization
    safe = JSON.parse(data)
  end

  def preview
    tpl = "Hello " + params[:name]
    # ruleid: ruby-taint-ssti
    html = ERB.new(tpl).result(binding)
    # ruleid: ruby-taint-ssti
    render inline: tpl
  end

  def show_bio
    # ruleid: ruby-taint-xss
    render html: params[:bio].html_safe
  end

  def back
    # ruleid: ruby-taint-open-redirect
    redirect_to params[:return_to]
  end
end
