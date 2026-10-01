# ruleid: ruby-hardcoded-session-secret
set :session_secret, "dev_secret_change_me"
# ruleid: ruby-hardcoded-session-secret
use Rack::Session::Cookie, key: "s", secret: "hunter2"

def issue(user)
  # ruleid: ruby-jwt-hardcoded-or-unverified
  JWT.encode({ sub: user.id }, "jwt_secret", "HS256")
end

def current_claims(tok)
  # ruleid: ruby-jwt-hardcoded-or-unverified
  JWT.decode(tok, nil, false)
end

def reset_code
  # ruleid: ruby-weak-random-token
  rand(100000..999999).to_s
end

def good_code
  # ok: ruby-weak-random-token
  SecureRandom.hex(16)
end

def check(api_token, given)
  # ruleid: ruby-timing-unsafe-secret-compare
  api_token == given
end

class AdminController < ApplicationController
  # ruleid: ruby-rails-skip-auth-filter
  skip_before_action :authenticate_user!, only: [:export]
  # ok: ruby-rails-skip-auth-filter
  skip_before_action :set_locale

  def user_params
    # ruleid: ruby-rails-permit-sensitive-attribute
    params.require(:user).permit(:name, :email, :role)
  end

  def safe_params
    # ok: ruby-rails-permit-sensitive-attribute
    params.require(:user).permit(:name, :email)
  end

  def admin?
    # ruleid: ruby-cookie-based-authorization
    cookies[:role] == "admin"
  end

  def local?
    # ruleid: ruby-ip-based-auth-spoofable
    request.headers["X-Forwarded-For"] == "127.0.0.1"
  end
end

post "/register" do
  # ruleid: ruby-mass-assignment-raw-params
  User.create(params)
end

# ruleid: ruby-debug-error-pages
set :show_exceptions, true

def valid_host?(h)
  # ruleid: ruby-regex-validation-line-anchors
  h =~ /^[a-z0-9.]+$/
end

def valid_host2?(h)
  # ok: ruby-regex-validation-line-anchors
  h =~ /\A[a-z0-9.]+\z/
end
