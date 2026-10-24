export const OIDC_APP_CONFIG = `Issuer         https://auth.example.com
Discovery      https://auth.example.com/.well-known/openid-configuration
Client ID      my-app
Client secret  (Secret clients only, shown once in the console)
Redirect URI   https://app.example.com/oauth/callback
Scopes         openid profile email groups offline_access

Authorize      https://auth.example.com/oauth/authorize
Token          https://auth.example.com/oauth/token
UserInfo       https://auth.example.com/oauth/userinfo
Logout         https://auth.example.com/oauth/logout
JWKS           https://auth.example.com/jwks.json`

export const SERVER_ENV = `OIDC_ISSUER=https://auth.example.com
OIDC_FRONTEND_ORIGIN=https://auth.example.com
OIDC_ALLOWED_HOSTS=auth.example.com
OIDC_TRUSTED_PROXIES=127.0.0.1
OIDC_SECRET_KEY=<long random value, kept outside data/>`

export const CADDY_OIDC = `auth.example.com {
	encode gzip
	reverse_proxy 127.0.0.1:8000
}`

export const NGINX_OIDC = `server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }
}`

export const CADDY_FORWARD = `app.example.com {
	encode gzip

	# /session/* is served on this host, so the session cookie is bound to
	# app.example.com only (no Domain), never to *.example.com.
	handle /session/* {
		reverse_proxy 127.0.0.1:8000
	}

	handle {
		forward_auth 127.0.0.1:8000 {
			uri /session/check
			copy_headers Remote-User Remote-Email Remote-Name Remote-Groups

			@denied status 401 403
			handle_response @denied {
				redir * {http.reverse_proxy.header.Location}
			}
		}

		reverse_proxy 127.0.0.1:3000
	}
}`

export const NGINX_FORWARD = `server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

    # /session/* is served on this host, so the session cookie is bound to
    # app.example.com only (no Domain), never to *.example.com.
    location /session/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header Cookie            $http_cookie;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    }

    location = /_session_check {
        internal;
        proxy_pass http://127.0.0.1:8000/session/check;
        proxy_pass_request_body off;
        proxy_set_header Content-Length    "";
        proxy_set_header Host              $host;
        proxy_set_header Cookie            $http_cookie;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Uri   $request_uri;
    }

    location / {
        auth_request /_session_check;
        auth_request_set $auth_user   $upstream_http_remote_user;
        auth_request_set $auth_email  $upstream_http_remote_email;
        auth_request_set $auth_name   $upstream_http_remote_name;
        auth_request_set $auth_groups $upstream_http_remote_groups;
        auth_request_set $auth_login  $upstream_http_location;
        error_page 401 403 = @session_login;

        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Remote-User       $auth_user;
        proxy_set_header Remote-Email      $auth_email;
        proxy_set_header Remote-Name       $auth_name;
        proxy_set_header Remote-Groups     $auth_groups;
    }

    location @session_login {
        return 302 $auth_login;
    }
}`

export const FORWARD_HEADERS = `Remote-User:   alice
Remote-Email:  alice@example.com
Remote-Name:   Alice Martin
Remote-Groups: users,devs`
