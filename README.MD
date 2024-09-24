# Ip Access Manager

This is a simple application for use with the Traefik forward-auth middleware. It allows temporary access for an ip using a separate authentication service.
The access is revoked at a fixed time of day.

## Why does this exist?
There are some services that cannot be properly protected by proxy-level authentication using a service like Authelia. For example Jellyfin: While you can log into Authelia on the web interface and everything works as expected, the same cannot be said for the app. There you cannot use any authentication system other than the one native to Jellyfin.

This project helps to work around this by not requiring any modification to server or client by using the ip address for validation.

# Traefik Configuration

Dynamic configuration:
```yaml
http:
  routers:
    ipmanager: # Used to authenticate an ip address
      rule: 'Host(`ipman.example.com`)'
      service: 'ipmanager'
      middlewares:
        - ipmanager-redirect
        - other-authenticator # Very important

    example_service:
        middlewares:
            - 'ipmanager'
        # ...

  services:
    ipmanager:
      loadBalancer:
        servers:
          - url: 'http://127.0.0.1:8080'
    
    example:
        # ...

  middlewares:
    ipmanager: # Used to che an ip
      forwardAuth:
        address: 'http://127.0.0.1:8080/allowed'
        trustForwardHeader: true
        authResponseHeaders: # Example for Authelia
          - 'Remote-User'
          - 'Remote-Groups'
          - 'Remote-Email'
          - 'Remote-Name'

    ipmanager-redirect: # Redirect to the correct api endpoint
      replacePath:
        path: "/authorize"
```

# API
## /allowed
Returns 200 when the ip is authorized, 403 otherwise. The headers given to `/authorize` that are configured in `headers` will be returned with for the same ip.

## /authorize
Authorizes the ip for the configured amount of time. All headers configured in `headers` will be saved, replacing the current values if the ip is already authorized.

# Config
The environment variable `CONFIG` specifies the path to a config file (Default: `config.toml`). The following formats are supported: toml, json, yaml, ini, ron, json5

`listen_address`
Address for the server to listen on. Default: `"127.0.0. 1:8080"` \
`threads`
Threads for processing the requests. Default: `1`  \
`headers`
List of headers to save from a `/authorize` request and return on a `/allowed` request for this ip. Default: `[]` \
`allow_list`
List of ip addresses that always are always allowed, but without any headers. Default: `[]`\
`days`
For how many additional days a authorization is valid for.  Default: `0` \
`hour`
The hour of the day to remove the authorizations in UTC. Default: `3`  \
`minute`
The minute to remove the authorizations in UTC. Default: `0`  \
`prune_interval`
Interval in which to prune the database in seconds.  Default: `3600`

# Logging
Logging is handled by env_logger. See [here](https://docs.rs/env_logger/0.11.5/env_logger/index.html) for the available configuration

# Security
* This project is **NOT** production ready. It has been written by a Rust novice and is barely tested. **It is not secure just because it is written in Rust.** This is the main reason I do not offer binary downloads.

* Any device sharing the same public ip will have the same access to the protected service. This must be kept in mind when using a public network. It is recommended to still use the native authentication of the service being proxied, if it is available.

# Limitations
* Because of the design choices of the `tiny_http` crate, headers can only contain ascii characters. If this is violated Traefik will report a "Bad Gateway"
* All times are in UTC because that was easier to program
* The messages and response codes are not customizable, other than by recompiling.
* *Should* work with IPv6, but isn't tested

Pull requests to improve this project are welcome