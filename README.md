# Spring Security + OAuth 2.0 Demo Application

This application is intended as a simple minimalistic demo of Spring Security with multiple filter chains,
one of which allows authentication via third-party OAuth 2.0. It shows minimal necessary configuration needed
to obtain working proof of concept. It should not be used as a starting point for production deployable code.
Please see `Caveats` below for list of most egregious simplification made in this application. 

##  Postman

In `/postman` path of the sources, you can find a postman collection, which covers all the endpoints of the application
and describes expected usage flows, both happy/successful and unhappy/failing.

## Endpoints

There are four groups of endpoints in this application:

1. `/api/unsecured/demo` - allows access without authentication. This behaviour is typically used for various healthcheck endpoints, like those provided by Spring Boot Actuator.
2. `/api/demo` and `/api/admin/demo` - allows access to all authenticated users with role of USER or ADMIN respectively. Authenticates users via JWT. 
3. `/api/login` - allows to obtain JWT after authentication with HTTP Basic Auth (username + password). 
4. `/api/github/login` - allows to obtain JWT after passing OAuth 2.0 authentication with Github.

## HTTP Methods

This demo supports two methods: GET and POST.
1. For `/api/demo` endpoint normal users with USER role can do GET requests, while users with ADMIN role can also do POST requests.
2. For `/api/admin/demo` endpoint only ADMIN users can do both requests
3. All login endpoints only support GET requests
4. Unsecured endpoint support both requests without authentication

## Caveats

### Users

Since this is a demo project for authN/authZ and not for user management, two simplifications were made in this regard:
- User data is hardcoded and stored in-memory. Application does not allow for new users enrollment
- All Github authenticated users share an account inside the application (i. e. `subject` in JWT and corresponding role would be same for all of them)

Please, do not use this application as an example of user management approach.

### Cryptography.

Since this is a demo project for authN/authZ and not for cryptography, another two simplifications were made:
- Proper key management was not implemented: keys and secrets are stored openly in source code, which allows anyone with access to source code to easily bypass security measures.
- No encryption is applied to JWT, which store username as a `subject`, which means, those are stored in plaintext on client's devices

Please, do not use this application as an example of secure approach to cryptography.

## License

This project is provided under MIT License and can be freely used without restrictions.
