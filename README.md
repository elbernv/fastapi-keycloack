# FastAPI Resource Server

Keycloack plugin for FastApi.

Your aplication receives the claims decoded from the access token.

# Usage

Run keycloak on port 8080 and configure your keycloack server:

```sh
docker run -p 8080:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin quay.io/keycloak/keycloak:15.0.2
```

Install dependencies

```sh
pip install fastapi fastapi-keycloack uvicorn
```

Create the main.py module

```python
from fastapi import Depends, FastAPI, Security

from fastapi_keycloack import JwtDecodeOptions, FastApiKeycloack, GrantType

app = FastAPI()

decode_options = JwtDecodeOptions(verify_aud=False)
allowed_grant_types = [
    GrantType.IMPLICIT,
    GrantType.PASSWORD,
    GrantType.AUTHORIZATION_CODE,
    GrantType.CLIENT_CREDENTIALS,
]

auth_scheme = FastApiKeycloack(
    url="http://localhost:8080/auth/realms/test-plugin",
    scheme_name="Keycloak",
    jwt_decode_options=decode_options,
    allowed_grant_types=allowed_grant_types,
)


def get_current_user(claims: dict = Security(auth_scheme)):
    return claims


@app.get("/users/me")
def read_current_user(claims: dict = Depends(get_current_user)):
    return claims

```

Run the application

```sh
uvicorn main:app
```
