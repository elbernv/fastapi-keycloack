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
