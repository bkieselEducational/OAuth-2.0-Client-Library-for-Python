[<-- BACK](https://github.com/bkieselEducational/OAuth-SDKs)
# OAuth 2.0 Client Library for Python


## Incorporating a Google OAuth 2.0 flow in your python application:

### Step 1: Register your app on the Google Cloud Platform and generate your credentials.
[Google Cloud Platform OAuth Setup](https://github.com/bkieselEducational/OAuth-Google-Cloud-Console-Setup)

### Step 2: Add the requisite packages to your requirements.txt file

```python
# Here are the additional packages that will allow us to implement an Oauth flow
# You can paste the code below to the bottom of your requirements.txt

cachetools==5.3.1
certifi==2023.7.22
charset-normalizer==3.2.0
google-auth-oauthlib==1.0.0
google-auth==2.22.0
oauthlib==3.2.2
requests-oauthlib==1.3.1
requests==2.31.0
rsa==4.9
urllib3==1.26.16
psycopg2==2.9.9
```

### Step 3: You will need to adjust your User model to allow for NULL passwords.

```python
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    if environment == "production":
        __table_args__ = {'schema': SCHEMA}
    ...
    ...
    hashed_password = db.Column(db.String(255), nullable=True, default=None)
    ...
    ...
```

### Step 4: Choose a file to house the 2 necessary endpoints to implement an OAuth flow. (This example simply uses auth_routes.py from the starter). In this file we must not only write our endpoints code, but must configure our Flow class from the oauth SDK.

```python
# Add the necessary imports to the top of your route file!
import os

import requests
from flask import abort, redirect # note that you can slap these 2 imports at the end of the 'from flask import' statement that you probably already have.
from google.oauth2 import id_token
from google_auth_oauthlib
from pip._vendor import cachecontrol
import google.auth.transport.requests
from tempfile import NamedTemporaryFile
import json
```

```python
############ OAUTH 2.0 SETUP #####################################################################
# Here we will configure our Flow class and also perform some other preliminary setup steps.

# We need to allow HTTP traffic for local dev
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

"""
As the flow object requires a file path to load the configuration from AND
we want to keep our credentials safe (out of our github repo!!).
We will create a temporary file to hold our values as json.
Some of these values will come from our .env file.
"""

# Import our credentials from the .env file
CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')
CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID')

# The dictionary to be written out as JSON
client_secrets = {
  "web": {
    "client_id": CLIENT_ID,
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": CLIENT_SECRET,
    "redirect_uris": [
      "http://localhost:8000/api/auth/callback"
    ]
  }
}

"""
Below we are generating a temporary file as the google oauth package requires a file for configuration!
Note that the property '.name' is the file PATH to our temporary file!
"""
secrets = NamedTemporaryFile()

# The command below will write our dictionary to the temp file AS json!
with open(secrets.name, "w") as output:
    json.dump(client_secrets, output)

# Below we will generate a configuration class from our JSON formatted file along with a session class for the flow.
oauth2_session, client_config = google_auth_oauthlib.helpers.session_from_client_secrets_file(
    secrets.name,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
)

secrets.close() # This method call deletes our temporary file from the /tmp folder! We no longer need it as our flow object has been configured!

"""
Initializing our flow class below, note that there is a parameter named 'autogenerate_code_verifier'
which is not shown as it has a default value of True, which is preceisely what we want.
As a result, our flow class constructor will generate a code verifier for us and transmit it in
URL parameters of the first redirect in our OAuth flow.
"""
flow = google_auth_oauthlib.flow.Flow(
    oauth2_session,
    client_type='web',
    client_config=client_config,
    redirect_uri="http://localhost:8000/api/auth/callback",
)

############ END OAUTH 2.0 SETUP ##########################################################################
```

```python
# Our OAuth flow initiating endpoint.

@auth_routes.route("/oauth_login")
def oauth_login():
    authorization_url, state = flow.authorization_url(prompt="select_account consent")
    # print("AUTH URL: ", authorization_url) # I recommend that you print this value out to see what it's generating.
    """
    Ex: https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=<Your Clien ID>&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fapi%2Fauth%2Fcallback&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+openid&state=MTSa8pz4vH4Tpgl6qVaISesExrPpBE&code_challenge=bpJG7pNYuCkA-8CZ6lo-P-GbvdOeYpXTCXT6ZB2j-4o&code_challenge_method=S256&prompt=select_account+consent&access_type=offline
    It SHOULD look a lot like the URL in the SECOND or THIRD line of our flow chart!

    Note that in the auth url above the value 'access_type' is set to 'offline' by default. Without this parameter being set, we would not receive a Refresh Token with our Access Token.
    Additionally, the values we passed in to the prompt property will garauntee that we see the screen to select our google account
    regardless of wether or not we are currently logged in with Google. After which we will see the Consent Screen for our application.
    """

    # The call to authorization_url() above is generating the random 'state' value that we will use as CSRF protection for our flow.
    session["state"] = state # We will save it into flask state so that we can verify later.

    # We will also extract the Referer Header from the original request sent by our client so that we can send them back to the page they were on when they initiated authentication with Google.
    referrer = request.headers.get('Referer') # Contains the URL from which the request came.
    session["referrer"] = referrer

    return redirect(authorization_url) # This line technically will enact the SECOND and THIRD lines of our flow chart.

```

```python
# The famous redirect_uri is our 2nd endpoint.

@auth_routes.route("/callback")
def callback():
    # Exchange the ephemeral 'code' returned by Google for an Access Token.
    flow.fetch_token(authorization_response=request.url) # This method is sending the request depicted on line 6 of our flow chart! The response is depicted on line 7 of our flow chart.

    # This is our CSRF protection for the Oauth Flow!
    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials # These should be the user's credentials sent back with the Access Token from the fetch_token() call above!
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session) # Here we get an HTTP transport for our id token request.

    """
    The method call below will go through the tedious work of verifying the JWT signature of the JWT sent back with the object from OpenID Connect.
    Although I cannot verify, hopefully it is also testing the values for "sub", "aud", "iat", and "exp" sent back in the CLAIMS section of the JWT
    Additionally note, that the oauth initializing URL generated in the previous endpoint DID NOT send a random nonce value. (As depicted in our flow chart)
    If it had, the server would return the nonce in the JWT claims to be used for further verification tests!

    The signature validation will require fetching the rsa key components from the google certs endpoint:
    https://www.googleapis.com/oauth2/v1/certs
    """
    id_info = id_token.verify_oauth2_token(  # Returns the decoded id_token claims if signature verification succeeds.
        id_token=credentials._id_token,
        request=token_request,
        audience=CLIENT_ID,
        clock_skew_in_seconds=5
    )

    # Now we generate a new session for the newly authenticated user!!
    # Note that depending on the way your app behaves, you may be creating a new user at this point...
    temp_email = id_info.get('email')

    user_exists = User.query.filter(User.email == temp_email).first()

    if not user_exists:
        user_exists = User(
            username=id_info.get("name"),
            email=temp_email,
            password='OAUTH'
        )

        db.session.add(user_exists)
        db.session.commit()

    login_user(user_exists)

    return redirect(session['referrer']) # This will send the final redirect to our user's browser. As depicted in Line 8 of the flow chart!

```

### Step 5: We will need to install a link in our frontend code to allow our user to initiate the flow.
```javascript
  <a href={`${window.origin}/api/auth/oauth_login`}><button>OAUTH</button></a>
```
