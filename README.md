# Spring Boot application as Hydra Identity Provider.

## Usage

### 1. Deploy obp-api server:
The props should contains the follow settings:
```
## if login_with_hydra set to true, all other props must not be empty
login_with_hydra=true
# hydra server urls
hydra_public_url=http://127.0.0.1:4444
hydra_admin_url=http://127.0.0.1:4445
# Consent names
hydra_consents=ReadAccountsBasic,ReadAccountsDetail,ReadBalances,ReadTransactionsBasic,"ReadTransactionsDebits,ReadTransactionsDetail
## check the oauth2.jwk_set.url props, it must contains jwks.json that locate in ${hydra_public_url}/.well-known/jwks.json
##oauth2.jwk_set.url=http://localhost:4444/.well-known/jwks.json,https://www.googleapis.com/oauth2/v3/certs
## whether create hydra client when create consumer, default is false
mirror_consumer_in_hydra=true
```

The obp-api server url example: `http://localhost:8080`

Login obp-api portal, create one consumer for project `OBP-Hydra-Identity-Provider`
The consumer_key example: `yp5tgl0thzjj1jk0sobqljpxyo514dsjvxoe1ngy`

### 2. Deploy `OBP-Hydra-Identity-Provider`:

execute command: `mvn clean package`

generate jar file in target folder: hydra-identity-provider-xxx.jar

Create application.properties file, and content as follows:
```
# current project port number
server.port=8086
spring.thymeleaf.encoding=UTF-8
spring.thymeleaf.servlet.content-type=text/html;

# hydra server urls
oauth2.admin_url=http://127.0.0.1:4445
oauth2.public_url=http://127.0.0.1:4444

# obp-api server url
obp.base_url=http://localhost:8080
# set consumer_key that generate in 1 step
consumer_key=yp5tgl0thzjj1jk0sobqljpxyo514dsjvxoe1ngy
```
make the application.properties file near to hydra-identity-provider-xxx.jar

execute command to start this project: `java -jar hydra-identity-provider-xxx.jar`

So the project running on `http://localhost:8086`

### 3. Deploy Hydra server
Check this reference [hydra 5min-tutorial](https://www.ory.sh/hydra/docs/5min-tutorial), to install hydra, take the Docker way as example.
Fix the quickstart.yml file as follows in environment part, the URL values is just step2 corresponding url, pay attention the leading blank characters, it is yml file.
```
      - URLS_CONSENT=http://localhost:8086/consent
      - URLS_LOGIN=http://localhost:8086/login
      - URLS_LOGOUT=http://localhost:8086/logout
```
execute this command to start the hydra server:
```
docker-compose -f quickstart.yml \
    -f quickstart-postgres.yml \
    -f quickstart-tracing.yml \
    up --build
```
The hydra server correponding url example:
```
oauth2.admin_url=http://127.0.0.1:4445
oauth2.public_url=http://127.0.0.1:4444
```
### 4. Deploy demo project `obp-hydra-auth2`:  `https://github.com/OpenBankProject/OBP-Hydra-OAuth2`

execute command: mvn clean package

generate jar file in target folder: obp-hydra-auth2-xxx.jar

crate file `application.properties`, and the content as follow:
```
# server port number
server.port=8081

# hydra server urls
oauth2.admin_url=http://127.0.0.1:4445
oauth2.public_url=http://127.0.0.1:4444
# login url that the same as hydra evironment: URLS_LOGIN
oauth2.authenticate_url=http://localhost:8086/login
obp.base_url=http://localhost:8080

# create one consumer, and copy OAuth2 information past here:
oauth2.client_id=z3xh2jrf4y2t3h0th0jbs0fs54zg1wqffoupexwy
oauth2.client_secret=1qxhj0uz3b5kvypi1lstqvfwysiyezuusdidxxih
oauth2.redirect_uri=http://127.0.0.1:8081/main.html
oauth2.client_scope=ReadAccountsBasic,\
ReadAccountsDetail,\
ReadBalances,\
ReadTransactionsBasic,\
ReadTransactionsDebits,\
ReadTransactionsDetail
```

make the application.properties file near to obp-hydra-auth2-xxx.jar

execute command to start this project: `java -jar obp-hydra-auth2-xxx.jar`

So the project running on `http://localhost:8081`

### 5. open web browser with url: [http://localhost:8081/index.html](http://localhost:8081/index.html)
