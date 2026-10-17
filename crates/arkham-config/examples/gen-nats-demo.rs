//! Write gitignored NATS nkey and user-JWT material for the integration demo.
//!
//! The operator, account, and user JWTs are signed with `nkeys` over the
//! ASCII `header.payload` input. Private keys stay under `integration/out`.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use arkham_config::grants::NatsScope;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let root = PathBuf::from(std::env::args().nth(1).ok_or("usage: gen-nats-demo <repo-root>")?);
  let out = root.join("integration/out");
  let nats = out.join("nats");
  fs::create_dir_all(&nats)?;

  let iat = unix_secs()?;
  let operator = nkeys::KeyPair::new_operator();
  let account = nkeys::KeyPair::new_account();
  let account_public = account.public_key();
  let operator_jwt = sign_jwt(&operator, &operator_payload(&operator.public_key(), iat))?;
  let account_jwt = sign_jwt(&operator, &account_payload(&account_public, &operator.public_key(), iat))?;

  let nkey_fake = user_pair()?;
  let nkey_real = user_pair()?;
  let jwt_fake = user_pair()?;
  let jwt_real = user_pair()?;
  let foreign_nkey = user_pair()?;
  let foreign_jwt_user = user_pair()?;
  let foreign_account = nkeys::KeyPair::new_account();

  let jwt_fake_token = sign_jwt(&account, &user_payload(&jwt_fake.public_key, &account_public, iat, "fake"))?;
  let jwt_real_token = sign_jwt(&account, &user_payload(&jwt_real.public_key, &account_public, iat, "real"))?;
  let foreign_jwt = sign_jwt(
    &foreign_account,
    &user_payload(&foreign_jwt_user.public_key, &foreign_account.public_key(), iat, "foreign"),
  )?;

  let nkey_fake_url = format!("nats://nkey:{}@nats:4222", nkey_fake.seed);
  let nkey_real_url = format!("tls://nkey:{}@nats:4222?sslrootcert=/certs/ca.crt", nkey_real.seed);
  let jwt_fake_url = format!("nats://creds:{}:{jwt_fake_token}@nats-jwt:4223", jwt_fake.seed);
  let jwt_real_url = format!(
    "tls://creds:{}:{jwt_real_token}@nats-jwt:4223?sslrootcert=/certs/ca.crt",
    jwt_real.seed
  );
  NatsScope::from_strings(&nkey_fake_url, &nkey_real_url)?;
  NatsScope::from_strings(&jwt_fake_url, &jwt_real_url)?;

  let template = fs::read_to_string(root.join("integration/arkham.toml"))?;
  let rendered = replace_sentinel(&template, "SU_FAKE_USER_SEED", &nkey_fake.seed)?;
  let rendered = replace_sentinel(&rendered, "SU_FAKE_JWT_SEED", &jwt_fake.seed)?;
  let rendered = replace_sentinel(&rendered, "FAKE_USER_JWT", &jwt_fake_token)?;
  fs::write(out.join("arkham.toml"), rendered)?;

  fs::write(nats.join("operator.jwt"), format!("{operator_jwt}\n"))?;
  fs::write(nats.join("server.conf"), server_conf(&nkey_real.public_key))?;
  fs::write(nats.join("jwt.conf"), jwt_conf(&account_public, &account_jwt))?;

  let env = format!(
    "ARKHAM_NATS_NKEY_REAL='{nkey_real_url}'\nARKHAM_NATS_JWT_REAL='{jwt_real_url}'\nNATS_NKEY_URL='{nkey_fake_url}'\nNATS_JWT_URL='{jwt_fake_url}'\nNATS_NKEY_FOREIGN='{foreign_nkey}'\nNATS_JWT_FOREIGN_SEED='{foreign_seed}'\nNATS_JWT_FOREIGN_JWT='{foreign_jwt}'\nNATS_NKEY_REAL_SEED='{nkey_real_seed}'\nNATS_JWT_REAL_ASSERT='{jwt_real_token}'\n",
    foreign_nkey = foreign_nkey.seed,
    foreign_seed = foreign_jwt_user.seed,
    nkey_real_seed = nkey_real.seed,
  );
  fs::write(nats.join("nats.env"), env)?;
  Ok(())
}

struct UserPair {
  seed: String,
  public_key: String,
}

fn user_pair() -> Result<UserPair, Box<dyn std::error::Error>> {
  let pair = nkeys::KeyPair::new_user();
  Ok(UserPair {
    seed: pair.seed()?,
    public_key: pair.public_key(),
  })
}

fn unix_secs() -> Result<i64, Box<dyn std::error::Error>> {
  let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
  Ok(i64::try_from(secs)?)
}

fn operator_payload(public: &str, iat: i64) -> Value {
  json!({
    "jti": format!("operator-{public}"),
    "iat": iat,
    "iss": public,
    "name": "arkham-demo",
    "sub": public,
    "nats": { "type": "operator", "version": 2 }
  })
}

fn account_payload(public: &str, issuer: &str, iat: i64) -> Value {
  json!({
    "jti": format!("account-{public}"),
    "iat": iat,
    "iss": issuer,
    "name": "demo",
    "sub": public,
    "nats": {
      "limits": {
        "subs": -1,
        "data": -1,
        "payload": -1,
        "imports": -1,
        "exports": -1,
        "wildcards": true,
        "conn": -1,
        "leaf": -1
      },
      "type": "account",
      "version": 2
    }
  })
}

fn user_payload(public: &str, issuer: &str, iat: i64, name: &str) -> Value {
  json!({
    "jti": format!("user-{public}"),
    "iat": iat,
    "iss": issuer,
    "name": name,
    "sub": public,
    "nats": {
      "pub": { "allow": [">"] },
      "sub": { "allow": [">"] },
      "subs": -1,
      "data": -1,
      "payload": -1,
      "type": "user",
      "version": 2
    }
  })
}

fn sign_jwt(issuer: &nkeys::KeyPair, payload: &Value) -> Result<String, Box<dyn std::error::Error>> {
  let header = json!({ "typ": "JWT", "alg": "ed25519-nkey" });
  let head = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
  let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?);
  let input = format!("{head}.{body}");
  let sig = issuer.sign(input.as_bytes())?;
  nkeys::KeyPair::from_public_key(&issuer.public_key())?.verify(input.as_bytes(), &sig)?;
  Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

fn replace_sentinel(text: &str, sentinel: &str, value: &str) -> Result<String, Box<dyn std::error::Error>> {
  if !text.contains(sentinel) {
    return Err(format!("integration/arkham.toml is missing {sentinel}").into());
  }
  Ok(text.replace(sentinel, value))
}

fn server_conf(real_public: &str) -> String {
  const NATS_PASSWORD: &str = "arkham_real_nats_pass"; // betterleaks:allow
  format!(
    "\
port: 4222
http_port: 8222
tls {{
  cert_file: /certs/nats.crt
  key_file: /certs/nats.key
}}
authorization {{
  users: [
    {{ user: agent, password: {NATS_PASSWORD} }}
    {{ nkey: {real_public} }}
  ]
}}
cluster {{
  no_advertise: true
}}
"
  )
}

fn jwt_conf(account_public: &str, account_jwt: &str) -> String {
  format!(
    "\
port: 4223
http_port: 8222
tls {{
  cert_file: /certs/nats.crt
  key_file: /certs/nats.key
}}
operator: /etc/nats/operator.jwt
resolver: MEMORY
resolver_preload: {{
  {account_public}: \"{account_jwt}\"
}}
cluster {{
  no_advertise: true
}}
"
  )
}
