use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use rand::{rngs::StdRng, SeedableRng};

fn issue(claims: &Claims) -> String {
    // ruleid: rust-jwt-hardcoded-key
    encode(&Header::default(), claims, &EncodingKey::from_secret(b"secret")).unwrap()
}

fn check(token: &str, key: &DecodingKey) -> Claims {
    let mut v = Validation::default();
    // ruleid: rust-jwt-insecure-validation
    v.insecure_disable_signature_validation();
    // ruleid: rust-jwt-insecure-validation
    v.validate_exp = false;
    decode::<Claims>(token, key, &v).unwrap().claims
}

fn session_id() -> u64 {
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // ruleid: rust-predictable-rng
    let mut rng = StdRng::seed_from_u64(seed);
    rng.gen()
}

fn verify(api_token: &str, given: &str) -> bool {
    // ruleid: rust-timing-unsafe-secret-compare
    api_token == given
}

async fn admin(jar: CookieJar) -> String {
    // ruleid: rust-cookie-based-authorization
    let role = jar.get("role").map(|c| c.value().to_string());
    role.unwrap_or_default()
}

async fn local(headers: HeaderMap) -> bool {
    // ruleid: rust-ip-based-auth-spoofable
    headers.get("x-forwarded-for").map(|v| v == "127.0.0.1").unwrap_or(false)
}

fn app() -> Router {
    // ruleid: rust-cors-permissive
    Router::new().layer(CorsLayer::permissive())
}

fn read_slot(buf: &[u8], idx: usize) -> u8 {
    // ruleid: rust-unchecked-memory-ops
    unsafe { *buf.get_unchecked(idx) }
}

struct Shared(*mut u8);
// ruleid: rust-unsafe-send-sync-impl
unsafe impl Sync for Shared {}

// ruleid: rust-static-mut
static mut COUNTER: u32 = 0;

fn qty(s: &str) -> u8 {
    // ruleid: rust-lossy-integer-cast
    s.parse::<i64>().unwrap() as u8
}
