use sfta_rs::get_hash;

fn main() {
    // std::env::set_var("RUST_BACKTRACE", "1");
    let base_info = "robloxs-1-5-21-322128023-1596787588-1406545887-1001appxatmm9sengvzx4rehd29pf7cfqen9knc801d9bce5585a8400user";
    let base64_hash = get_hash(base_info);
    println!("Base64 Hash: {}", base64_hash);
}
