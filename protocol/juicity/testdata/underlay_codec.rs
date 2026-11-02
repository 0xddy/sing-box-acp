// Built as an example of the pinned upstream juicity-common crate.
use anyhow::{anyhow, Result};
use juicity_common::crypto::juicity_underlay::{decrypt_udp, encrypt_udp};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [op, key, salt, body] if op == "seal" => {
            let salt = hex::decode(salt)?
                .try_into()
                .map_err(|_| anyhow!("expected a 32-byte salt"))?;
            encrypt_udp(&hex::decode(key)?, &hex::decode(body)?, &salt)?
        }
        [op, key, packet] if op == "open" => {
            decrypt_udp(&hex::decode(key)?, &hex::decode(packet)?)?
        }
        _ => {
            return Err(anyhow!(
                "use seal KEY SALT PAYLOAD or open KEY PACKET (hex)"
            ))
        }
    };
    println!("{}", hex::encode(result));
    Ok(())
}
