//! Diagnostic example: native delegated credential path, public output only.
//! This is NOT a proxy, policy probe, or protection status endpoint.
use anyhow::{Context, bail, ensure};
use spire_api::DelegatedIdentityClient;
use std::{str::FromStr, sync::Arc, time::Duration};
use ztunnel::{
    config,
    container_runtime::ContainerRuntimeManager,
    identity::{CaClientTrait, CacheKey, Identity, SpireClient},
    state::WorkloadInfo,
};

fn arguments(args: &[String]) -> anyhow::Result<(Identity, String, String)> {
    ensure!(
        args.len() == 3,
        "expected: fetch SPIFFE_ID POD_UID POD_NAME"
    );
    let id = Identity::from_str(&args[0]).context("invalid expected SPIFFE identity")?;
    let Identity::Spiffe {
        trust_domain,
        namespace,
        service_account,
    } = &id;
    for value in [
        trust_domain.as_str(),
        namespace.as_str(),
        service_account.as_str(),
        args[2].as_str(),
    ] {
        ensure!(
            !value.is_empty()
                && value.len() <= 253
                && value.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'.'),
            "noncanonical identity/name"
        );
    }
    ensure!(id.to_string() == args[0], "noncanonical identity");
    let uid = &args[1];
    ensure!(
        uid.len() == 36
            && uid
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }),
        "canonical Pod UID required"
    );
    Ok((id, uid.clone(), args[2].clone()))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("version") => {
            ensure!(args.next().is_none(), "version takes no arguments");
            println!("{}", ztunnel::version::BuildInfo::new());
            return Ok(());
        }
        Some("hold") => {
            ensure!(args.next().is_none(), "hold takes no arguments");
            tokio::time::sleep(Duration::from_secs(1800)).await;
            return Ok(());
        }
        Some("fetch") => {}
        _ => bail!("commands: hold | fetch SPIFFE_ID POD_UID POD_NAME"),
    }
    let (id, uid, name) = arguments(&args.collect::<Vec<_>>())?;
    let cfg = Arc::new(config::parse_config()?);
    let Identity::Spiffe {
        trust_domain,
        namespace,
        service_account,
    } = &id;
    ensure!(
        cfg.spire_enabled && cfg.cluster_domain == trust_domain.as_str(),
        "explicit SPIRE mode and exact local domain required"
    );
    let cert = tokio::time::timeout(Duration::from_secs(30), async {
        let dc = DelegatedIdentityClient::default()
            .await
            .context("SPIRE admin connection")?;
        let pid = ContainerRuntimeManager::new(&cfg)
            .await
            .context("node CRI connection")?;
        let client = SpireClient::new(dc, cfg.cluster_domain.clone(), Box::new(pid), cfg.clone());
        let key = CacheKey::Workload {
            id: id.clone(),
            uid: uid.clone().into(),
            workload: Arc::new(WorkloadInfo::new(
                name,
                namespace.to_string(),
                service_account.to_string(),
            )),
        };
        client
            .fetch_certificate(&key)
            .await
            .context("native PID-attested credential fetch")
    })
    .await
    .context("bounded credential probe timed out")??;
    // Deliberately never serialize Debug for WorkloadCertificate: it owns a key.
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "schemaVersion":1,"identity":id.to_string(),"podUID":uid,
            "publicCertificateChain":cert.cert_and_intermediates().iter().map(|c|c.as_pem()).collect::<Vec<_>>(),
            "privateKeyExported":false,"workloadAttestationPath":"native-ztunnel-CRI-PodUID-PID-delegated-SPIRE",
            "packetProtectionTested":false
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        vec![
            "spiffe://cmtc-a.mesh.example/ns/demo/sa/client".into(),
            "11111111-2222-3333-4444-555555555555".into(),
            "client".into(),
        ]
    }
    #[test]
    fn canonical_arguments() {
        assert!(arguments(&args()).is_ok());
    }
    #[test]
    fn rejects_identity_only_or_malformed_binding() {
        for value in [
            "",
            "11111111222233334444555555555555",
            "11111111-2222-3333-4444-55555555555Z",
        ] {
            let mut a = args();
            a[1] = value.into();
            assert!(arguments(&a).is_err());
        }
        for value in [
            "spiffe://cmtc-a.mesh.example/ztunnel-proxy",
            "spiffe://cmtc-a.mesh.example/ns//sa/client",
            "spiffe://cmtc-a.mesh.example/ns/demo/sa/client/extra",
        ] {
            let mut a = args();
            a[0] = value.into();
            assert!(arguments(&a).is_err());
        }
        assert!(arguments(&args()[..2]).is_err());
    }
}
