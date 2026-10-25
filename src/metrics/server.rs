// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use ::hyper_util::service::TowerToHyperService;
use bytes::Bytes;
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;

use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

use crate::config::Config;
use crate::drain::DrainWatcher;
use crate::hyper_util;

pub struct Server {
    s: hyper_util::Server<Mutex<Registry>>,
}

impl Server {
    pub async fn new(
        config: Arc<Config>,
        drain_rx: DrainWatcher,
        registry: Registry,
    ) -> anyhow::Result<Self> {
        hyper_util::Server::<Mutex<Registry>>::bind(
            "stats",
            config.stats_addr,
            drain_rx,
            Mutex::new(registry),
        )
        .await
        .map(|s| Server { s })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        self.s.spawn_service(|registry: Arc<Mutex<Registry>>| {
            let service = ServiceBuilder::new()
                .layer(CompressionLayer::new())
                .service_fn(move |req: Request<Incoming>| {
                    let registry = registry.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(match req.uri().path() {
                            "/metrics" | "/stats/prometheus" => handle_metrics(registry, req).await,
                            _ => hyper_util::empty_response(hyper::StatusCode::NOT_FOUND),
                        })
                    }
                });
            TowerToHyperService::new(service)
        })
    }
}

async fn handle_metrics(
    reg: Arc<Mutex<Registry>>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let mut buf = String::new();
    let reg = reg.lock().expect("mutex");
    if let Err(err) = encode(&mut buf, &reg) {
        return Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body(err.to_string().into())
            .expect("builder with known status code should not fail");
    }

    let response_content_type = content_type(&req);

    Response::builder()
        .status(hyper::StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, response_content_type)
        .body(buf.into())
        .expect("builder with known status code should not fail")
}

#[derive(Default)]
enum ContentType {
    #[default]
    PlainText,
    OpenMetrics,
}

impl From<ContentType> for &str {
    fn from(c: ContentType) -> Self {
        match c {
            ContentType::PlainText => "text/plain; charset=utf-8",
            ContentType::OpenMetrics => "application/openmetrics-text;charset=utf-8;version=1.0.0",
        }
    }
}

#[inline(always)]
fn content_type<T>(req: &Request<T>) -> &str {
    req.headers()
        .get_all(http::header::ACCEPT)
        .iter()
        .flat_map(|entry| entry.to_str().ok())
        // get_all can return multiple in one line still
        .flat_map(|entry| entry.split(",").map(|entry| entry.to_lowercase()))
        .find_map(|v| match v.split(";").collect::<Vec<_>>().first() {
            Some(&"application/openmetrics-text") => Some(ContentType::OpenMetrics),
            _ => None,
        })
        .unwrap_or_default()
        .into()
}

#[cfg(test)]
mod test {

    #[test]
    fn test_content_type() {
        let plain_text_req = http::Request::new("I want some plain text");
        assert_eq!(
            super::content_type(&plain_text_req),
            "text/plain; charset=utf-8"
        );

        let openmetrics_req = http::Request::builder()
            .header("X-Custom-Beep", "boop")
            .header("Accept", "application/json")
            .header("Accept", "application/openmetrics-text; other stuff")
            .body("I would like openmetrics")
            .unwrap();
        assert_eq!(
            super::content_type(&openmetrics_req),
            "application/openmetrics-text;charset=utf-8;version=1.0.0"
        );

        let mixed_req = http::Request::builder()
          .header("X-Custom-Beep", "boop")
          .header("Accept", "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.6,application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.5,application/openmetrics-text;version=0.0.1;q=0.4,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.3,text/plain;version=0.0.4;q=0.2,*/*;q=0.1")
          .body("I would like openmetrics")
          .unwrap();
        assert_eq!(
            super::content_type(&mixed_req),
            "application/openmetrics-text;charset=utf-8;version=1.0.0"
        );

        let unsupported_req_accept = http::Request::builder()
            .header("Accept", "application/json")
            .body("I would like some json")
            .unwrap();
        // asking for something we don't support, fall back to plaintext
        assert_eq!(
            super::content_type(&unsupported_req_accept),
            "text/plain; charset=utf-8"
        )
    }

    fn frozen_metrics_body() -> bytes::Bytes {
        use prometheus_client::metrics::counter::Counter;
        use prometheus_client::metrics::gauge::Gauge;
        let mut registry = prometheus_client::registry::Registry::default();
        let requests: Counter = Counter::default();
        requests.inc_by(12345);
        registry.register(
            "fixture_requests",
            "A frozen request counter for compression verification",
            requests,
        );
        let active = Gauge::<i64>::default();
        active.set(17);
        registry.register(
            "fixture_active",
            "A frozen active connection gauge for compression verification",
            active,
        );
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
        text.into()
    }

    async fn compressed_snapshot(encoding: &str, frozen: bytes::Bytes) -> bytes::Bytes {
        use http_body_util::{BodyExt, Empty, Full};
        use tower::{ServiceBuilder, ServiceExt};
        let service = ServiceBuilder::new()
            .layer(tower_http::compression::CompressionLayer::new())
            .service_fn(move |_request: http::Request<Empty<bytes::Bytes>>| {
                let body = frozen.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                            .body(Full::new(body))
                            .unwrap(),
                    )
                }
            });
        let request = http::Request::builder()
            .header(http::header::ACCEPT_ENCODING, encoding)
            .body(Empty::<bytes::Bytes>::new())
            .unwrap();
        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers()[http::header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .map(|v| v.to_str().unwrap())
                .unwrap_or(""),
            encoding
        );
        response.into_body().collect().await.unwrap().to_bytes()
    }

    async fn decompress_snapshot(encoding: &str, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZstdDecoder};
        use tokio::io::AsyncReadExt;
        let mut decoded = Vec::new();
        match encoding {
            "gzip" => {
                GzipDecoder::new(bytes).read_to_end(&mut decoded).await?;
            }
            "zstd" => {
                ZstdDecoder::new(bytes).read_to_end(&mut decoded).await?;
            }
            "br" => {
                BrotliDecoder::new(bytes).read_to_end(&mut decoded).await?;
            }
            "" => decoded.extend_from_slice(bytes),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unsupported test encoding",
                ));
            }
        }
        Ok(decoded)
    }

    #[tokio::test]
    async fn metrics_compression_frozen_body_roundtrips_exactly() {
        let frozen = frozen_metrics_body();
        let expected_schema =
            crate::test_helpers::app::metrics_schema(std::str::from_utf8(&frozen).unwrap())
                .unwrap();
        for encoding in ["", "gzip", "zstd", "br"] {
            let encoded = compressed_snapshot(encoding, frozen.clone()).await;
            if !encoding.is_empty() {
                assert_ne!(
                    encoded, frozen,
                    "requested compression returned raw bytes for {encoding}"
                );
            }
            let decoded = decompress_snapshot(encoding, &encoded).await.unwrap();
            assert_eq!(
                decoded.as_slice(),
                frozen.as_ref(),
                "frozen body roundtrip failed for {encoding}"
            );
            let actual_schema =
                crate::test_helpers::app::metrics_schema(std::str::from_utf8(&decoded).unwrap())
                    .unwrap();
            assert_eq!(actual_schema, expected_schema);
        }
    }

    #[tokio::test]
    async fn metrics_compression_truncated_body_is_rejected() {
        let frozen = frozen_metrics_body();
        for encoding in ["gzip", "zstd", "br"] {
            let encoded = compressed_snapshot(encoding, frozen.clone()).await;
            assert!(encoded.len() > 2);
            let truncated = &encoded[..encoded.len() / 2];
            assert!(
                decompress_snapshot(encoding, truncated).await.is_err(),
                "truncated {encoding} stream was accepted"
            );
        }
    }

    #[tokio::test]
    async fn metrics_compression_corrupt_headers_and_gzip_checksum_are_rejected() {
        let frozen = frozen_metrics_body();
        for encoding in ["gzip", "zstd"] {
            let mut encoded = compressed_snapshot(encoding, frozen.clone()).await.to_vec();
            encoded[..4].fill(0);
            assert!(
                decompress_snapshot(encoding, &encoded).await.is_err(),
                "corrupt {encoding} header was accepted"
            );
        }
        // Gzip carries a CRC32 trailer. Brotli does not provide an equivalent
        // checksum, so no general corruption-integrity claim is made for br.
        let mut gzip = compressed_snapshot("gzip", frozen).await.to_vec();
        let crc_offset = gzip.len() - 8;
        gzip[crc_offset] ^= 0x80;
        assert!(
            decompress_snapshot("gzip", &gzip).await.is_err(),
            "corrupt gzip checksum was accepted"
        );
    }
}
