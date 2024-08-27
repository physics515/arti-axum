//!
//! This crate allows you to run your [axum][1] http server as a tor hidden
//! service using [arti][2].
//!
//! ## Example
//!
//! ```rust
//! # use arti_client::{TorClient, TorClientConfig};
//! # use axum::{routing, Router};
//! # use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};
//! # fn main() {
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let tor_client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
//!
//! let (onion_service, rend_requests) = tor_client.launch_onion_service(
//!     OnionServiceConfigBuilder::default()
//!         .nickname("hello-world".to_owned().try_into().unwrap())
//!         .build()?,
//! )?;
//!
//! let stream_requests = handle_rend_requests(rend_requests);
//!
//! let app = Router::new().route("/", routing::get(|| async { "Hello, World!" }));
//!
//! println!("serving at: http://{}", onion_service.onion_name().unwrap());
//!
//! arti_axum::serve(stream_requests, app).await;
//! # Ok(())
//! # }
//! # example(); // we're intentionally not polling the future
//! # }
//! ```
//!
//! [1]: https://docs.rs/axum/latest/axum/index.html
//! [2]: https://gitlab.torproject.org/tpo/core/arti/
use std::{
    convert::Infallible,
    future::{
        poll_fn,
        Future,
        IntoFuture,
    },
    io,
    io::{
        Read,
        Write,
    },
    marker::PhantomData,
    path::PathBuf,
    pin::Pin,
    task::{
        Context,
        Poll,
    },
};

use axum::{
    body::Body,
    extract::Request,
    response::Response,
    Router,
};
use futures_util::{
    future::{
        BoxFuture,
        FutureExt,
    },
    stream::{
        BoxStream,
        Stream,
        StreamExt,
    },
    AsyncReadExt,
    AsyncWriteExt,
};
use hyper::body::Incoming;
use hyper_util::{
    rt::{
        TokioExecutor,
        TokioIo,
    },
    server::conn::auto::Builder,
};
use native_tls::{
    Identity,
    Protocol,
    TlsAcceptor,
    TlsStream,
};
use pin_project_lite::pin_project;
use tokio::runtime::Handle;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;
use tor_proto::stream::{
    DataStream,
    IncomingStreamRequest,
};
use tower::util::{
    Oneshot,
    ServiceExt,
};
use tower_service::Service;

/// Serve the service with the supplied stream requests.
///
/// See the [crate documentation](`crate`) for an example.
pub fn serve<M, S>(
    stream_requests: impl Stream<Item = StreamRequest> + Send + 'static,
    make_service: M,
) -> Serve<M, S>
where
    M: for<'a> Service<IncomingStream<'a>, Error = Infallible, Response = S>,
    S: Service<Request, Error = Infallible, Response = Response>,
{
    Serve {
        stream_requests: stream_requests.boxed(),
        make_service,
        _marker: PhantomData,
    }
}

/// Future returned by [`serve`].
pub struct Serve<M, S> {
    stream_requests: BoxStream<'static, StreamRequest>,
    make_service: M,
    _marker: PhantomData<S>,
}

impl<M, S> IntoFuture for Serve<M, S>
where
    M: for<'a> Service<IncomingStream<'a>, Error = Infallible, Response = S> + Send + 'static,
    for<'a> <M as Service<IncomingStream<'a>>>::Future: Send,
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
{
    type Output = ();
    type IntoFuture = private::ServeFuture;

    fn into_future(mut self) -> Self::IntoFuture {
        private::ServeFuture {
            inner: async move {
                // Setup TLS
                let tls_acceptor = native_tls_acceptor(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("self_signed_certs")
                        .join("key.pem"),
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("self_signed_certs")
                        .join("cert.pem"),
                );
                let tls_acceptor = TlsAcceptor::from(tls_acceptor);

                while let Some(stream_request) = self.stream_requests.next().await {
                    let mut data_stream = match stream_request.request() {
                        IncomingStreamRequest::Begin(_) => {
                            match stream_request.accept(Connected::new_empty()).await {
                                Ok(data_stream) => data_stream,
                                Err(error) => {
                                    tracing::trace!("failed to accept incoming stream: {error}");
                                    continue;
                                }
                            }
                        }
                        _ => {
                            // we only accept BEGIN streams
                            continue;
                        }
                    };

                    poll_fn(|cx| self.make_service.poll_ready(cx))
                        .await
                        .unwrap_or_else(|err| match err {});

                    let tls_data_stream = TlsDataStream {
                        data_stream: &mut data_stream,
                    };

                    let mut stream = tls_acceptor.accept(tls_data_stream).unwrap();

                    let incoming_stream = IncomingStream {
                        data_stream: &mut stream,
                    };

                    let tower_service = self
                        .make_service
                        .call(incoming_stream)
                        .await
                        .unwrap_or_else(|err| match err {});

                    let hyper_service = TowerToHyperService {
                        service: tower_service,
                    };

                    tokio::spawn(async move {
                        match Builder::new(TokioExecutor::new())
                            // upgrades needed for websockets
                            .serve_connection_with_upgrades(
                                TokioIo::new(data_stream),
                                hyper_service,
                            )
                            .await
                        {
                            Ok(()) => {}
                            Err(_err) => {
                                // This error only appears when the client
                                // doesn't send a request and
                                // terminate the connection.
                                //
                                // If client sends one request then terminate
                                // connection whenever, it doesn't
                                // appear.
                            }
                        }
                    });
                }
            }
            .boxed(),
        }
    }
}

mod private {
    use super::*;

    pub struct ServeFuture {
        pub inner: BoxFuture<'static, ()>,
    }

    impl Future for ServeFuture {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.inner.poll_unpin(cx)
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct TowerToHyperService<S> {
    service: S,
}

impl<S> hyper::service::Service<Request<Incoming>> for TowerToHyperService<S>
where
    S: tower_service::Service<Request> + Clone,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = TowerToHyperServiceFuture<S, Request>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let req = req.map(Body::new);
        TowerToHyperServiceFuture {
            future: self.service.clone().oneshot(req),
        }
    }
}

pin_project! {
    struct TowerToHyperServiceFuture<S, R>
    where
        S: tower_service::Service<R>,
    {
        #[pin]
        future: Oneshot<S, R>,
    }
}

impl<S, R> Future for TowerToHyperServiceFuture<S, R>
where
    S: tower_service::Service<R>,
{
    type Output = Result<S::Response, S::Error>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().future.poll(cx)
    }
}

#[derive(Debug)]
pub struct TlsDataStream<'a> {
    data_stream: &'a mut DataStream,
}

impl Read for TlsDataStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = Handle::current().block_on(async { self.data_stream.read(buf).await });
        read
    }
}

impl Write for TlsDataStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let write = Handle::current().block_on(async { self.data_stream.write(buf).await });
        write
    }

    fn flush(&mut self) -> io::Result<()> {
        let flush = Handle::current().block_on(async { self.data_stream.flush().await });
        flush
    }
}

/// An incoming stream.
///
/// This is a single client connecting over the TOR network to your onion
/// service.
#[derive(Debug)]
pub struct IncomingStream<'a> {
    // in the future we can use this to return information about the circuit used etc.
    #[allow(dead_code)]
    data_stream: &'a mut TlsStream<TlsDataStream<'a>>,
}

impl Read for IncomingStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.data_stream.read(buf)
    }
}

impl Write for IncomingStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data_stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.data_stream.flush()
    }
}

impl Service<IncomingStream<'_>> for Router<()> {
    type Response = Router;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: IncomingStream<'_>) -> Self::Future {
        std::future::ready(Ok(self.clone()))
    }
}

fn native_tls_acceptor(key_file: PathBuf, cert_file: PathBuf) -> TlsAcceptor {
    let key_pem = std::fs::read_to_string(&key_file).unwrap();
    let cert_pem = std::fs::read_to_string(&cert_file).unwrap();

    let id = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
    TlsAcceptor::builder(id)
        // let's be modern
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use hyper::{
        service::{
            make_service_fn,
            service_fn,
        },
        Server,
    };
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn test_serve() {
        // Setup TOR
        let tor_client = match TorClient::create_bootstrapped(TorClientConfig::default()).await {
            Ok(tor_client) => tor_client,
            Err(e) => {
                bail!(Error::Runtime(format!(
                    "Error bootstrapping tor client: {e:?}"
                )))
            }
        };

        let hs_nickname: HsNickname = match "pluggin-server".to_owned().try_into() {
            Ok(nickname) => nickname,
            Err(e) => bail!(Error::Runtime(format!("Error converting nickname: {e:?}"))),
        };

        let onion_service_config = match OnionServiceConfigBuilder::default()
            .nickname(hs_nickname)
            .build()
        {
            Ok(config) => config,
            Err(e) => {
                bail!(Error::Runtime(format!(
                    "Error building onion service config: {e:?}"
                )))
            }
        };

        let (onion_service, rend_requests) =
            match tor_client.launch_onion_service(onion_service_config) {
                Ok((service, requests)) => (service, requests),
                Err(e) => {
                    bail!(Error::Runtime(format!(
                        "Error launching onion service: {e:?}"
                    )))
                }
            };

        // Create TCP Stream
        let stream_requests = handle_rend_requests(rend_requests);

        let app = Router::new().route(
            "/",
            make_service_fn(|_conn| {
                async {
                    Ok::<_, Infallible>(service_fn(|_req| {
                        async { Ok::<_, Infallible>(Response::new(Body::from("Hello, World!"))) }
                    }))
                }
            }),
        );

        arti_axum::serve(stream_requests, app);

        tokio::spawn(serve.into_future());

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("http://{}", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
}
