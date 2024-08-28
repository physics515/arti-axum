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
#![feature(async_closure)]

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
    sync::LazyLock,
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
use tokio::sync::Mutex as TokioMutex;
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

static DATA_STREAM_LOCK: LazyLock<TokioMutex<Option<DataStream>>> =
    LazyLock::new(|| TokioMutex::new(None));

/// Serve the service with the supplied stream requests.
///
/// See the [crate documentation](`crate`) for an example.
pub fn serve<M, S>(
    stream_requests: impl Stream<Item = StreamRequest> + Send + 'static,
    make_service: M,
    tls_key_path: String,
    tls_cert_path: String,
) -> Serve<M, S>
where
    M: for<'a> Service<IncomingStream<'a>, Error = Infallible, Response = S>,
    S: Service<Request, Error = Infallible, Response = Response>,
{
    Serve {
        stream_requests: stream_requests.boxed(),
        make_service,
        tls_key_path,
        tls_cert_path,
        _marker: PhantomData,
    }
}

/// Future returned by [`serve`].
pub struct Serve<M, S> {
    stream_requests: BoxStream<'static, StreamRequest>,
    make_service: M,
    tls_key_path: String,
    tls_cert_path: String,
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
                    PathBuf::from(self.tls_key_path),
                    PathBuf::from(self.tls_cert_path),
                );

                while let Some(stream_request) = self.stream_requests.next().await {
                    let data_stream = match stream_request.request() {
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

                    std::thread::spawn(move || {
                        let runtime = tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(1)
                            .enable_all()
                            .build()
                            .unwrap();

                        runtime.block_on(async {
                            DATA_STREAM_LOCK.lock().await.replace(data_stream);
                        })
                    })
                    .join()
                    .unwrap();

                    let tls_data_stream = TlsDataStream;

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
                        let datastream = DATA_STREAM_LOCK.lock().await.take().unwrap();
                        match Builder::new(TokioExecutor::new())
                            // upgrades needed for websockets
                            .serve_connection_with_upgrades(TokioIo::new(datastream), hyper_service)
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

use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct TlsDataStream;

impl Read for TlsDataStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let buf_arc = Arc::new(TokioMutex::new(Vec::new()));
        let buf_arc_clone = buf_arc.clone();
        let (res, b_res) = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let mut binding = DATA_STREAM_LOCK.lock().await;
                let data_stream = binding.as_mut().unwrap();
                let res = data_stream.read(buf_arc_clone.lock().await.as_mut()).await;
                let buf = buf_arc_clone.lock().await.clone();
                (res, buf)
            })
        })
        .join()
        .unwrap();

        buf.copy_from_slice(&b_res);
        res
    }
}

impl Write for TlsDataStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let new_buf = Arc::new(TokioMutex::new(buf.to_vec()));
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let mut binding = DATA_STREAM_LOCK.lock().await;
                let data_stream = binding.as_mut().unwrap();
                data_stream.write(&new_buf.lock().await).await
            })
        })
        .join()
        .unwrap()
    }

    fn flush(&mut self) -> io::Result<()> {
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let mut binding = DATA_STREAM_LOCK.lock().await;
                let data_stream = binding.as_mut().unwrap();
                data_stream.flush().await
            })
        })
        .join()
        .unwrap()
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
    data_stream: &'a mut TlsStream<TlsDataStream>,
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
    let key_pem = match std::fs::read_to_string(&key_file) {
        Ok(key_pem) => key_pem,
        Err(e) => {
            panic!("Failed to read key file: {} at {}", e, key_file.display());
        }
    };

    println!("key_pem: {}", key_pem);

    let cert_pem = match std::fs::read_to_string(&cert_file) {
        Ok(cert_pem) => cert_pem,
        Err(e) => {
            panic!("Failed to read cert file: {} at {}", e, cert_file.display());
        }
    };

    println!("cert_pem: {}", cert_pem);

    let id = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
    TlsAcceptor::builder(id)
        // let's be modern
        .min_protocol_version(Some(Protocol::Tlsv12))
        .build()
        .unwrap()
}
