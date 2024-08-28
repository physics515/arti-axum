#![warn(clippy::pedantic, clippy::nursery, clippy::all, clippy::cargo)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions, clippy::tabs_in_doc_comments)]

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
//! 	OnionServiceConfigBuilder::default()
//! 		.nickname("hello-world".to_owned().try_into().unwrap())
//! 		.build()?,
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
	convert::Infallible, future::{poll_fn, Future, IntoFuture}, io, io::{Read, Write}, marker::PhantomData, path::PathBuf, pin::Pin, sync::LazyLock, task::{Context, Poll}
};

use axum::{body::Body, extract::Request, response::Response, Router};
use futures_util::{
	future::{BoxFuture, FutureExt}, stream::{BoxStream, Stream, StreamExt}, AsyncReadExt, AsyncWriteExt
};
use hyper::body::Incoming;
use hyper_util::{
	rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder
};
use native_tls::{Identity, Protocol, TlsAcceptor, TlsStream};
use pin_project_lite::pin_project;
use tokio::sync::Mutex as TokioMutex;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;
use tor_proto::stream::{DataStream, IncomingStreamRequest};
use tower::util::{Oneshot, ServiceExt};
use tower_service::Service;

static DATA_STREAM_LOCK: LazyLock<TokioMutex<Option<DataStream>>> = LazyLock::new(|| TokioMutex::new(None));

static TLS_DATA_STREAM_LOCK: LazyLock<TokioMutex<Option<TlsStream<DStream>>>> = LazyLock::new(|| TokioMutex::new(None));

/// Serve the service with the supplied stream requests.
///
/// See the [crate documentation](`crate`) for an example.
pub fn serve<M, S>(stream_requests: impl Stream<Item = StreamRequest> + Send + 'static, make_service: M, tls_key_path: String, tls_cert_path: String) -> Serve<M, S>
where
	M: for<'a> Service<IncomingStream, Error = Infallible, Response = S>,
	S: Service<Request, Error = Infallible, Response = Response>,
{
	println!("serve called");
	Serve { stream_requests: stream_requests.boxed(), make_service, tls_key_path, tls_cert_path, _marker: PhantomData }
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
	M: for<'a> Service<IncomingStream, Error = Infallible, Response = S> + Send + 'static,
	for<'a> <M as Service<IncomingStream>>::Future: Send,
	S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
	S::Future: Send,
{
	type IntoFuture = private::ServeFuture;
	type Output = ();

	fn into_future(mut self) -> Self::IntoFuture {
		private::ServeFuture {
			inner: async move {
				println!("IntoFuture called");

				// Setup TLS
				let tls_acceptor = native_tls_acceptor(PathBuf::from(self.tls_key_path), PathBuf::from(self.tls_cert_path));

				println!("tls acceptor created");

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

					println!("accepted stream");

					poll_fn(|cx| self.make_service.poll_ready(cx)).await.unwrap_or_else(|err| match err {});

					println!("service ready");

					std::thread::spawn(move || {
						let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

						runtime.block_on(async {
							DATA_STREAM_LOCK.lock().await.replace(data_stream);
						});
					})
					.join()
					.unwrap();

					println!("moved stream to DATA_STREAM_LOCK");

					let d_stream = DStream;

					println!("created DStream");

					let stream = tls_acceptor.accept(d_stream).unwrap();

					println!("accepted tls stream");

					std::thread::spawn(move || {
						let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

						runtime.block_on(async {
							TLS_DATA_STREAM_LOCK.lock().await.replace(stream);
						});
					})
					.join()
					.unwrap();

					println!("moved stream to TLS_DATA_STREAM_LOCK");

					let tls_d_stream = TlsDStream;

					println!("created TlsDStream");

					let incoming_stream = IncomingStream;

					println!("created incoming stream");

					let tower_service = self.make_service.call(incoming_stream).await.unwrap_or_else(|err| match err {});

					println!("called make_service");

					let hyper_service = TowerToHyperService { service: tower_service };

					println!("created hyper service");

					tokio::spawn(async move {
						match Builder::new(TokioExecutor::new())
							// upgrades needed for websockets
							.serve_connection_with_upgrades(TokioIo::new(tls_d_stream), hyper_service)
							.await
						{
							Ok(()) => {
								println!("connection closed");
							}
							Err(err) => {
								// This error only appears when the client
								// doesn't send a request and
								// terminate the connection.
								//
								// If client sends one request then terminate
								// connection whenever, it doesn't
								// appear.
								println!("error: {err}");
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
	use super::{BoxFuture, Context, Future, FutureExt, Pin, Poll};

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
	type Error = S::Error;
	type Future = TowerToHyperServiceFuture<S, Request>;
	type Response = S::Response;

	fn call(&self, req: Request<Incoming>) -> Self::Future {
		let req = req.map(Body::new);
		TowerToHyperServiceFuture { future: self.service.clone().oneshot(req) }
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
pub struct TlsDStream;

impl Read for TlsDStream {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let buf_arc = Arc::new(TokioMutex::new(Vec::new()));
		let buf_arc_clone = buf_arc;
		let (res, b_res) = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let res = TLS_DATA_STREAM_LOCK.lock().await.as_mut().unwrap().read(buf_arc_clone.lock().await.as_mut());
				let buf = buf_arc_clone.lock().await.clone();
				(res, buf)
			})
		})
		.join()
		.unwrap();

		match res {
			Ok(n) => {
				buf[..n].copy_from_slice(&b_res);
				Ok(n)
			}
			Err(e) => Err(e),
		}
	}
}

impl tokio::io::AsyncRead for TlsDStream {
	fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf) -> Poll<io::Result<()>> {
		let buf_arc = Arc::new(TokioMutex::new(Vec::new()));
		let buf_arc_clone = buf_arc;
		let (res, b_res) = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let res = TLS_DATA_STREAM_LOCK.lock().await.as_mut().unwrap().read(buf_arc_clone.lock().await.as_mut());
				let buf = buf_arc_clone.lock().await.clone();
				(res, buf)
			})
		})
		.join()
		.unwrap();

		match res {
			Ok(n) => {
				buf.put_slice(&b_res[..n]);
				Poll::Ready(Ok(()))
			}
			Err(e) => Poll::Ready(Err(e)),
		}
	}
}

impl tokio::io::AsyncWrite for TlsDStream {
	fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let new_buf = Arc::new(TokioMutex::new(buf.to_vec()));
		let res = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let res = TLS_DATA_STREAM_LOCK.lock().await.as_mut().unwrap().write(&new_buf.lock().await);
				res
				//data_stream.write(&new_buf.lock().await)
			})
		})
		.join()
		.unwrap();

		Poll::Ready(res)
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let _ = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let res = TLS_DATA_STREAM_LOCK.lock().await.as_mut().unwrap().flush();
				res
			})
		})
		.join()
		.unwrap();

		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

#[derive(Debug, Clone)]
pub struct DStream;

impl Read for DStream {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let buf_arc = Arc::new(TokioMutex::new(Vec::new()));
		let buf_arc_clone = buf_arc;
		let (res, b_res) = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let res = DATA_STREAM_LOCK.lock().await.as_mut().unwrap().read(buf_arc_clone.lock().await.as_mut()).await;
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

impl Write for DStream {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		println!("DStream::write: writing to DStream");
		let new_buf = Arc::new(TokioMutex::new(buf.to_vec()));
		println!("DStream::write: created new_buf");
		let res = std::thread::spawn(move || {
			println!("DStream::write: spwaned thread");
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
			println!("DStream::write: created runtime");

			runtime.block_on(async { DATA_STREAM_LOCK.lock().await.as_mut().unwrap().write(&new_buf.lock().await).await })
		})
		.join()
		.unwrap();
		println!("DStream::write: wrote to DStream: {res:?}");
		res
	}

	fn flush(&mut self) -> io::Result<()> {
		std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async { DATA_STREAM_LOCK.lock().await.as_mut().unwrap().flush().await })
		})
		.join()
		.unwrap()
	}
}

impl tokio::io::AsyncRead for DStream {
	fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf) -> Poll<io::Result<()>> {
		let buf_arc = Arc::new(TokioMutex::new(Vec::new()));
		let buf_arc_clone = buf_arc;
		let (_, b_res) = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let res = DATA_STREAM_LOCK.lock().await.as_mut().unwrap().read(buf_arc_clone.lock().await.as_mut()).await;
				let buf = buf_arc_clone.lock().await.clone();
				(res, buf)
			})
		})
		.join()
		.unwrap();

		buf.put_slice(&b_res);
		Poll::Ready(Ok(()))
	}
}

impl tokio::io::AsyncWrite for DStream {
	fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let new_buf = Arc::new(TokioMutex::new(buf.to_vec()));
		let res = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let mut binding = DATA_STREAM_LOCK.lock().await;
				let data_stream = binding.as_mut().unwrap();
				data_stream.write(&new_buf.lock().await).await
			})
		})
		.join()
		.unwrap();

		Poll::Ready(res)
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let _ = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let mut binding = DATA_STREAM_LOCK.lock().await;
				let data_stream = binding.as_mut().unwrap();
				data_stream.flush().await
			})
		})
		.join()
		.unwrap();

		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

/// An incoming stream.
///
/// This is a single client connecting over the TOR network to your onion
/// service.
#[derive(Debug)]
pub struct IncomingStream;

impl Read for IncomingStream {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let buf_arc = Arc::new(TokioMutex::new(Vec::new()));
		let buf_arc_clone = buf_arc.clone();
		let (res, b_res) = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

			runtime.block_on(async {
				let mut binding = TLS_DATA_STREAM_LOCK.lock().await;
				let data_stream = binding.as_mut().unwrap();
				let res = data_stream.read(buf_arc_clone.lock().await.as_mut());
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

impl Write for IncomingStream {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		let new_buf = Arc::new(TokioMutex::new(buf.to_vec()));
		std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

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
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();

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

impl Service<IncomingStream> for Router<()> {
	type Error = Infallible;
	type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
	type Response = Router;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Poll::Ready(Ok(()))
	}

	fn call(&mut self, _req: IncomingStream) -> Self::Future {
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
