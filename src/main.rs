use chrono::Local;
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use hickory_client::proto::xfer::DnsResponse;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestInfo, ResponseHandler, ResponseInfo};
use hickory_server::{ServerFuture, server::RequestHandler};
use log::{debug, info};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::runtime;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, format};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

pub struct DnsContext<'a> {
    /// dns 请求信息
    request_info: RequestInfo<'a>,

    /// dns 响应信息
    response: Option<DnsResponse>,
}

///
pub trait Executable: Send + Sync + 'static {
    fn execute(&self, context: &mut DnsContext<'_>) -> impl Future<Output = ()> + Send;
}

/// dns请求转发器
pub trait RequestForwarder: Executable {
    fn forward(&self, context: &mut DnsContext<'_>) -> impl Future<Output = ()> + Send;
}

/// 单线程的dns转发器
pub struct SequentialDnsForwarder {
    /// 发送dns请求的客户端
    client: Arc<Mutex<Client>>,
}

impl Executable for SequentialDnsForwarder {
    async fn execute(&self, context: &mut DnsContext<'_>) {
        self.forward(context).await;
    }
}

impl RequestForwarder for SequentialDnsForwarder {
    async fn forward(&self, context: &mut DnsContext<'_>) {
        let query = context.request_info.query;

        let response = self.client.lock().unwrap().query(
            query.name().into(),
            query.query_class(),
            query.query_type(),
        );

        match response.await {
            Ok(res) => {
                context.response = Some(res);
            }
            Err(e) => {
                debug!("dns request has err: {e}");
                context.response = None;
            }
        }
    }
}

// dns请求处理
pub struct DnsRequestHandler {
    executors: Vec<SequentialDnsForwarder>,
}

// 修改后的handle_request方法
#[async_trait::async_trait]
impl RequestHandler for DnsRequestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        println!("Handling request: {:?}", request);
        let mut context = DnsContext {
            request_info: request.request_info().unwrap(),
            response: None,
        };

        for x in &self.executors {
            x.execute(&mut context).await;
        }

        match context.response {
            None => {
                let response = MessageResponseBuilder::from_message_request(request)
                    .build_no_records(request.header().to_owned());
                response_handle.send_response(response).await.unwrap()
            }
            Some(res) => {
                let response = MessageResponseBuilder::from_message_request(request).build(
                    request.header().to_owned(),
                    res.answers().iter(),
                    res.name_servers().iter(),
                    vec![],
                    res.additionals(),
                );
                response_handle.send_response(response).await.unwrap()
            }
        }
    }
}

struct RustDnsLogFormatter;

impl<S, N> FormatEvent<S, N> for RustDnsLogFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Format values from the event's's metadata:
        let metadata = event.metadata();
        write!(
            &mut writer,
            "{} {} {}",
            Local::now().format("%FT%T%.6f"),
            metadata.level(),
            metadata.target()
        )?;

        if let Some(line) = metadata.line() {
            write!(&mut writer, ":{line}")?;
        }

        // Format all the spans in the event's span context.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.name())?;

                let ext = span.extensions();
                let fields = &ext
                    .get::<FormattedFields<N>>()
                    .expect("will never be `None`");

                // Skip formatting the fields if the span had no fields.
                if !fields.is_empty() {
                    write!(writer, "{{{fields}}}")?;
                }
            }
        }

        // Write fields on the event
        write!(writer, ":")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

fn main() -> Result<(), String> {
    // Setup tracing for logging based on input
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().event_format(RustDnsLogFormatter))
        .with(
            EnvFilter::builder()
                .with_default_directive(Level::DEBUG.into())
                .from_env()
                .map_err(|err| {
                    format!("failed to parse environment variable for tracing: {err}")
                })?,
        )
        .init();

    info!("RustDNS {} starting...", hickory_client::version());
    let mut runtime = runtime::Builder::new_multi_thread();
    runtime
        .enable_all()
        .thread_name("rustdns-worker")
        .worker_threads(4);
    let runtime = runtime
        .build()
        .map_err(|err| format!("failed to initialize Tokio runtime: {err}"))?;

    runtime.block_on(async_run())
}

async fn async_run() -> Result<(), String> {
    let address = SocketAddr::from(([223, 5, 5, 5], 53));
    let conn = UdpClientStream::builder(address, TokioRuntimeProvider::default()).build();
    let (client, bg) = Client::connect(conn).await.unwrap();
    tokio::spawn(bg);

    let forwarder = SequentialDnsForwarder {
        client: Arc::new(Mutex::new(client)),
    };
    let handler = DnsRequestHandler {
        executors: vec![forwarder],
    };
    let mut future = ServerFuture::new(handler);
    let bind1 = UdpSocket::bind("0.0.0.0:253");
    future.register_socket(bind1.await.unwrap());
    tracing::info!("server starting up, awaiting connections...");
    future.block_until_done().await?;
    Ok(())
}
