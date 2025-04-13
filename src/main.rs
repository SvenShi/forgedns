use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::{server::RequestHandler, ServerFuture};
use tokio::net::UdpSocket;

pub struct RustDnsRequestHandler {}

#[async_trait::async_trait]
impl RequestHandler for RustDnsRequestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {

        println!("Handling request: {:?}", request);
        let response = MessageResponseBuilder::from_message_request(request).build_no_records(*request.header());

        response_handle.send_response(response).await.unwrap()
    }

}
#[tokio::main]
async fn main() {
    let handler = RustDnsRequestHandler {};
    let mut future = ServerFuture::new(handler);
    let bind1 = UdpSocket::bind("0.0.0.0:253");
    future.register_socket(bind1.await.unwrap());
    future.block_until_done().await.unwrap();
}
