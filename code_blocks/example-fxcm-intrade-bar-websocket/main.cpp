#include <iostream>
#include "client_wss.hpp"
#include <openssl/ssl.h>
#include <wincrypt.h>
#include <xtime.hpp>
#include <nlohmann/json.hpp>

using namespace std;
using WssClient = SimpleWeb::SocketClient<SimpleWeb::WSS>;
using json = nlohmann::json;

/*
void addRootCertificates() {
  X509_STORE* store = ::SSL_CTX_get_cert_store(context.native_handle());
  HCERTSTORE hCertStore = CertOpenSystemStore(0LL, "ROOT");
  if (!hCertStore) {
      std::cerr << "Cannot open system store." << std::endl;
      return;
  }

  PCCERT_CONTEXT certContext = nullptr;
  while (true) {
      certContext = CertEnumCertificatesInStore(hCertStore, certContext);
      if (!certContext) {
          break;
      }

      X509* x509 = d2i_X509(nullptr, (const unsigned char**)&certContext->pbCertEncoded,
              certContext->cbCertEncoded);
      if (x509) {
          X509_STORE_add_cert(store, x509);
          X509_free(x509);
      }
  }

  CertFreeCertificateContext(certContext);
  CertCloseStore(hCertStore, 0);
}
*/

int main()
{
    //wss://mr-axiano.com/fxcm2/
    WssClient client("mr-axiano.com/fxcm2/", true, std::string(), std::string(), "curl-ca-bundle.crt");
    client.on_message = //[](shared_ptr<WssClient::Connection> connection, std::shared_ptr<WssClient::InMessage> message) {
        [](shared_ptr<WssClient::Connection> connection, shared_ptr<WssClient::Message> message) {
        //std::cout << "Client: Message received: \"" << message->string() << "\"" << std::endl;
        std::string temp = message->string();
        std::string line; line.reserve(1024);
        size_t pos = 0;
        while(pos < temp.size()) {
            line += temp[pos];
            if(temp[pos] == '{') {
            }
            else if(temp[pos] == '}') {
                //std::cout << line << std::endl;
                try {
                    json j = json::parse(line);
                    if(j["Symbol"] == "EUR/USD") {
                        const double bid = j["Rates"][0];
                        const double ask = j["Rates"][1];
                        const double high = j["Rates"][2];
                        const double low = j["Rates"][3];

                        const double a = j["Rates"][0];
                        const double b = j["Rates"][1]; //
                        const double c = j["Rates"][2];
                        const double d = j["Rates"][3];
                        //
                        static xtime::ftimestamp_t last_ftimestamp = 0;
                        xtime::ftimestamp_t ftimestamp = j["Updated"];
                        ftimestamp /= 1000.0;
                        if(last_ftimestamp != ftimestamp) {
                            printf("EUR/USD a %.5f b %.5f c %.5f d %.5f aver %.5f %s\n",
                                a,
                                b,
                                c,
                                d,
                                ((bid + ask) / 2.0),
                                xtime::get_str_date_time_ms(ftimestamp).c_str());
                            last_ftimestamp = ftimestamp;
                        }
                    }
                } catch(...) {

                }
                line.clear();
            }
            ++pos;
        }

        //1575348834
        //1575307522444

        //cout << "Client: Sending close connection" << endl;
        //    connection->send_close(1000);
    };

    client.on_open = [](shared_ptr<WssClient::Connection> connection) {
        std::cout << "Client: Opened connection" << std::endl;

        //string message = "Hello";
        //cout << "Client: Sending message: \"" << message << "\"" << endl;

        //auto send_stream = make_shared<WssClient::SendStream>();
        //    *send_stream << message;
        //    connection->send(send_stream);
    };

    client.on_close = [](shared_ptr<WssClient::Connection> /*connection*/, int status, const string & /*reason*/) {
        std::cout << "Client: Closed connection with status code " << status << endl;
    };

    // See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    client.on_error = [](shared_ptr<WssClient::Connection> /*connection*/, const SimpleWeb::error_code &ec) {
        cout << "Client: Error: " << ec << ", error message: " << ec.message() << endl;
    };

    client.start();
    while(true)  {

    }
    return 0;
}
