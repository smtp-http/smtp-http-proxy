#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <curl/curl.h>
#include <boost/asio.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/program_options.hpp>
#include <boost/optional/optional.hpp>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <json.hpp>
#include <deque>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>


#define LOG(a) BOOST_LOG_TRIVIAL(a)

using namespace std;
using boost::asio::ip::tcp;
using boost::asio::ip::address;
namespace po = boost::program_options;

void DecodeQuoted(const std::string& v_strSrc, std::string& v_strDst) {
	std::string::size_type i = 0;
	char pDst[sizeof(int)+1] = {0};
	const char* pSrc = v_strSrc.c_str();
	while (i < v_strSrc.size()) {
		if (strncmp(pSrc+i, "=\r\n", 3) == 0){
			i += 3;
		}
		else if (strncmp(pSrc+i, "=\n", 2) == 0){
			i += 2;
		}
		else {
			if (pSrc[i] == '='){
			sscanf(pSrc+i, "=%02X", (unsigned int*)pDst);
			v_strDst.append(pDst);
			i += 3;
			}
		 	else
			{
				v_strDst.push_back(pSrc[i]);
				i++;
			}
		}
	}
}

bool Base64Encode(const string& input, string* output) {
  typedef boost::archive::iterators::base64_from_binary<boost::archive::iterators::transform_width<string::const_iterator, 6, 8> > Base64EncodeIterator;
  stringstream result;
  copy(Base64EncodeIterator(input.begin()) , Base64EncodeIterator(input.end()), ostream_iterator<char>(result));
  size_t equal_count = (3 - input.length() % 3) % 3;
  for (size_t i = 0; i < equal_count; i++) {
    result.put('=');
  }
  *output = result.str();
  return output->empty() == false;
}

class Sender {
	public:
		virtual void send(const std::string& response, bool close = false) = 0;
};

class SMTPMessage {
	public:
		SMTPMessage(
				const std::string& from,
				const std::vector<std::string>& to,
				const std::string& data,
				const std::string& subject,
				const std::string& messageID,
				const std::string& encode,
				const std::string& date,
				const std::string& mimeversion		
		):
					from(from),
					to(to),
					data(data),
					subject(subject),
					messageID(messageID),
					encode(encode),
					Date(date),
					mimeversion(mimeversion){}

		const std::string& getFrom() const {
			return from;
		}

		const std::vector<std::string>& getTo() const {
			return to;
		}
		const std::string& getSubject() const {
			return subject;
		}
		const std::string& getData() const {
			return data;
		}

	private:
		std::string from;
		std::vector<std::string> to;
		std::string data;
		std::string subject;
		std::string messageID;
		std::string encode;
		std::string Date;
		std::string mimeversion;
};

class SMTPHandler {
	public:
		virtual void handle(const SMTPMessage& message) = 0;
};

using json = nlohmann::json;

static size_t curlWriteCallback(void* contents, size_t size, size_t nmemb, void*) {
	size_t realsize = size * nmemb;
	LOG(debug) << "HTTP: <- " << std::string((const char*) contents, realsize);
	return realsize;
}

static int curlDebugCallback(CURL*, curl_infotype type, char* data, size_t size, void *) {
	auto text = boost::algorithm::trim_right_copy(std::string(data, size));
	switch (type) {
		case CURLINFO_TEXT:
			LOG(debug) << "HTTP: " << data;
			break;
		case CURLINFO_HEADER_OUT:
			LOG(debug) << "HTTP: -> H: " << text;
			break;
		case CURLINFO_DATA_OUT:
			break;
		case CURLINFO_SSL_DATA_OUT:
			break;
		case CURLINFO_HEADER_IN:
			LOG(debug) << "HTTP: <- H: " << text;
			break;
		case CURLINFO_DATA_IN:
			break;
		case CURLINFO_SSL_DATA_IN:
			break;
		default: 
			return 0;
	}
	return 0;
}


class HTTPPoster : public SMTPHandler {
	public:
		HTTPPoster(const std::string& url, const std::vector<std::string>& headers) : 
				url(url),
				headers(headers),
				stopRequested(false) {
			thread = new std::thread(std::bind(&HTTPPoster::run, this));
		}

		virtual void handle(const SMTPMessage& message) override {
			{
				std::lock_guard<std::mutex> lock(queueMutex);
				queue.push_back(message);
			}
			queueNonEmpty.notify_one();
		}

		void stop() {
			stopRequested = true;
			queueNonEmpty.notify_one();
			thread->join();
			delete thread;
			thread = 0;
		}

	private:
		void run() {
			while (!stopRequested) {
				boost::optional<SMTPMessage> message;
				{
					std::unique_lock<std::mutex> lock(queueMutex);
					queueNonEmpty.wait(lock, [this]() { return !queue.empty() || stopRequested; });
					if (stopRequested) { break; }
					message = queue.front();
					queue.pop_front();
				}
				doHandle(*message);
			}
		}

		void doHandle(const SMTPMessage& message) {
			json j;
			//j["envelope"] = {
			//	{"from", message.getFrom()},
			//	{"to", message.getTo()}
			//};
			//j["data"] = message.getData();
			const std::vector<std::string> &to = message.getTo();
			int count = to.size();
    			for (int i = 0; i < count;i++){
				std::string str =  to[i];
				std::string::iterator it;              //指向string类的迭代器。你可以理解为指针	
				for (it = str.begin(); it != str.end(); it++)	{		
					if (*it == '<' || *it == '>')	
					*it = ' ';
					//str.erase(it);          //删除it处的一个字符	
				}


				j["To"] = str;//to[i];//message.getTo();
				j["Title"] = message.getSubject();
				std::string basebody;
				std::string quoted;
				DecodeQuoted(message.getData(),quoted);
				Base64Encode(quoted, &basebody);
				j["Body"] = basebody;
				j["EncodeBody"]=true;
				//j["TextMode"]=true;
				std::string body=j.dump();
 
				LOG(error) << "Processing message: " << body;

				std::shared_ptr<CURL> curl(curl_easy_init(), curl_easy_cleanup);
				struct curl_slist *slist = NULL; 
				slist = curl_slist_append(slist, "Content-Type: application/json"); 
				for (const auto& header : headers) {
					curl_slist_append(slist, header.c_str());
				}
				curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, slist); 
				curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, "POST");
				curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.c_str());
				curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curlWriteCallback);
				curl_easy_setopt(curl.get(), CURLOPT_DEBUGFUNCTION, curlDebugCallback);
				curl_easy_setopt(curl.get(), CURLOPT_VERBOSE, 1);
				curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1);
				curl_easy_setopt(curl.get(), CURLOPT_MAXREDIRS, 5);
				curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());

				auto ret = curl_easy_perform(curl.get());
				if (ret != CURLE_OK) {
					LOG(error) << "ERROR " << curl_easy_strerror(ret) << std::endl;
				}
				long statusCode;
				ret = curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &statusCode);
				if (ret != CURLE_OK) {
					LOG(error) << "ERROR " << curl_easy_strerror(ret) << std::endl;
				}
				if (statusCode != 200) {
					LOG(error) << "Error: Unexpected status code: " << statusCode;
				}
			}

			
		}

	private:
		std::string url;
		std::vector<std::string> headers;
		std::atomic_bool stopRequested;
		std::thread* thread;
		std::deque<SMTPMessage> queue;
		std::mutex queueMutex;
		std::condition_variable queueNonEmpty;
};

class SMTPSession {
	public:
		SMTPSession(Sender& sender, SMTPHandler& handler) : sender(sender), handler(handler), receivingData(false) {
		}

		void reset() {
			from = boost::optional<std::string>();
			to.clear();
			dataLines.str("");
			dataLines.clear();
			subjectLines.str("");
			subjectLines.clear();
			
			mid.str("");
			mid.clear();
			
			encode.str("");
			encode.clear();
			
			date.str("");
			date.clear();
			
			mimeVersion.str("");
			mimeVersion.clear();
		}

		void start() {
			send("220 " + boost::asio::ip::host_name());
		}

		void receive(const std::string& data) {
			LOG(debug) << "SMTP <- " << data;
			if (receivingData) {
				if (data == ".") {
					receivingData = false;
					send("250 Ok");
					if (from) {
						handler.handle(SMTPMessage(*from, to,
						 dataLines.str(),
						subjectLines.str(),
						  mid.str(),
						  encode.str(),
						   date.str(),
						    mimeVersion.str()));
					}
					else {
						LOG(warning) << "Didn't receive FROM; not handling mail";
					}
					reset();
				}
				else if (boost::algorithm::istarts_with(data, "Content-Transfer-Encoding:")) {
									encode << data << std::endl;

				}
				else if (boost::algorithm::istarts_with(data, "Date:")) {
										date << data << std::endl;

				}else if (boost::algorithm::istarts_with(data, "MIME-Version:")) {
									mimeVersion << data << std::endl;

				}else if (boost::algorithm::istarts_with(data, "Message-ID:")) {
										mid << data << std::endl;

				}else if (boost::algorithm::istarts_with(data, "Subject:")&&data.length()>7) {
									subjectLines << data.substr(8) << std::endl;

				}
				else if (boost::algorithm::istarts_with(data, "To:")) {
				
				}
				else {
					//if(data.length()>0&&data[data.length()-1]=='=')
					//	dataLines << data.substr(0,data.length()-1);
					//else
						dataLines << data << std::endl;
				}
			}
			else {
				if (boost::algorithm::istarts_with(data, "HELO") || boost::algorithm::istarts_with(data, "EHLO")) {
					send("250 Hello");
				}
				else if (boost::algorithm::istarts_with(data, "DATA")) {
					receivingData = true;
					send("354 Send data");
				}
				else if (boost::algorithm::istarts_with(data, "QUIT")) {
					send("221 Bye", true);
				}
				else if (boost::algorithm::istarts_with(data, "MAIL FROM:")) {
					reset();
					from = data.substr(10);
					send("250 Ok");
				}
				else if (boost::algorithm::istarts_with(data, "RCPT TO:")) {
					to.push_back(data.substr(8));
					send("250 Ok");
				}
				else if (boost::algorithm::istarts_with(data, "AUTH PLAIN")) {
					send("235 auth success");
				}
				else if (boost::algorithm::istarts_with(data, "NOOP")) {
					send("250 Ok");
				}
				else if (boost::algorithm::istarts_with(data, "RSET")) {
					reset();
					send("250 Ok");
				}
				else {
					send("502 Command not implemented");
				}
			}
		}

		void send(const std::string& data, bool closeAfterNextWrite = false) {
			LOG(debug) << "SMTP -> " << data;
			sender.send(data, closeAfterNextWrite);
		}

	
	private:
		Sender& sender;
		SMTPHandler& handler;
		bool receivingData;
		boost::optional<std::string> from;
		std::vector<std::string> to;
		std::stringstream dataLines;
		std::stringstream subjectLines;
		std::stringstream mid;
		std::stringstream encode;
		std::stringstream date;
		std::stringstream mimeVersion;
};

template<typename T>
class LineBufferingReceiver {
	public:
		LineBufferingReceiver(T& target) : target(target) {}

		template <typename InputIterator>
		void receive(InputIterator begin, InputIterator end) {
			while (begin != end) {
				char c = *begin++;
				if (c == '\n') {
					if (!buffer.empty()) {
						if (buffer.back() == '\r') {
							buffer.pop_back();
						}
						target.receive(std::string(&buffer[0], buffer.size()));
						buffer.clear();
					}
				}
				else {
					buffer.push_back(c);
				}
			}
		}

	private:
		T& target;
		std::vector<char> buffer;
};

class Session : public std::enable_shared_from_this<Session>, public Sender {
	public:
		Session(tcp::socket socket, HTTPPoster& httpPoster) :
				socket(std::move(socket)),
				smtpSession(*this, httpPoster),
				receiver(smtpSession) {
		}

		void start() {
			smtpSession.start();
		}

	private:
		void doRead() {
			auto self(shared_from_this());
			socket.async_read_some(
					boost::asio::buffer(buffer),
					[this, self](boost::system::error_code ec, std::size_t length) {
						if (!ec) {
							receiver.receive(buffer.data(), buffer.data() + length);
							doRead();
						}
					});
		}

		virtual void send(const std::string& command, bool closeAfterNextWrite) override {
			std::string cmd = command + "\r\n";
			auto self(shared_from_this());
			boost::asio::async_write(
					socket, boost::asio::buffer(cmd, cmd.size()),
					[this, self, closeAfterNextWrite](boost::system::error_code ec, std::size_t) {
						if (!ec) {
							if (closeAfterNextWrite) {
								boost::system::error_code errorCode;
								socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, errorCode);
								socket.close();
							}
							else {
								doRead();
							}
						}
					});
		}

		tcp::socket socket;
		enum { maxLength = 8192 };
		std::array<char, 8192> buffer;
		SMTPSession smtpSession;
		LineBufferingReceiver<SMTPSession> receiver;
};

class Server {
	public:
		Server(
				boost::asio::io_service& ioService, 
				boost::asio::ip::address& bindAddress,
				int port, 
				boost::optional<int> notifyFD,
				HTTPPoster& httpPoster) :
					httpPoster(httpPoster),
					acceptor(ioService, tcp::endpoint(bindAddress, port)),
					socket(ioService) {
			doAccept();
			if (notifyFD) {
				auto writeResult = write(*notifyFD, "\n", 1);
				if (writeResult <= 0) { LOG(error) << "Error " << writeResult << " writing to descriptor " << *notifyFD; }
				auto closeResult = close(*notifyFD);
				if (closeResult < 0) { LOG(error) << "Error " << closeResult << " closing descriptor " << *notifyFD; }
			}
			LOG(info) << "Listening for SMTP connections on " << tcp::endpoint(bindAddress, port);
		}

	private:
		void doAccept() {
			acceptor.async_accept(socket, [this](boost::system::error_code ec) {
				if (!ec) {
					std::make_shared<Session>(std::move(socket), httpPoster)->start();
				}
				doAccept();
			});
		}

		HTTPPoster& httpPoster;
		tcp::acceptor acceptor;
		tcp::socket socket;
};

int main(int argc, char* argv[]) {
	curl_global_init(CURL_GLOBAL_ALL);

	try {
		int port;
		std::string httpURL;
		std::vector<std::string> httpHeaders;

		po::options_description options("Allowed options");
		options.add_options()
			("help", "Show this help message")
			("verbose", "Enable verbose output")
			("debug", "Enable debug output")
			("notify-fd", po::value<int>(), "Write to file descriptor when ready")
			("bind", po::value<std::string>()->default_value("0.0.0.0"), "SMTP address to bind")
			("port", po::value<int>(&port)->default_value(25), "SMTP port to bind")
			("url", po::value<std::string>(&httpURL)->required(), "HTTP URL")
			("header,H", po::value<std::vector<std::string>>(&httpHeaders), "Extra HTTP Headers");
		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, options), vm);
		if (vm.count("help")) {
			std::cout << options << "\n";
				return 0;
		}
		po::notify(vm);    

		boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::warning);
		boost::log::add_console_log(std::clog, boost::log::keywords::format = "[%TimeStamp%] %Message%");
		boost::log::add_common_attributes();

		boost::optional<int> notifyFD;
		address bindAddress;

		if (vm.count("bind")) {
			bindAddress = address::from_string(vm["bind"].as<std::string>());
		}
		if (vm.count("verbose")) {
			boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);
		}
		if (vm.count("debug")) {
			boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::debug);
		}
		if (vm.count("notify-fd")) {
			notifyFD = vm["notify-fd"].as<int>();
		}

		boost::asio::io_service io_service;

		HTTPPoster httpPoster(httpURL, httpHeaders);
		Server s(
				io_service, 
				bindAddress,
				port,
				notifyFD,
				httpPoster
		);
		io_service.run();

		httpPoster.stop();

	}
	catch (boost::program_options::error& e) {
		std::cerr << e.what() << std::endl;
	}
	catch (std::exception& e) {
		LOG(fatal) << "Exception: " << e.what() << "\n";
	}
}
