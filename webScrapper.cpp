#include <string>
#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2def.h>
#include <vector>
//#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
//#pragma comment(lib, "Ws2_32.lib")
using namespace std;

class InstagramScrapper
{
    // Private members
    private:
        int error = 0;
        string URL, port;

        SOCKET Socket;
        WSAData wsaData;

        ADDRINFOA hints, *addrInfo;
        SSL_CTX* ctx;
        SSL* ssl;
        ofstream outputFile;

    // Goal is to parse this instagram post comments
    //  https://www.instagram.com/p/CrH0KmjLZdy/

    // Public functions
    public:
        //Constructor
        InstagramScrapper (string URL, string port) 
        {
            //Initialize data for Getting web URI
            cout << "URL: " + URL << endl;
            cout << "Port: " + port << endl;
            this->URL = URL;
            this->port = port;

            //SSL_library_init();
            //OpenSSL_add_all_algorithms();

            // Create new Context for SSL connection
            ctx = SSL_CTX_new(SSLv23_client_method());
            if(ctx == nullptr){
                ERR_print_errors_fp(stderr);
                exit(-1);
            }
            //Create new SSL instance
            ssl = SSL_new(ctx);
            if(ssl == nullptr){
                ERR_print_errors_fp(stderr);
                exit(-1);
            }
            //Init for Windows socket functionality
            if(Init() != 0){
                exit(-1);
            }
        }
        // Init is required but is automatically called from constructor
        int Init(){
            //STEP 1: Init Winsock2
            //cout <<  "Loading socket dll" << endl;
            error = WSAStartup(MAKEWORD(2,1), &wsaData);
            if(error != 0)
            {
                cerr << "DLL didnt load" << endl;
                return error;
            }
            return 0;
        }

        //Bool return may be uneccessary
        bool CreateSocket() {
            //STEP 2: Create Socket
            //cout << "Creating Socket..." << endl;
            Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if(Socket == INVALID_SOCKET){
                cout << "Couldn't create socket" << endl;
                exit(-1);
                // exit will prob mean following return never runs
                return false;
            }
            //Wrap Socket with ssl functionality, AKA connect SSL object with Socket file descriptor
            if(SSL_set_fd(ssl, Socket) != 1){
                ERR_print_errors_fp(stderr);
                exit(-1);
                // exit will prob mean following return never runs
                return false;
            }
            return true;
        }

        //Returns value of getaddrinfo()
        int GetHostInfo() {
            // STEP 3: Get Server address information
            //**NOTE** - Host info is sometimes returned from invalid URLs with the getaddrinfo func
            //ZeroMemory( &hints, sizeof(hints) );
            this->hints = {};
            hints.ai_family = AF_UNSPEC; 
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_CANONNAME; // Neccessary to not have undefined behavior on line 72

            error = getaddrinfo(URL.c_str(), port.c_str(), &hints, &addrInfo);
            if(error != 0) { // Check if we were able to get the address info into addrInfo
                cerr << "Error getting server info: " << error << endl;
                return error;
            }
            else
            {
                //cout << "Got Addr" << endl;
                addrinfo *iter = addrInfo;
                char ipString [INET6_ADDRSTRLEN];
                //Print IP address of returned DNS docs
                do
                {
                    inet_ntop(iter->ai_family, iter->ai_addr, ipString, sizeof(ipString)); // Convert Ip to string
                    if(iter->ai_canonname!=nullptr) cout << "English Name: " << iter->ai_canonname << endl;
                    cout << "IP Addr: " << ipString << endl;
                    //cout << "Next addr: " << addrInfo->ai_next << endl;
                    iter = iter->ai_next;
                } while(iter != nullptr);
            }
            return 0;
        }

        //returns value of connect()
        int ConnectToURL(){
            for(addrinfo *p = addrInfo; p!=nullptr; p=p->ai_next)
            {
                char ipString [INET6_ADDRSTRLEN];
                inet_ntop(p->ai_family, p->ai_addr, ipString, sizeof(ipString)); //Convert ai_addr to readable string stored in ipString
                cout << "Attempting connect to " << ipString << endl;
                if(p->ai_family == AF_INET)
                {
                    //Found a valid IPv4 address to attempt to connect to
                    error = connect(Socket, p->ai_addr, p->ai_addrlen);
                    if(error == 0)
                    {
                        cout << "Socket connected to: " << ipString;
                        if(p->ai_canonname!=nullptr) cout << " | " << p->ai_canonname << endl;
                        else cout << endl;
                        //Preform TLS handshake
                        if(SSL_connect(ssl) != 1) {
                            cerr << "TLS could not be established" << endl;
                        }else{
                            SslInfo();
                        }
                        break;
                    }else{
                        cout << "Socket Error " << error << endl;
                        cout << "Last Error: " << WSAGetLastError() << endl;
                        CleanUp();
                        return error;
                    }
                }else{
                    cout << "Unsupported protocol family: " << p->ai_family << endl;
                }
            }

            return error;
        }

        //Returns number of bytes sent for GET request
        int GETRequest(string URI){
            string universalResourceIdentifier = "/";
            if(URI != "") universalResourceIdentifier = URI;
            
            string getRequest = "GET " + universalResourceIdentifier + " HTTP/1.1\r\n";
            getRequest += "Host: " + URL + "\r\n";
            getRequest += "Accept: text/html\r\n\r\n";

            cout << "Sending msg: \n" + getRequest << endl;

            int byteSent = send(Socket, getRequest.c_str(), getRequest.length(), 0);
            cout << "Sent " << byteSent << " bytes" << endl;
            return byteSent;
        }

        //Returns number of bytes received
        int Receive(){
            char recvBuffer[1024] = {0};
            int totalBytes = 0;
            int recvdBytes = 0;
            int contentLength = 0;
            string header = "";
            string body = "";
            vector<string> headers;

            //Process HTTP response Header
            do
            {
                cout << "Processing header..." << endl;
                recvdBytes = recv(Socket, recvBuffer, sizeof(recvBuffer), 0);
                string buff(recvBuffer, recvdBytes);
                header += buff;
                
                //********Work on picking out HTTP response to GET request**************s
                cout << "Printing Buffer: " << endl; 
                char* c = recvBuffer;
                for(int i=0; i<recvdBytes; i++)
                {
                    cout << *c;
                    c++;
                }
                cout << endl << "Done printing buffer " << endl;

                memset(recvBuffer, 0, sizeof(recvBuffer)); //Clear recvBuffer for future recv calls

                unsigned int endOfHeaders = header.find("\r\n\r\n");

                if(endOfHeaders != header.npos)
                {
                    cout << "Found end of header..." << endl;
                    body = header.substr(endOfHeaders+4); //+4 to skip the 4 characters "\r\n\r\n"
                    header = header.substr(0, endOfHeaders);
                    totalBytes = body.length();
                    contentLength = ParseHeaders(headers, header);
                    break;
                }
            } while (recvdBytes > 0);

            //Process Body
            do
            {
                cout << "Processing body..." << endl;
                recvdBytes = recv(Socket, recvBuffer, sizeof(recvBuffer), 0);
                string buff(recvBuffer, recvdBytes);
                memset(recvBuffer, 0, sizeof(recvBuffer)); // clear char buffer for next iter
                body += buff;
                totalBytes += recvdBytes;
            }
            while(totalBytes < contentLength);
            
            if(recvdBytes < 0)
            {
                cerr << "Error recieving data... Terminating!" << endl;
                CleanUp();
                return -1;
            }
            outputFile << body;
            return totalBytes;
        }

        //Returns value of Content-Length header
        int ParseHeaders(vector<string> &vec, string &header)
        {
            int currIndex = 0;
            int len = header.length();
            cout << "Parsing Headers..." << endl;

            //Parse headers and put them into &vec
            while(currIndex < len){
                string parse;
                unsigned int index = header.find("\n", currIndex);
                if(index == header.npos) break;
                parse = header.substr(currIndex, index-currIndex-1);
                vec.push_back(parse);
                cout << parse << endl;
                currIndex = index+1; // next header starts 1 past the newline
            }

            //Search headers for the content length and return it
            for(string n : vec)
            {
                unsigned int found = n.find("Content-Length");
                if(found == n.npos) continue;

                found = n.find(":");
                int len = stoi(n.substr(found+2));
                cout << "Got Content Length of: " << len << endl;
                return len;
            }
            cout << "ERROR: Content length not found" << endl;
            return 0;

        }
        
        bool CreateFileNamed(string name)
        {
            outputFile.open(URL+"_"+name, ios_base::trunc | ios_base::out);

            if(outputFile.is_open()) {
                cout << "File " << URL+"_"+name << " opened!" << endl;
                return true;
            } else {
                cout << "File " << URL+"_"+name << " could not be opened!" << endl;
                return false;
            }
        }
        //Cleanup memory and shutdown connections and open files
        void CleanUp()
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            shutdown(Socket, SD_SEND);

            if(outputFile.is_open())
                outputFile.close();
            if(closesocket(Socket) != 0)
                cerr << "Error closing the socket" << endl;
            WSACleanup();
            cout << "Clean Up Done!" << endl;
        }
        //For debugging purposes
        void SslInfo(){
            OSSL_HANDSHAKE_STATE state = SSL_get_state(ssl);
            const char* buffer;
            buffer = SSL_get_version(ssl);
            //SSL_SESSION* session = SSL_get_session(ssl);
            X509* peerCert = SSL_get_peer_certificate(ssl);
            if (peerCert != nullptr) {
                // Print certificate information
                std::cout << "Peer Certificate Subject: ";
                X509_NAME_print_ex_fp(stdout, X509_get_subject_name(peerCert), 0, XN_FLAG_ONELINE);
                std::cout << std::endl;

                std::cout << "Peer Certificate Issuer: ";
                X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(peerCert), 0, XN_FLAG_ONELINE);
                std::cout << std::endl;

                // Cleanup
                X509_free(peerCert);
            } else {
                std::cout << "No peer certificate received." << std::endl;
            }

            cout << "Version: " << buffer << endl;
            cout << "State: " << state << endl;
            cout << SSL_get_cipher(ssl) << endl;
            cout << SSL_get_verify_result(ssl) << endl;
            //cout << session->status << endl;
        }
};


int main(int argc, char* argv[])
{
    if(argc > 3 || argc == 2)
    {
        cout << "Proper input is webscrapper.exe <URL> <Port#>" << endl;
        exit(-1);
    }

    InstagramScrapper* testHTTPS = new InstagramScrapper("www.example.com", "443");
    //InstagramScrapper giveaway("www.example.com", "80");  //Testing HTTP GET from HTTPS web server //** This is possible

    testHTTPS->CreateSocket(); // discard return of true because its inconsiquential
    testHTTPS->GetHostInfo(); //Get host info for connection thats about to occur
    testHTTPS->ConnectToURL(); //Connection Established to example.com verified with Wireshark
    

    testHTTPS->CleanUp();
    return 0;
}

/*
    //InstagramScrapper cern("info.cern.ch", "80"); //Testing HTTP get request
    InstagramScrapper cern(argv[1], argv[2]); //Testing command line inputs

    cern.Init();
    cern.CreateSocket();
    if(cern.GetHostInfo() != 0) return -1;
    if(cern.ConnectToURL() != 0) return -1;
    if(cern.GETRequest("/hypertext/WWW/TheProject.html") == -1) {
       cern.CleanUp();
       return -1;
    } else { 
       cern.CreateFileNamed("output.txt");
    }
    int totalRecieved = cern.Receive();
    cout << "Received " << totalRecieved << " total bytes" << endl;
    cern.CleanUp();
*/

