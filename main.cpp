#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <cstdlib>
#include <algorithm>
#include "template.hpp" 

using namespace std;

// OTP (One-Time Password) Implementation - Logic retained for potential future use, 
// but removed from current API endpoints for now.
class OTPManager {
private:
    unordered_map<string, string> otpSecrets;
    unordered_map<string, string> otpCodes;
    unordered_map<string, time_t> otpExpiry;
    mutex otp_mutex;
    
    string generateSecret(int length = 32) {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        string secret;
        for (int i = 0; i < length; i++) {
            secret += chars[rand() % chars.length()];
        }
        return secret;
    }
    
    string generateOTP(const string& secret, time_t timeStep = 30) {
        time_t currentTime = time(nullptr) / timeStep;
        string combined = secret + to_string(currentTime);
        
        unsigned int hash = 5381;
        for (char c : combined) {
            hash = ((hash << 5) + hash) + c;
        }
        
        string otp = to_string(hash % 1000000);
        while (otp.length() < 6) {
            otp = "0" + otp;
        }
        return otp;
    }
    
public:
    string generateNewOTP(const string& userId) {
        lock_guard<mutex> lock(otp_mutex);
        
        if (otpSecrets.find(userId) == otpSecrets.end()) {
            otpSecrets[userId] = generateSecret();
        }
        
        string otp = generateOTP(otpSecrets[userId]);
        otpCodes[userId] = otp;
        otpExpiry[userId] = time(nullptr) + 300;
        
        return otp;
    }
    
    bool validateOTP(const string& userId, const string& otpCode) {
        lock_guard<mutex> lock(otp_mutex);
        
        if (otpExpiry.find(userId) == otpExpiry.end() || 
            otpExpiry[userId] < time(nullptr) ||
            otpCodes.find(userId) == otpCodes.end()) {
            return false;
        }
        
        string currentOTP = generateOTP(otpSecrets[userId]);
        string previousOTP = generateOTP(otpSecrets[userId], 30);
        
        bool isValid = (otpCode == currentOTP || otpCode == previousOTP);
        
        if (isValid) {
            otpCodes.erase(userId);
            otpExpiry.erase(userId);
        }
        
        return isValid;
    }
};

class URLShortenerServer {
private:
    unordered_map<string, string> aliases;
    Template templateEngine;
    mutex aliases_mutex;
    int server_port;
    const string DATA_FILE = "aliases.dat";
    OTPManager otpManager;
    
    string readFile(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) return "";
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
        return content;
    }
    
    string buildHttpResponse(const string& content, const string& contentType = "text/html", int statusCode = 200) {
        string statusText = "OK";
        if (statusCode == 404) statusText = "Not Found";
        else if (statusCode == 400) statusText = "Bad Request";
        else if (statusCode == 401) statusText = "Unauthorized";
        else if (statusCode == 409) statusText = "Conflict";
        else if (statusCode == 429) statusText = "Too Many Requests";
        
        string response = "HTTP/1.1 " + to_string(statusCode) + " " + statusText + "\r\n";
        response += "Content-Type: " + contentType + "\r\n";
        response += "Content-Length: " + to_string(content.length()) + "\r\n";
        response += "Connection: close\r\n";
        
        response += "X-Content-Type-Options: nosniff\r\n";
        response += "X-Frame-Options: DENY\r\n";
        response += "X-XSS-Protection: 1; mode=block\r\n";
        response += "Referrer-Policy: strict-origin-when-cross-origin\r\n";
        response += "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self'\r\n";
        
        response += "\r\n";
        response += content;
        
        return response;
    }
    
    string handleGetRequest(const string& path, const unordered_map<string, string>& queryParams, const unordered_map<string, string>& headers = {}) {
        if (path == "/") {
            lock_guard<mutex> lock(aliases_mutex);
            templateEngine.set("aliases", "");
            return buildHttpResponse(templateEngine.render());
        }
        else if (path == "/admin") {
            string adminContent = readFile("admin.html");
            if (adminContent.empty()) {
                return buildHttpResponse("<h1>404 Not Found</h1><p>Admin page not found.</p>", "text/html", 404);
            }
            return buildHttpResponse(adminContent);
        }
        else if (path.find("/r/") == 0) {
            string alias = path.substr(3);
            lock_guard<mutex> lock(aliases_mutex);
            
            auto it = aliases.find(alias);
            if (it != aliases.end()) {
                string redirectResponse = "HTTP/1.1 302 Found\r\n";
                redirectResponse += "Location: " + it->second + "\r\n";
                redirectResponse += "Connection: close\r\n";
                redirectResponse += "\r\n";
                return redirectResponse;
            } else {
                return buildHttpResponse("<h1>404 Not Found</h1><p>Alias not found.</p>", "text/html", 404);
            }
        }
        else if (path == "/api/aliases") {
            // OTP check removed for testing/simplicity
            lock_guard<mutex> lock(aliases_mutex);
            
            string json = "{\"aliases\":[";
            bool first = true;
            for (const auto& pair : aliases) {
                if (!first) json += ",";
                json += "{\"alias\":\"" + pair.first + "\",\"url\":\"" + pair.second + "\"}";
                first = false;
            }
            json += "]}";
            
            return buildHttpResponse(json, "application/json");
        }
        else if (path == "/api/generate-otp") {
            string otp = otpManager.generateNewOTP("admin");
            string json = "{\"otp\":\"" + otp + "\",\"valid_for_seconds\":300}";
            return buildHttpResponse(json, "application/json");
        }
        else {
            return buildHttpResponse("<h1>404 Not Found</h1>", "text/html", 404);
        }
    }
    
    bool isValidAlias(const string& alias) {
        if (alias.empty() || alias.length() > 50) return false;
        for (char c : alias) {
            if (!isalnum(c) && c != '-' && c != '_') return false;
        }
        return true;
    }
    
    bool isValidUrl(const string& url) {
        if (url.empty() || url.length() > 2000) return false;
        if (url.find("http://") != 0 && url.find("https://") != 0) return false;
        for (char c : url) {
            if (c == '\0' || c == '\r' || c == '\n' || c == '\t') return false;
        }
        return true;
    }
    
    struct RateLimit {
        unordered_map<string, pair<int, time_t>> requestCounts;
        mutex rateMutex;
        
        bool checkRateLimit(const string& ip, int maxRequests = 100, int windowSeconds = 60) {
            lock_guard<mutex> lock(rateMutex);
            time_t now = time(nullptr);
            
            auto it = requestCounts.find(ip);
            if (it == requestCounts.end() || now - it->second.second > windowSeconds) {
                requestCounts[ip] = {1, now};
                return true;
            }
            
            if (it->second.first >= maxRequests) {
                return false;
            }
            
            it->second.first++;
            return true;
        }
    };
    
    RateLimit rateLimiter;
    
    string extractJsonValue(const string& body, const string& key) {
        string search_key = "\"" + key + "\":\"";
        size_t key_pos = body.find(search_key);
        if (key_pos == string::npos) return "";
        size_t value_start = key_pos + search_key.length();
        size_t value_end = body.find("\"", value_start);
        if (value_end == string::npos) return "";
        return body.substr(value_start, value_end - value_start);
    }

    string handlePostRequest(const string& path, const string& body, const unordered_map<string, string>& headers) {
        string clientIp = headers.count("X-Forwarded-For") ? headers.at("X-Forwarded-For") : (headers.count("X-Real-IP") ? headers.at("X-Real-IP") : "unknown");
        
        if (!rateLimiter.checkRateLimit(clientIp)) {
            return buildHttpResponse("{\"error\":\"Rate limit exceeded. Please try again later.\"}", "application/json", 429);
        }
        
        if (path == "/api/aliases") {
            string alias = extractJsonValue(body, "alias");
            string url = extractJsonValue(body, "url");
            
            if (alias.empty() || url.empty()) {
                string errorResponse = "{\"status\":\"error\",\"message\":\"Invalid request format. Expected JSON: {\\\"alias\\\":\\\"your_alias\\\",\\\"url\\\":\\\"your_url\\\"}\"}";
                return buildHttpResponse(errorResponse, "application/json", 400);
            }
            
            if (!isValidAlias(alias)) {
                return buildHttpResponse("{\"status\":\"error\",\"message\":\"Invalid alias. Only alphanumeric characters, hyphens, and underscores are allowed (max 50 chars).\"}", "application/json", 400);
            }
            
            if (!isValidUrl(url)) {
                return buildHttpResponse("{\"status\":\"error\",\"message\":\"Invalid URL. Must start with http:// or https:// and be a valid URL (max 2000 chars).\"}", "application/json", 400);
            }
            
            // OTP check and extraction removed for testing/simplicity
            
            {
                lock_guard<mutex> lock(aliases_mutex);
                if (aliases.find(alias) != aliases.end()) {
                    return buildHttpResponse("{\"status\":\"error\",\"message\":\"Alias already exists.\"}", "application/json", 409);
                }
            }
            
            {
                lock_guard<mutex> lock(aliases_mutex);
                aliases[alias] = url;
                saveAliases();
            }
            
            string jsonResponse = "{\"status\":\"success\",\"alias\":\"" + alias + "\",\"url\":\"" + url + "\"}";
            return buildHttpResponse(jsonResponse, "application/json");
        }
        else {
            return buildHttpResponse("<h1>404 Not Found</h1>", "text/html", 404);
        }
    }
    
    void parseQueryParams(const string& query, unordered_map<string, string>& params) {
        if (query.empty()) return;
        size_t start = 0;
        size_t end = query.find('&');
        while (end != string::npos) {
            string pair = query.substr(start, end - start);
            size_t eqPos = pair.find('=');
            if (eqPos != string::npos) params[pair.substr(0, eqPos)] = pair.substr(eqPos + 1);
            start = end + 1;
            end = query.find('&', start);
        }
        string pair = query.substr(start);
        size_t eqPos = pair.find('=');
        if (eqPos != string::npos) params[pair.substr(0, eqPos)] = pair.substr(eqPos + 1);
    }
    
    void parseHeaders(const string& headersStr, unordered_map<string, string>& headers) {
        size_t start = 0;
        size_t end = headersStr.find("\r\n");
        
        while (end != string::npos) {
            string line = headersStr.substr(start, end - start);
            size_t colonPos = line.find(": ");
            if (colonPos != string::npos) {
                string key = line.substr(0, colonPos);
                transform(key.begin(), key.end(), key.begin(), ::tolower);
                headers[key] = line.substr(colonPos + 2);
            }
            start = end + 2;
            end = headersStr.find("\r\n", start);
        }
    }
    
    void handleClient(int clientSocket) {
        try {
            char buffer[65536] = {0}; 
            ssize_t bytesRead = read(clientSocket, buffer, sizeof(buffer) - 1);
            
            if (bytesRead <= 0) { close(clientSocket); return; }
            
            string request(buffer, bytesRead);
            
            size_t methodEnd = request.find(' ');
            if (methodEnd == string::npos) { close(clientSocket); return; }
            
            string method = request.substr(0, methodEnd);
            size_t pathStart = methodEnd + 1;
            size_t pathEnd = request.find(' ', pathStart);
            
            if (pathEnd == string::npos) { close(clientSocket); return; }
            
            string path = request.substr(pathStart, pathEnd - pathStart);
            size_t queryStart = path.find('?');
            string query;
            
            if (queryStart != string::npos) {
                query = path.substr(queryStart + 1);
                path = path.substr(0, queryStart);
            }
            
            size_t headersStart = request.find("\r\n") + 2;
            size_t headersEnd = request.find("\r\n\r\n");
            
            unordered_map<string, string> headers;
            if (headersStart != string::npos && headersEnd != string::npos && headersStart < headersEnd) {
                parseHeaders(request.substr(headersStart, headersEnd - headersStart), headers);
            }
            
            string body;
            size_t bodyStart = headersEnd + 4;
            if (bodyStart < request.length()) {
                body = request.substr(bodyStart);
            }
            
            unordered_map<string, string> queryParams;
            parseQueryParams(query, queryParams);
            
            string response;
            
            if (method == "GET") {
                response = handleGetRequest(path, queryParams, headers);
            } else if (method == "POST") {
                cerr << "DEBUG: POST body: " << body << endl;
                response = handlePostRequest(path, body, headers);
            } else {
                response = buildHttpResponse("<h1>405 Method Not Allowed</h1>", "text/html", 405);
            }
            
            write(clientSocket, response.c_str(), response.length());
            close(clientSocket);
        } catch (const std::exception& e) {
            cerr << "!!! EXCEPTION in handleClient: " << e.what() << endl;
            close(clientSocket);
        } catch (...) {
            cerr << "!!! UNKNOWN EXCEPTION in handleClient" << endl;
            close(clientSocket);
        }
    }
    
public:
    URLShortenerServer(int port = 8080) : server_port(port), templateEngine("") {
        try {
            templateEngine = Template::fromFile("index.html");
        } catch (const exception& e) {
            cerr << "Error loading template: " << e.what() << endl;
            throw;
        }
        loadAliases();
    }
    
    void start() {
        int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket < 0) { cerr << "Error creating socket" << endl; return; }

        int opt = 1;
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            cerr << "Error setting socket options" << endl;
            close(serverSocket);
            return;
        }
        
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(server_port);
        
        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            cerr << "Error binding socket" << endl;
            close(serverSocket);
            return;
        }
        
        if (listen(serverSocket, 10) < 0) {
            cerr << "Error listening on socket" << endl;
            close(serverSocket);
            return;
        }
        
        cout << "URL Shortener Server started on port " << server_port << endl;
        
        while (true) {
            sockaddr_in clientAddr;
            memset(&clientAddr, 0, sizeof(clientAddr));
            socklen_t clientAddrLen = sizeof(clientAddr);
            
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
            if (clientSocket < 0) { cerr << "Error accepting connection" << endl; continue; }
            
            thread clientThread(&URLShortenerServer::handleClient, this, clientSocket);
            clientThread.detach();
        }
        
        close(serverSocket);
    }
    
    void addTestAliases() {
        lock_guard<mutex> lock(aliases_mutex);
        aliases["google"] = "https://www.google.com";
        aliases["github"] = "https://www.github.com";
        aliases["youtube"] = "https://www.youtube.com";
    }
    
    void loadAliases() {
        ifstream file(DATA_FILE);
        if (!file.is_open()) return;
        
        string line;
        while (getline(file, line)) {
            size_t delimiterPos = line.find("|");
            if (delimiterPos != string::npos) {
                aliases[line.substr(0, delimiterPos)] = line.substr(delimiterPos + 1);
            }
        }
        file.close();
    }
    
    void saveAliases() {
        ofstream file(DATA_FILE);
        if (!file.is_open()) { cerr << "Error: Could not save aliases to file" << endl; return; }
        
        for (const auto& pair : aliases) {
            file << pair.first << "|" << pair.second << "\n";
        }
        file.close();
    }
};

int main() {
    int port = 8080;
    const char* port_env = getenv("PORT");
    if (port_env) {
        try {
            port = stoi(port_env);
            if (port <= 0 || port > 65535) port = 8080;
        } catch (...) {
            port = 8080;
        }
    }

    try {
        URLShortenerServer server(port);
        server.addTestAliases();
        server.start();
    } catch (const exception& e) {
        cerr << "Server error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
