#include <iostream>
#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <mutex>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <random>
#include <iomanip>

#include "httplib.h"
#include "template.hpp"

using namespace std;

string jsonEscape(const string& input) {
    stringstream ss;
    for (char c : input) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    ss << "\\u" << hex << setw(4) << setfill('0') << (int)c;
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

void set_security_headers(httplib::Response& res, const string& contentType) {
    res.set_header("Content-Type", contentType);
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-XSS-Protection", "1; mode=block");
    res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
    res.set_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self'");
}

class OTPManager {
private:
    unordered_map<string, string> otpSecrets;
    unordered_map<string, string> otpCodes;
    unordered_map<string, time_t> otpExpiry;
    mutex otp_mutex;

    string generateSecret(int length = 32) {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        string secret;
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, chars.length() - 1);
        for (int i = 0; i < length; i++) {
            secret += chars[dis(gen)];
        }
        return secret;
    }

    string generateOTP(const string& secret, time_t timeStep = 30) {
        time_t currentTime = time(nullptr) / timeStep;
        string combined = secret + to_string(currentTime);
        unsigned int hash = 5381;
        for (char c : combined) hash = ((hash << 5) + hash) + c;
        string otp = to_string(hash % 1000000);
        while (otp.length() < 6) otp = "0" + otp;
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
        if (it->second.first >= maxRequests) return false;
        it->second.first++;
        return true;
    }
};

class URLShortenerServer {
private:
    unordered_map<string, string> aliases;
    Template templateEngine;
    mutex aliases_mutex;
    const string DATA_FILE = "aliases.dat";
    OTPManager otpManager;
    RateLimit rateLimiter;
    int server_port;

    string readFile(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) return "";
        return string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
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
    }

    void saveAliases() {
        ofstream file(DATA_FILE);
        if (!file.is_open()) return;
        for (const auto& pair : aliases) {
            file << pair.first << "|" << pair.second << "\n";
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
            if (iscntrl(c)) return false;
        }
        return true;
    }

    string extractJsonValue(const string& body, const string& key) {
        string search_key = "\"" + key + "\":\"";
        size_t key_pos = body.find(search_key);
        if (key_pos == string::npos) return "";
        size_t value_start = key_pos + search_key.length();
        size_t value_end = body.find("\"", value_start);
        while (value_end != string::npos && body[value_end - 1] == '\\') {
            value_end = body.find("\"", value_end + 1);
        }
        if (value_end == string::npos) return "";
        return body.substr(value_start, value_end - value_start);
    }

public:
    URLShortenerServer(int port = 8080) : server_port(port), templateEngine("") {
        try {
            templateEngine = Template::fromFile("index.html");
        } catch (...) {}
        loadAliases();
        addTestAliases();
    }

    void addTestAliases() {
        lock_guard<mutex> lock(aliases_mutex);
        if (aliases.empty()) {
            aliases["google"] = "https://www.google.com";
            aliases["github"] = "https://www.github.com";
        }
    }

    void start() {
        httplib::Server svr;

        svr.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
            if (!rateLimiter.checkRateLimit(req.remote_addr)) {
                set_security_headers(res, "application/json");
                res.status = 429;
                res.set_content("{\"error\":\"Rate limit exceeded.\"}", "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });

        svr.Get("/", [this](const httplib::Request&, httplib::Response& res) {
            lock_guard<mutex> lock(aliases_mutex);
            templateEngine.set("aliases", "");
            set_security_headers(res, "text/html");
            res.set_content(templateEngine.render(), "text/html");
        });

        svr.Get("/admin", [this](const httplib::Request&, httplib::Response& res) {
            string adminContent = readFile("admin.html");
            if (adminContent.empty()) {
                res.status = 404;
                adminContent = "<h1>404 Not Found</h1>";
            }
            set_security_headers(res, "text/html");
            res.set_content(adminContent, "text/html");
        });

        svr.Get(R"(/r/([a-zA-Z0-9_-]+))", [this](const httplib::Request& req, httplib::Response& res) {
            string alias = req.matches[1].str();
            lock_guard<mutex> lock(aliases_mutex);
            auto it = aliases.find(alias);
            if (it != aliases.end()) {
                res.set_redirect(it->second, 302);
            } else {
                res.status = 404;
                set_security_headers(res, "text/html");
                res.set_content("<h1>404 Not Found</h1>", "text/html");
            }
        });

        svr.Get("/api/generate-otp", [this](const httplib::Request&, httplib::Response& res) {
            string otp = otpManager.generateNewOTP("admin");
            string json = "{\"otp\":\"" + jsonEscape(otp) + "\",\"valid_for_seconds\":300}";
            set_security_headers(res, "application/json");
            res.set_content(json, "application/json");
        });

        svr.Get("/api/aliases", [this](const httplib::Request& req, httplib::Response& res) {
            lock_guard<mutex> lock(aliases_mutex);
            stringstream json;
            json << "{\"aliases\":[";
            bool first = true;
            for (const auto& pair : aliases) {
                if (!first) json << ",";
                json << "{\"alias\":\"" << jsonEscape(pair.first)
                     << "\",\"url\":\"" << jsonEscape(pair.second) << "\"}";
                first = false;
            }
            json << "]}";
            set_security_headers(res, "application/json");
            res.set_content(json.str(), "application/json");
        });

        svr.Post("/api/aliases", [this](const httplib::Request& req, httplib::Response& res) {
            string alias = extractJsonValue(req.body, "alias");
            string url = extractJsonValue(req.body, "url");

            if (alias.empty() || url.empty()) {
                set_security_headers(res, "application/json");
                res.status = 400;
                res.set_content("{\"status\":\"error\",\"message\":\"Invalid JSON.\"}", "application/json");
                return;
            }

            if (!isValidAlias(alias)) {
                set_security_headers(res, "application/json");
                res.status = 400;
                res.set_content("{\"status\":\"error\",\"message\":\"Invalid alias.\"}", "application/json");
                return;
            }

            if (!isValidUrl(url)) {
                set_security_headers(res, "application/json");
                res.status = 400;
                res.set_content("{\"status\":\"error\",\"message\":\"Invalid URL.\"}", "application/json");
                return;
            }

            {
                lock_guard<mutex> lock(aliases_mutex);
                if (aliases.find(alias) != aliases.end()) {
                    set_security_headers(res, "application/json");
                    res.status = 409;
                    res.set_content("{\"status\":\"error\",\"message\":\"Alias exists.\"}", "application/json");
                    return;
                }
            }

            {
                lock_guard<mutex> lock(aliases_mutex);
                aliases[alias] = url;
                saveAliases();
            }

            string jsonResponse = "{\"status\":\"success\",\"alias\":\"" + jsonEscape(alias) +
                                  "\",\"url\":\"" + jsonEscape(url) + "\"}";
            set_security_headers(res, "application/json");
            res.set_content(jsonResponse, "application/json");
        });

        cout << "Server running on port " << server_port << endl;
        if (!svr.listen("0.0.0.0", server_port)) {
            cerr << "Failed to bind port " << server_port << endl;
        }
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
        server.start();
    } catch (const exception& e) {
        return 1;
    }
    return 0;
}
