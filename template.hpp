#pragma once
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cctype>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <functional>
#include <fstream>
#include <iomanip>
#include <ctime>

using namespace std;
using namespace std::chrono;

enum class TokenType { 
    Text, VarOpen, VarClose, TagOpen, TagClose, CommentOpen, CommentClose,
    Identifier, Whitespace, Operator, Number, String, Boolean, Pipe
};

struct Token { 
    TokenType type; 
    string value; 
};

// Dictionary structure for template variables
struct Dict {
    unordered_map<string, string> values;
    
    string get(const string& key) const {
        auto it = values.find(key);
        return it != values.end() ? it->second : "";
    }
    
    void set(const string& key, const string& value) {
        values[key] = value;
    }
    
    bool has(const string& key) const {
        return values.find(key) != values.end();
    }
};

class Template {
private:
    vector<Token> tokens;
    string template_id;
    unordered_map<string, function<string(const vector<string>&)>> custom_filters;
    unordered_map<string, Dict> dictionaries;
    
    void log(const string& msg) {
        auto now = system_clock::now();
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
        time_t t = system_clock::to_time_t(now);
        cout << "[" << put_time(localtime(&t), "%H:%M:%S") << "." << ms.count() << "] " << msg << endl;
    }

    string html_escape(const string& str) {
        string result;
        for (char c : str) {
            switch (c) {
                case '&': result += "&amp;"; break;
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '"': result += "&quot;"; break;
                case '\'': result += "&#39;"; break;
                default: result += c;
            }
        }
        return result;
    }

    string url_encode(const string& str) {
        string escaped_str = "";
        for (char c : str) {
            if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
                escaped_str += c;
            } else {
                escaped_str += '%';
                escaped_str += "0123456789ABCDEF"[(c >> 4) & 0xF];
                escaped_str += "0123456789ABCDEF"[c & 0xF];
            }
        }
        return escaped_str;
    }

    string js_escape(const string& str) {
        string result;
        for (char c : str) {
            switch (c) {
                case '\\': result += "\\\\"; break;
                case '"': result += "\\\""; break;
                case '\'': result += "\\'"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }

    bool string_endswith(const string& value, const string& suffix) const {
        if (value.length() >= suffix.length()) {
            return value.compare(value.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
        return false;
    }

    bool string_startswith(const string& value, const string& prefix) const {
        if (value.length() >= prefix.length()) {
            return value.compare(0, prefix.length(), prefix) == 0;
        }
        return false;
    }

    bool string_contains(const string& value, const string& substring) const {
        return value.find(substring) != string::npos;
    }

    string apply_filter(const string& value, const string& filter, const vector<string>& args = {}) {
        // Check custom filters first
        auto custom_it = custom_filters.find(filter);
        if (custom_it != custom_filters.end()) {
            vector<string> filter_args = {value};
            filter_args.insert(filter_args.end(), args.begin(), args.end());
            return custom_it->second(filter_args);
        }
        
        // Built-in filters
        if (filter == "raw") return value;
        if (filter == "escape") return html_escape(value);
        if (filter == "url_encode") return url_encode(value);
        if (filter == "js_escape") return js_escape(value);
        if (filter == "uppercase" || filter == "upper") {
            string result = value;
            transform(result.begin(), result.end(), result.begin(), ::toupper);
            return result;
        }
        if (filter == "lowercase" || filter == "lower") {
            string result = value;
            transform(result.begin(), result.end(), result.begin(), ::tolower);
            return result;
        }
        if (filter == "trim") {
            string result = value;
            result.erase(0, result.find_first_not_of(" \t\n\r"));
            result.erase(result.find_last_not_of(" \t\n\r") + 1);
            return result;
        }
        if (filter == "length") {
            return to_string(value.length());
        }
        if (filter == "capitalize") {
            string result = value;
            if (!result.empty()) {
                result[0] = toupper(result[0]);
            }
            return result;
        }
        if (filter == "reverse") {
            string result = value;
            reverse(result.begin(), result.end());
            return result;
        }
        if (filter == "truncate") {
            size_t len = args.empty() ? 50 : stoi(args[0]);
            if (value.length() > len) {
                return value.substr(0, len) + "...";
            }
            return value;
        }
        if (filter == "replace") {
            if (args.size() >= 2) {
                string result = value;
                string from = args[0];
                string to = args[1];
                size_t pos = 0;
                while ((pos = result.find(from, pos)) != string::npos) {
                    result.replace(pos, from.length(), to);
                    pos += to.length();
                }
                return result;
            }
            return value;
        }
        if (filter == "default") {
            return value.empty() && !args.empty() ? args[0] : value;
        }
        if (filter == "first") {
            return value.empty() ? "" : string(1, value[0]);
        }
        if (filter == "last") {
            return value.empty() ? "" : string(1, value.back());
        }
        if (filter == "round") {
            try {
                double num = stod(value);
                int precision = args.empty() ? 0 : stoi(args[0]);
                ostringstream oss;
                oss << fixed << setprecision(precision) << num;
                return oss.str();
            } catch (...) {
                return value;
            }
        }
        
        // Date/Time filters
        if (filter == "date") {
            try {
                // Parse timestamp or date string
                time_t timestamp = stoll(value);
                struct tm* timeinfo = localtime(&timestamp);
                string format = args.empty() ? "%Y-%m-%d" : args[0];
                
                char buffer[256];
                strftime(buffer, sizeof(buffer), format.c_str(), timeinfo);
                return string(buffer);
            } catch (...) {
                return value;
            }
        }
        
        if (filter == "time") {
            try {
                time_t timestamp = stoll(value);
                struct tm* timeinfo = localtime(&timestamp);
                string format = args.empty() ? "%H:%M:%S" : args[0];
                
                char buffer[256];
                strftime(buffer, sizeof(buffer), format.c_str(), timeinfo);
                return string(buffer);
            } catch (...) {
                return value;
            }
        }
        
        if (filter == "datetime") {
            try {
                time_t timestamp = stoll(value);
                struct tm* timeinfo = localtime(&timestamp);
                string format = args.empty() ? "%Y-%m-%d %H:%M:%S" : args[0];
                
                char buffer[256];
                strftime(buffer, sizeof(buffer), format.c_str(), timeinfo);
                return string(buffer);
            } catch (...) {
                return value;
            }
        }

        if (filter == "base64_encode") {
            return this->base64_encode(value);
        }
        if (filter == "base64_decode" || filter == "base64") {
            return this->base64_decode(value);
        }

        if (filter == "endswith") {
            cout << "DEBUG: endswith filter called with value: '" << value << "', args size: " << args.size() << endl;
            if (args.empty()) {
                //cout << "DEBUG: endswith called with no args" << endl;
                return "false";
            }
            //cout << "DEBUG: endswith checking '" << value << "' ends with '" << args[0] << "'" << endl;
            bool result = string_endswith(value, args[0]);
            //cout << "DEBUG: endswith result: " << (result ? "true" : "false") << endl;
            return result ? "true" : "false";
        }

        if (filter == "startswith") {
            if (args.empty()) return "false";
            return string_startswith(value, args[0]) ? "true" : "false";
        }

        if (filter == "contains") {
            if (args.empty()) return "false";
            return string_contains(value, args[0]) ? "true" : "false";
        }
        
        if (filter == "join") {
            return value; // For lists, handled separately
        }
        
        return value;
    }

    vector<Token> tokenize(const string& src) {
        auto start = high_resolution_clock::now();
        vector<Token> tokens;
        size_t i = 0;
        bool inside_tag = false;
        
        while (i < src.size()) {
            if (i + 1 < src.size() && src[i] == '{' && src[i + 1] == '#') {
                tokens.push_back({TokenType::CommentOpen, "{#"});
                i += 2;
                string comment;
                while (i + 1 < src.size() && !(src[i] == '#' && src[i + 1] == '}')) {
                    comment += src[i++];
                }
                if (i + 1 < src.size()) {
                    tokens.push_back({TokenType::CommentClose, "#}"});
                    i += 2;
                }
                continue;
            }
            
            if (i + 1 < src.size() && src[i] == '{' && src[i + 1] == '%') {
                tokens.push_back({TokenType::TagOpen, "{%"});
                inside_tag = true;
                i += 2;
                continue;
            }
            
            if (i + 1 < src.size() && src[i] == '%' && src[i + 1] == '}') {
                tokens.push_back({TokenType::TagClose, "%}"});
                inside_tag = false;
                i += 2;
                continue;
            }
            
            if (i + 1 < src.size() && src[i] == '{' && src[i + 1] == '{') {
                tokens.push_back({TokenType::VarOpen, "{{"});
                inside_tag = true;
                i += 2;
                continue;
            }
            
            if (i + 1 < src.size() && src[i] == '}' && src[i + 1] == '}') {
                tokens.push_back({TokenType::VarClose, "}}"});
                inside_tag = false;
                i += 2;
                continue;
            }
            
            if (inside_tag && src[i] == '|') {
                tokens.push_back({TokenType::Pipe, "|"});
                i++;
                continue;
            }
            
            if (inside_tag && isspace(src[i])) {
                string ws;
                while (i < src.size() && isspace(src[i])) {
                    ws += src[i++];
                }
                tokens.push_back({TokenType::Whitespace, ws});
                continue;
            }
            
            if (inside_tag && (src[i] == '"' || src[i] == '\'')) {
                char quote = src[i];
                string str;
                i++;
                while (i < src.size() && src[i] != quote) {
                    if (src[i] == '\\' && i + 1 < src.size()) {
                        i++;
                        str += src[i++];
                    } else {
                        str += src[i++];
                    }
                }
                if (i < src.size()) i++;
                tokens.push_back({TokenType::String, str});
                continue;
            }
            
            if (inside_tag && (src[i] == '>' || src[i] == '<' || src[i] == '=' || src[i] == '!' || src[i] == '+' || src[i] == '-' || src[i] == '*' || src[i] == '/')) {
                string op;
                op += src[i++];
                if (i < src.size() && src[i] == '=') {
                    op += src[i++];
                }
                tokens.push_back({TokenType::Operator, op});
                continue;
            }
            
            if (inside_tag && isdigit(src[i])) {
                string num;
                while (i < src.size() && (isdigit(src[i]) || src[i] == '.')) {
                    num += src[i++];
                }
                tokens.push_back({TokenType::Number, num});
                continue;
            }
            
            if (inside_tag && (isalnum(src[i]) || src[i] == '_')) {
                string id;
                while (i < src.size() && (isalnum(src[i]) || src[i] == '_')) {
                    id += src[i++];
                }
                if (id == "true" || id == "false") {
                    tokens.push_back({TokenType::Boolean, id});
                } else {
                    tokens.push_back({TokenType::Identifier, id});
                }
                continue;
            }
            
            string text;
            text += src[i++];
            while (i < src.size()) {
                if ((i + 1 < src.size() && src[i] == '{' && (src[i + 1] == '%' || src[i + 1] == '{' || src[i + 1] == '#')) ||
                    (i + 1 < src.size() && src[i] == '%' && src[i + 1] == '}') ||
                    (i + 1 < src.size() && src[i] == '}' && src[i + 1] == '}')) {
                    break;
                }
                text += src[i++];
            }
            tokens.push_back({TokenType::Text, text});
        }
        
        auto end = high_resolution_clock::now();
        log("Tokenized " + to_string(tokens.size()) + " tokens in " + 
            to_string(duration_cast<microseconds>(end - start).count()) + "μs");
        
        return tokens;
    }
    
    size_t skip_whitespace(const vector<Token>& tokens, size_t i) {
        while (i < tokens.size() && tokens[i].type == TokenType::Whitespace) {
            i++;
        }
        return i;
    }
    
    string resolve_value(const string& token_value, TokenType token_type, 
                         const unordered_map<string, string>& vars,
                         const unordered_map<string, vector<string>>& lists) {
        if (token_type == TokenType::String || token_type == TokenType::Number || token_type == TokenType::Boolean) {
            return token_value;
        }
        if (token_type == TokenType::Identifier) {
            // Check for dictionary access (dot notation)
            size_t dot_pos = token_value.find('.');
            if (dot_pos != string::npos) {
                string dict_name = token_value.substr(0, dot_pos);
                string key = token_value.substr(dot_pos + 1);
                
                auto dict_it = dictionaries.find(dict_name);
                if (dict_it != dictionaries.end()) {
                    return dict_it->second.get(key);
                }
            }
            
            auto it = vars.find(token_value);
            if (it != vars.end()) return it->second;
            
            auto lit = lists.find(token_value);
            if (lit != lists.end()) return to_string(lit->second.size());
            
            return "";
        }
        return "";
    }

    // Separate function for arithmetic operations
    string perform_arithmetic(const string& left_val, const string& right_val, const string& op) {
        try {
            double left_num = stod(left_val);
            double right_num = stod(right_val);
            double result = 0;
            
            if (op == "+") result = left_num + right_num;
            else if (op == "-") result = left_num - right_num;
            else if (op == "*") result = left_num * right_num;
            else if (op == "/") result = left_num / right_num;
            
            return to_string(result);
        } catch (...) {
            return ""; // Return empty string if arithmetic fails
        }
    }

    bool evaluate_condition(const string& left_operand, TokenType left_type,
                           const string& op, const string& right_operand, 
                           TokenType right_type, 
                           const unordered_map<string, string>& vars,
                           const unordered_map<string, vector<string>>& lists) {
        if (op.empty()) {
            string val = resolve_value(left_operand, left_type, vars, lists);
            return !val.empty() && val != "0" && val != "false";
        }
        
        string left_val = resolve_value(left_operand, left_type, vars, lists);
        string right_val = resolve_value(right_operand, right_type, vars, lists);
        
        // Handle arithmetic operations
        if (op == "+" || op == "-" || op == "*" || op == "/") {
            // Arithmetic operations return string, so we can't use them directly
            // Use them for math in other contexts, but for comparison we treat them as numeric comparison
            try {
                double left_num = stod(left_val);
                double right_num = stod(right_val);
                
                if (op == "+") return left_num + right_num;
                if (op == "-") return left_num - right_num;
                if (op == "*") return left_num * right_num;
                if (op == "/") return left_num / right_num;
            } catch (...) {
                return false; // Can't perform arithmetic on non-numbers
            }
        }
        
        if (op == "==") return left_val == right_val;
        if (op == "!=") return left_val != right_val;
        
        if (op == ">" || op == "<" || op == ">=" || op == "<=") {
            try {
                double left_num = stod(left_val);
                double right_num = stod(right_val);
                
                if (op == ">") return left_num > right_num;
                if (op == "<") return left_num < right_num;
                if (op == ">=") return left_num >= right_num;
                if (op == "<=") return left_num <= right_num;
            } catch (...) {
                if (op == ">") return left_val > right_val;
                if (op == "<") return left_val < right_val;
                if (op == ">=") return left_val >= right_val;
                if (op == "<=") return left_val <= right_val;
            }
        }
        
        return false;
    }

    // Helper function to find the colon in ternary operator
    size_t find_ternary_colon(const vector<Token>& tokens, size_t start_pos) {
        size_t pos = start_pos;
        int brace_depth = 0;
        int bracket_depth = 0;
        
        while (pos < tokens.size()) {
            if (tokens[pos].type == TokenType::VarClose) {
                break;
            }
            
            if (tokens[pos].type == TokenType::Operator && tokens[pos].value == ":" && 
                brace_depth == 0 && bracket_depth == 0) {
                return pos;
            }
            
            if (tokens[pos].type == TokenType::Text) {
                for (char c : tokens[pos].value) {
                    if (c == '(') brace_depth++;
                    else if (c == ')') brace_depth--;
                    else if (c == '[') bracket_depth++;
                    else if (c == ']') bracket_depth--;
                }
            }
            
            pos++;
        }
        return string::npos;
    }
    
    // Helper function to find the closing }}
    size_t find_var_close(const vector<Token>& tokens, size_t start_pos) {
        size_t pos = start_pos;
        while (pos < tokens.size()) {
            if (tokens[pos].type == TokenType::VarClose) {
                return pos;
            }
            pos++;
        }
        return string::npos;
    }
    
    // Helper function to evaluate ternary condition using your existing logic
    string evaluate_ternary_condition(const vector<Token>& tokens, size_t start_pos, size_t end_pos,
                                     const unordered_map<string, string>& vars,
                                     const unordered_map<string, vector<string>>& lists) {
        // Parse: left_operand operator right_operand
        size_t pos = start_pos;
        
        // Skip whitespace
        while (pos < end_pos && tokens[pos].type == TokenType::Whitespace) {
            pos++;
        }
        
        // Get left operand
        string left_operand = "";
        TokenType left_type = TokenType::Text;
        if (pos < end_pos) {
            if (tokens[pos].type == TokenType::Identifier) {
                left_operand = tokens[pos].value;
                left_type = TokenType::Identifier;
            } else if (tokens[pos].type == TokenType::String) {
                left_operand = tokens[pos].value;
                left_type = TokenType::String;
            } else if (tokens[pos].type == TokenType::Number) {
                left_operand = tokens[pos].value;
                left_type = TokenType::Number;
            } else if (tokens[pos].type == TokenType::Boolean) {
                left_operand = tokens[pos].value;
                left_type = TokenType::Boolean;
            }
        }
        
        // Skip to operator
        pos++;
        while (pos < end_pos && tokens[pos].type == TokenType::Whitespace) {
            pos++;
        }
        
        // Get operator
        string op = "";
        if (pos < end_pos && tokens[pos].type == TokenType::Operator) {
            op = tokens[pos].value;
        }
        
        // Skip to right operand
        pos++;
        while (pos < end_pos && tokens[pos].type == TokenType::Whitespace) {
            pos++;
        }
        
        // Get right operand
        string right_operand = "";
        TokenType right_type = TokenType::Text;
        if (pos < end_pos) {
            if (tokens[pos].type == TokenType::Identifier) {
                right_operand = tokens[pos].value;
                right_type = TokenType::Identifier;
            } else if (tokens[pos].type == TokenType::String) {
                right_operand = tokens[pos].value;
                right_type = TokenType::String;
            } else if (tokens[pos].type == TokenType::Number) {
                right_operand = tokens[pos].value;
                right_type = TokenType::Number;
            } else if (tokens[pos].type == TokenType::Boolean) {
                right_operand = tokens[pos].value;
                right_type = TokenType::Boolean;
            }
        }
        
        // Use your existing evaluation logic
        bool result = evaluate_condition(left_operand, left_type, op, right_operand, right_type, vars, lists);
        return result ? "true" : "false";
    }
    
    // Helper function to extract ternary value (simple text/var extraction)
    string extract_ternary_value(const vector<Token>& tokens, size_t start_pos, size_t end_pos,
                                const unordered_map<string, string>& vars,
                                const unordered_map<string, vector<string>>& lists) {
        string value = "";
        size_t pos = start_pos;
        
        while (pos < end_pos && pos < tokens.size()) {
            if (tokens[pos].type == TokenType::Identifier) {
                auto it = vars.find(tokens[pos].value);
                if (it != vars.end()) {
                    value += it->second;
                } else {
                    // Handle simple literals
                    if (tokens[pos].value == "true" || tokens[pos].value == "false") {
                        value += tokens[pos].value;
                    }
                }
            } else if (tokens[pos].type == TokenType::String) {
                value += tokens[pos].value;
            } else if (tokens[pos].type == TokenType::Number) {
                value += tokens[pos].value;
            } else if (tokens[pos].type == TokenType::Boolean) {
                value += tokens[pos].value;
            } else if (tokens[pos].type == TokenType::Whitespace) {
                value += tokens[pos].value;
            } else if (tokens[pos].type == TokenType::Text) {
                value += tokens[pos].value;
            }
            pos++;
        }
        
        return value;
    }

    string render_internal(const vector<Token>& tokens,
                          const unordered_map<string, string>& vars,
                          const unordered_map<string, vector<string>>& lists) {
        string output;
        size_t i = 0;
        
        while (i < tokens.size()) {
            const Token& tok = tokens[i];
            
            if (tok.type == TokenType::Text || tok.type == TokenType::Whitespace) {
                output += tok.value;
            }
            else if (tok.type == TokenType::CommentOpen) {
                while (i < tokens.size() && tokens[i].type != TokenType::CommentClose) {
                    i++;
                }
            }
            else if (tok.type == TokenType::VarOpen) {
                size_t j = skip_whitespace(tokens, i + 1);
                
                if (j < tokens.size() && tokens[j].type == TokenType::Identifier) {
                    string var_name = tokens[j].value;
                    j = skip_whitespace(tokens, j + 1);
                    
                    // Check for ternary operator: ?
                    if (j < tokens.size() && tokens[j].type == TokenType::Operator && tokens[j].value == "?") {
                        // Parse ternary expression: {{ condition ? true_value : false_value }}
                        size_t colon_pos = find_ternary_colon(tokens, j + 1);
                        size_t var_close_pos = find_var_close(tokens, j + 1);
                        
                        if (colon_pos != string::npos && var_close_pos != string::npos && colon_pos < var_close_pos) {
                            // Extract and evaluate the condition
                            string condition_result = evaluate_ternary_condition(tokens, j + 1, colon_pos, vars, lists);
                            
                            // Extract true and false values
                            string true_value = extract_ternary_value(tokens, j + 1, colon_pos, vars, lists);
                            string false_value = extract_ternary_value(tokens, colon_pos + 1, var_close_pos, vars, lists);
                            
                            string result = (condition_result == "true") ? true_value : false_value;
                            output += result;
                            i = var_close_pos;
                        }
                    } else {
                        // Original variable handling with filters
                        vector<string> filters;
                        vector<vector<string>> filter_args;
                        
                        while (j < tokens.size() && tokens[j].type == TokenType::Pipe) {
                            j = skip_whitespace(tokens, j + 1);
                            if (j < tokens.size() && tokens[j].type == TokenType::Identifier) {
                                string filter_name = tokens[j].value;
                                filters.push_back(filter_name);
                                j = skip_whitespace(tokens, j + 1);
                                
                                // Collect arguments for this filter
                                vector<string> args;
                                while (j < tokens.size() && 
                                       (tokens[j].type == TokenType::String || 
                                        tokens[j].type == TokenType::Number ||
                                        tokens[j].type == TokenType::Identifier ||
                                        tokens[j].type == TokenType::Boolean)) {
                                    args.push_back(tokens[j].value);
                                    j = skip_whitespace(tokens, j + 1);
                                }
                                filter_args.push_back(args);
                            }
                        }
                        
                        if (j < tokens.size() && tokens[j].type == TokenType::VarClose) {
                            auto it = vars.find(var_name);
                            if (it != vars.end()) {
                                string value = it->second;
                                
                                bool has_raw_filter = false;
                                bool has_special_escape_filter = false;
                                
                                // Apply filters
                                for (size_t k = 0; k < filters.size(); k++) {
                                    const string& filter = filters[k];
                                    const vector<string>& args = (k < filter_args.size()) ? filter_args[k] : vector<string>();
                                    
                                    if (filter == "raw") {
                                        has_raw_filter = true;
                                    } else if (filter == "url_encode" || filter == "js_escape" || filter == "escape") {
                                        has_special_escape_filter = true;
                                    }
                                    value = apply_filter(value, filter, args);
                                }
                                
                                if (!has_raw_filter && !has_special_escape_filter) {
                                    value = html_escape(value);
                                }
                                
                                output += value;
                            }
                            i = j;
                        }
                    }
                }
            }
            else if (tok.type == TokenType::TagOpen) {
                size_t j = skip_whitespace(tokens, i + 1);
                
                if (j < tokens.size() && tokens[j].type == TokenType::Identifier) {
                    string keyword = tokens[j].value;
                    
                    if (keyword == "for") {
                        j = skip_whitespace(tokens, j + 1);
                        
                        if (j >= tokens.size() || tokens[j].type != TokenType::Identifier) {
                            i++;
                            continue;
                        }
                        string loop_var = tokens[j].value;
                        j = skip_whitespace(tokens, j + 1);
                        
                        if (j >= tokens.size() || tokens[j].type != TokenType::Identifier || tokens[j].value != "in") {
                            i++;
                            continue;
                        }
                        j = skip_whitespace(tokens, j + 1);
                        
                        if (j >= tokens.size() || tokens[j].type != TokenType::Identifier) {
                            i++;
                            continue;
                        }
                        string list_name = tokens[j].value;
                        j = skip_whitespace(tokens, j + 1);
                        
                        if (j >= tokens.size() || tokens[j].type != TokenType::TagClose) {
                            i++;
                            continue;
                        }
                        j++;
                        
                        vector<Token> loop_body;
                        int nested = 0;
                        
                        while (j < tokens.size()) {
                            if (tokens[j].type == TokenType::TagOpen) {
                                size_t peek = skip_whitespace(tokens, j + 1);
                                if (peek < tokens.size() && tokens[peek].type == TokenType::Identifier) {
                                    if (tokens[peek].value == "for") {
                                        nested++;
                                    } else if (tokens[peek].value == "endfor") {
                                        if (nested == 0) break;
                                        nested--;
                                    }
                                }
                            }
                            loop_body.push_back(tokens[j]);
                            j++;
                        }
                        
                        auto list_it = lists.find(list_name);
                        if (list_it != lists.end()) {
                            size_t index = 0;
                            for (const auto& val : list_it->second) {
                                auto loop_vars = vars;
                                loop_vars[loop_var] = val;
                                
                                // Add loop variables
                                loop_vars["loop_index"] = to_string(index + 1);
                                loop_vars["loop_index0"] = to_string(index);
                                loop_vars["loop_first"] = (index == 0) ? "true" : "false";
                                loop_vars["loop_last"] = (index == list_it->second.size() - 1) ? "true" : "false";
                                loop_vars["loop_length"] = to_string(list_it->second.size());
                                loop_vars["loop_even"] = ((index + 1) % 2 == 0) ? "true" : "false";
                                loop_vars["loop_odd"] = ((index + 1) % 2 == 1) ? "true" : "false";
                                
                                output += render_internal(loop_body, loop_vars, lists);
                                index++;
                            }
                        }
                        
                        if (j < tokens.size() && tokens[j].type == TokenType::TagOpen) {
                            j = skip_whitespace(tokens, j + 1);
                            if (j < tokens.size() && tokens[j].type == TokenType::Identifier) {
                                j = skip_whitespace(tokens, j + 1);
                                if (j < tokens.size() && tokens[j].type == TokenType::TagClose) {
                                    i = j;
                                }
                            }
                        }
                    }
                    else if (keyword == "if") {
                        j = skip_whitespace(tokens, j + 1);
                        
                        vector<tuple<string, TokenType, string, string, TokenType, string>> conditions;
                        
                        while (true) {
                            bool is_not = false;
                            if (j < tokens.size() && tokens[j].type == TokenType::Identifier && tokens[j].value == "not") {
                                is_not = true;
                                j = skip_whitespace(tokens, j + 1);
                            }
                            
                            if (j >= tokens.size() || 
                                (tokens[j].type != TokenType::Identifier && 
                                 tokens[j].type != TokenType::Boolean &&
                                 tokens[j].type != TokenType::String &&
                                 tokens[j].type != TokenType::Number)) {
                                break;
                            }
                            
                            string left_operand = tokens[j].value;
                            TokenType left_type = tokens[j].type;
                            j = skip_whitespace(tokens, j + 1);

                            // **NEW: Handle filters in if conditions**
                            string filter_value = left_operand;
                            TokenType filter_type = left_type;
                            
                            // Check for filters after the left operand
                            if (j < tokens.size() && tokens[j].type == TokenType::Pipe) {
                                j = skip_whitespace(tokens, j + 1);
                                if (j < tokens.size() && tokens[j].type == TokenType::Identifier) {
                                    string filter_name = tokens[j].value;
                                    j = skip_whitespace(tokens, j + 1);
                                    
                                    // Collect filter arguments
                                    vector<string> filter_args;
                                    while (j < tokens.size() && 
                                           (tokens[j].type == TokenType::String || 
                                            tokens[j].type == TokenType::Number ||
                                            tokens[j].type == TokenType::Identifier ||
                                            tokens[j].type == TokenType::Boolean)) {
                                        filter_args.push_back(tokens[j].value);
                                        j = skip_whitespace(tokens, j + 1);
                                    }
                                    
                                    // Apply the filter to get the actual value for comparison
                                    string original_value = resolve_value(left_operand, left_type, vars, lists);
                                    filter_value = apply_filter(original_value, filter_name, filter_args);
                                    filter_type = TokenType::String; // Filter results are always strings
                                    
                                    //cout << "DEBUG: Applied filter " << filter_name << " to '" << left_operand << "' -> '" << filter_value << "'" << endl;
                                }
                            }

                            string op = "";
                            string right_operand = "";
                            TokenType right_type = TokenType::Text;
                            
                            if (j < tokens.size() && tokens[j].type == TokenType::Operator) {
                                op = tokens[j].value;
                                j = skip_whitespace(tokens, j + 1);
                                
                                if (j < tokens.size() && 
                                    (tokens[j].type == TokenType::Identifier || 
                                     tokens[j].type == TokenType::Number ||
                                     tokens[j].type == TokenType::String ||
                                     tokens[j].type == TokenType::Boolean)) {
                                    right_operand = tokens[j].value;
                                    right_type = tokens[j].type;
                                    j = skip_whitespace(tokens, j + 1);
                                }
                            }
                            
                            string logic_op = is_not ? "not" : "";
                            
                            if (j < tokens.size() && tokens[j].type == TokenType::Identifier && 
                                (tokens[j].value == "and" || tokens[j].value == "or")) {
                                logic_op = logic_op.empty() ? tokens[j].value : (logic_op + "_" + tokens[j].value);
                                j = skip_whitespace(tokens, j + 1);
                            }
                            
                            // Use the filtered value in the condition
                            conditions.push_back({filter_value, filter_type, op, right_operand, right_type, logic_op});
                            
                            if (j < tokens.size() && tokens[j].type == TokenType::TagClose) {
                                break;
                            }
                        }
                        
                        if (j >= tokens.size() || tokens[j].type != TokenType::TagClose) {
                            i++;
                            continue;
                        }
                        j++;
                        
                        vector<pair<vector<tuple<string, TokenType, string, string, TokenType, string>>, vector<Token>>> branches;
                        vector<Token> current_body;
                        int nested = 0;
                        
                        branches.push_back({conditions, {}});
                        
                        while (j < tokens.size()) {
                            if (tokens[j].type == TokenType::TagOpen) {
                                size_t peek = skip_whitespace(tokens, j + 1);
                                if (peek < tokens.size() && tokens[peek].type == TokenType::Identifier) {
                                    string tag = tokens[peek].value;
                                    
                                    if (tag == "if") {
                                        nested++;
                                    } else if ((tag == "elsif" || tag == "elseif" || tag == "else") && nested == 0) {
                                        branches.back().second = current_body;
                                        current_body.clear();
                                        
                                        if (tag == "else") {
                                            j = peek;
                                            j = skip_whitespace(tokens, j + 1);
                                            if (j < tokens.size() && tokens[j].type == TokenType::TagClose) {
                                                j++;
                                            }
                                            branches.push_back({{}, {}});
                                            continue;
                                        }
                                    } else if (tag == "endif") {
                                        if (nested == 0) break;
                                        nested--;
                                    }
                                }
                            }
                            
                            current_body.push_back(tokens[j]);
                            j++;
                        }
                        
                        if (!current_body.empty()) {
                            branches.back().second = current_body;
                        }
                        
                        for (const auto& [branch_conditions, body] : branches) {
                            if (branch_conditions.empty()) {
                                output += render_internal(body, vars, lists);
                                break;
                            }
                            
                            bool result = true;
                            string last_logic = "";
                            
                            for (const auto& [left_op, left_t, op, right_op, right_t, logic] : branch_conditions) {
                                bool cond = evaluate_condition(left_op, left_t, op, right_op, right_t, vars, lists);
                                
                                if (logic.find("not") != string::npos) {
                                    cond = !cond;
                                }
                                
                                if (last_logic == "and") {
                                    result = result && cond;
                                } else if (last_logic == "or") {
                                    result = result || cond;
                                } else {
                                    result = cond;
                                }
                                
                                if (logic.find("and") != string::npos) {
                                    last_logic = "and";
                                } else if (logic.find("or") != string::npos) {
                                    last_logic = "or";
                                } else {
                                    last_logic = "";
                                }
                            }
                            
                            if (result) {
                                output += render_internal(body, vars, lists);
                                break;
                            }
                        }
                        
                        if (j < tokens.size() && tokens[j].type == TokenType::TagOpen) {
                            j = skip_whitespace(tokens, j + 1);
                            if (j < tokens.size() && tokens[j].type == TokenType::Identifier) {
                                j = skip_whitespace(tokens, j + 1);
                                if (j < tokens.size() && tokens[j].type == TokenType::TagClose) {
                                    i = j;
                                }
                            }
                        }
                    }
                }
            }
            
            i++;
        }
        
        return output;
    }

public:
    unordered_map<string, string> vars;
    unordered_map<string, vector<string>> lists;

    // Base64 encode/decode implementations
    string base64_encode(const string& input) {
        static const string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        
        string result;
        int val = 0, valb = -8;
        
        for (unsigned char c : input) {
            val = (val << 8) + c;
            valb += 8;
            
            if (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        
        // Add padding if needed
        while (result.length() % 4 != 0) {
            result.push_back('=');
        }
        
        return result;
    }
    
    string base64_decode(const string& input) {
        static const string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
        
        string result;
        int val = 0, valb = -8;
        
        for (unsigned char c : input) {
            if (c == '=') break;
            if (base64_chars.find(c) == string::npos) continue;
            
            val = (val << 6) + base64_chars.find(c);
            valb += 6;
            
            if (valb >= 0) {
                result.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return result;
    }
    
    Template(const string& html, const string& id = "default") : template_id(id) {
        log("Creating template...");
        tokens = tokenize(html);
    }
    
    // Load template from file
    static Template fromFile(const string& filepath, const string& id = "") {
        ifstream file(filepath);
        if (!file.is_open()) {
            throw runtime_error("Could not open file: " + filepath);
        }
        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        string template_id = id.empty() ? filepath : id;
        return Template(content, template_id);
    }

    // Load template from string
    static Template fromString(const string& content, const string& id = "string") {
        return Template(content, id);
    }
    
    // Register custom filter
    void addFilter(const string& name, function<string(const vector<string>&)> filter_func) {
        custom_filters[name] = filter_func;
        log("Registered custom filter: " + name);
    }
    
    // Set a variable (chainable)
    Template& set(const string& key, const string& value) {
        vars[key] = value;
        return *this;
    }
    
    // Set a list (chainable)
    Template& setList(const string& key, const vector<string>& items) {
        lists[key] = items;
        return *this;
    }
    
    // Set a dictionary (chainable)
    Template& setDict(const string& name, const Dict& dict) {
        dictionaries[name] = dict;
        return *this;
    }

    
    // Clear all variables and lists
    void clear() {
        vars.clear();
        lists.clear();
        dictionaries.clear();
    }
    
    string render() {
        auto start = high_resolution_clock::now();
        log("Rendering with " + to_string(vars.size()) + " vars, " + to_string(lists.size()) + " lists, " + to_string(dictionaries.size()) + " dicts");
        
        string result = render_internal(tokens, vars, lists);
        
        auto end = high_resolution_clock::now();
        log("Rendered in " + to_string(duration_cast<microseconds>(end - start).count()) + "μs");
        
        return result;
    }
    
    // Render to file
    void renderToFile(const string& filepath) {
        string content = render();
        ofstream file(filepath);
        if (!file.is_open()) {
            throw runtime_error("Could not write to file: " + filepath);
        }
        file << content;
        log("Rendered to file: " + filepath);
    }
};
