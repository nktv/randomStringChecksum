#include "headers/ServerConnection.h"
#include "headers/sha1.h"
#include <cstdio>

static atomic<bool> isFound(false);
static char suffix[RANDOM_STRING_LENGTH + 1] = {0};
static atomic<long long> hashCount(0);
static int authDataLen(0);
inline static const char allowed[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

void getRandomString(char* utf8string) {
    thread_local mt19937 gen(std::random_device{}());
    thread_local uniform_int_distribution<> dis(0, sizeof(allowed) - 2); // for null

    for (size_t i = 0; i < RANDOM_STRING_LENGTH; ++i) {
        utf8string[i] = allowed[dis(gen)];
    }

    utf8string[RANDOM_STRING_LENGTH] = '\0';
}

void sha1_hex(const char* input, size_t len, char* outputHex) {
    unsigned char hash[20];
    Custom_SHA1_CTX ctx;
    Custom_SHA1_Init(&ctx);
    Custom_SHA1_Update(&ctx, (unsigned char*)input, len);
    Custom_SHA1_Final(hash, &ctx);

    static const char hexDigits[] = "0123456789abcdef";
    for (int i = 0; i < 20; ++i) {
        outputHex[i * 2]     = hexDigits[(hash[i] >> 4) & 0xF];
        outputHex[i * 2 + 1] = hexDigits[hash[i] & 0xF];
    }
    outputHex[40] = '\0';
}

    
static void powFunc(const char* authData, int difficulty) {
    char prefix[difficulty + 1]; // +1 for null terminator
    memset(prefix, '0', difficulty);
    prefix[difficulty] = '\0';
    char combined[authDataLen + RANDOM_STRING_LENGTH + 1] = {0};

    //INFO_LOG("Thread started with authData: " << authData << " and difficulty: " << difficulty);
    while(!isFound.load()) {
        thread_local char randomString[RANDOM_STRING_LENGTH + 1] = {0};
        getRandomString(randomString);
        

        thread_local char hashHex[SHA_DIGEST_LENGTH * 2 + 1]; // SHA_DIGEST_LENGTH is 20 bytes, so hex string will be 40 chars + null terminator

        
        memcpy(combined, authData, authDataLen);
        memcpy(combined + authDataLen, randomString, RANDOM_STRING_LENGTH);
        sha1_hex(combined, authDataLen + RANDOM_STRING_LENGTH, hashHex);

        if (++hashCount % 100000000 == 0) {
            std::cout << "Processed " << hashCount << " hashes..." << " hash: " << hashHex << endl;
        }

        //if(hashStr.substr(0, difficulty) == prefix) {
        if (memcmp(hashHex, prefix, difficulty) == 0) {
            if(isFound.load()) {
                return;
            }

            isFound.store(true);
            strncpy(suffix, randomString, RANDOM_STRING_LENGTH + 1); // copy safely
            INFO_LOG("Got Result Thread: " << std::this_thread::get_id() << " Random String: " << randomString << " Hash: " << hashHex << " Total Hash Count " << hashCount);
            break;
        }
    }

   // INFO_LOG("Thread finished: " << std::this_thread::get_id() << " with authData: " << authData << " and difficulty: " << difficulty);
    return;
}

string proofOfWork(const char* authData, int difficulty) {


    int threadCount = std::max(5, static_cast<int>(std::thread::hardware_concurrency()));
    //INFO_LOG("Thread count: " << threadCount);

    std::vector<std::thread> threads(threadCount);
    //INFO_LOG("Starting threads...");


    for(int i = 0; i< threadCount; i++) {
        threads[i] = std::thread(powFunc, authData, difficulty);
    }

    //INFO_LOG("Waiting for threads to finish...");
    for(int i = 0; i< threadCount; i++) {
        if(threads[i].joinable()) {
            threads[i].join();
        }
    }

    //INFO_LOG("Threads finished. Suffix: " << suffix);
    return suffix;
}

int main(int argc, char* argv[]) {

    /*auto start = std::chrono::high_resolution_clock::now();
    proofOfWork("JIyjjsQkrOlEVpmqyfvlDUFkuOlSYQBNtMYqVXzofKasRkQUPTfEOxMfsYmpgXhK", 9);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "Time taken: " << duration.count() << " seconds \n";
    return 0;*/

    if(argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <host> <port>" << std::endl;
        return 0;
    }
        
    ServerConnection connectionObj(argv[1], std::stoi(argv[2]), "/home/tamil-8170/Documents/exas/client.crt", "/home/tamil-8170/Documents/exas/client.key");
    if (!connectionObj.Connect()) {
        ERROR_LOG("Failed to connect to server");
        return 0;
    }

    char authData[100] = {0};
    char hashedData[41] = {0};

    // static int t = 0;
    // string readData = "POW authData 9";

    while(true) {

        
        // t++;
        // if(t == 1) {
        //     readData = "POW authData 9";
        // } else if(t == 2) {
        //     readData = "NAME authData";
        // } else if(t == 3) {
        //     readData = "MAILNUM authData";
        // } else if(t == 4) {
        //     readData = "MAIL1";
        // } else if(t == 5) {
        //     readData = "MAIL2";
        // } else if(t == 6) {
        //     readData = "SKYPE";
        // } else if(t == 7) {
        //     readData = "BIRTHDATE";
        // } else if(t == 8) {
        //     readData = "COUNTRY";
        // } else if(t == 9) {
        //     readData = "ADDRNUM";
        // } else if(t == 10) {
        //     readData = "ADDRLINE1";
        // } else if(t == 11) {
        //     readData = "ADDRLINE2";
        // }

        string readData = connectionObj.ReadLine();
        istringstream iss(readData);
        vector<string> splittenData = {istream_iterator<string>{iss}, istream_iterator<string>{}};

        if(splittenData.empty()) {
            ERROR_LOG("No data received. Exiting...");
            break;;
        }

        string command = splittenData[0];
        string arg1 = splittenData.size() > 1 ? splittenData[1] : "";

        char combined[authDataLen + arg1.length()] = {0};
        if(!command.empty() && (command != "HELO" && command != "ERROR" && command != "POW" && command != "END") && !arg1.empty()) {
            memcpy(combined, authData, authDataLen);
            memcpy(combined + authDataLen, splittenData[1].c_str(), splittenData[1].length());
            sha1_hex(combined, authDataLen + splittenData[1].length(), hashedData);
        }

        if(command == "HELO") {
            INFO_LOG("HELO command received");
            connectionObj.writeLine("EHLO\n");
        } else if (command == "ERROR") {
            INFO_LOG("ERROR command received");
            cerr << "ERROR: ";
            for (size_t i = 1; i < splittenData.size(); ++i) {
                cerr << splittenData[i] << " ";
            }
            cerr << endl;
            break;
        } else if (command == "POW") {
            snprintf(authData, sizeof(authData), "%s", splittenData[1].c_str());
            authDataLen = strlen(authData);
            int difficulty = stoi(splittenData[2]);

            INFO_LOG("POW command received with authData: " << authData << " difficulty: " << difficulty);  
            string resultStr = proofOfWork(authData, difficulty) + "\n";
            connectionObj.writeLine(resultStr);
        }
        else if (command == "END") {
            INFO_LOG("END command received");
            connectionObj.writeLine("OK\n");
            break;
        }
        else if (command == "NAME") {
            INFO_LOG("NAME command received");
            connectionObj.writeLine(string(hashedData) + " TAMIL SELVAN NAGARAJAN\n");
        }
        else if (command == "MAILNUM") {
            INFO_LOG("MAILNUM command received");
            connectionObj.writeLine(string(hashedData) + " 2\n");
        }
        else if (command == "MAIL1") {
            INFO_LOG("MAIL1 command received");
            connectionObj.writeLine(string(hashedData) + " selvanprofessional@gmail.com\n");
        }
        else if (command == "MAIL2") {
            INFO_LOG("MAIL2 command received");
            connectionObj.writeLine(string(hashedData) + " my.name2@example.com\n");
        }
        else if (command == "SKYPE") {
            INFO_LOG("SKYPE command received");
            connectionObj.writeLine(string(hashedData) + " my.name@example.com\n");
        }
        else if (command == "BIRTHDATE") {
            INFO_LOG("BIRTHDATE command received");
            connectionObj.writeLine(string(hashedData) + " 09.04.1995\n");
        }
        else if (command == "COUNTRY") {
            INFO_LOG("COUNTRY command received");
            connectionObj.writeLine(string(hashedData) + " India\n");
        }
        else if (command == "ADDRNUM") {
            INFO_LOG("ADDRNUM command received");
            connectionObj.writeLine(string(hashedData) + " 2\n");
        }
        else if (command == "ADDRLINE1") {
            INFO_LOG("ADDRLINE1 command received");
            connectionObj.writeLine(string(hashedData) + " Long street 3\n");
        }
        else if (command == "ADDRLINE2") {
            INFO_LOG("ADDRLINE2 command received");
            connectionObj.writeLine(string(hashedData) + " Chennai\n");
            break;
        }
    }

    connectionObj.DestroySSL();
    INFO_LOG("Connection closed");
}