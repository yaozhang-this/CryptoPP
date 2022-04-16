#include <iostream>
#include <string>
#include <fstream>
#include "cryptopp/hex.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha.h"
#include "unistd.h"
#include <chrono>
#include <ctime>
int main (int argc, char* argv[])
{
    using namespace std;
    using namespace CryptoPP;
    string cur;
    cout << "Enter your username:";
    cin >> cur;
    string curpsw;
    cout << "Enter your password:";
    cin >> curpsw;
    HexEncoder encoder(new FileSink(cout));
    SHA256 hash;
    byte digest[SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, (byte*) curpsw.c_str(), curpsw.length());
    ifstream infile("user0020083.cfg");
    string usr;
    string psw;
    bool success = false;
    while (infile >> usr >> psw)
    {
        if (usr == cur){
            string hex;
            HexEncoder newEncoder;
            newEncoder.Attach(new StringSink(hex));
            newEncoder.Put(digest, sizeof(digest));
            newEncoder.MessageEnd();
            if (psw == hex)
            {
                success = true;
                break;
            }
            else{
                return 0;
            }
        }
    }
    if (!success){
          cout << "wrong password or username" << endl;
          return 0;
    }
    ifstream secretfile("user0020083.txt");
    if (secretfile.is_open()){
         cout << secretfile.rdbuf();
    }
    //record the file access to log
    ofstream log;
    log.open("user0020083.log");
    time_t tm = time(NULL);
    log << "Accessed by " << cur << " at " << asctime(localtime(&tm));
    log.close();

    return 0; 
}
