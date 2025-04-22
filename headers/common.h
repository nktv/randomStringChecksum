#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <iterator>
#include <iomanip>
#include <thread>
#include <atomic>
#include <random>

using namespace std;


#define INFO_LOG(msg)  std::cout<<"INFO: "<< msg << endl;
#define ERROR_LOG(msg) std::cout<<"ERROR: "<< msg << endl;

#define RANDOM_STRING_LENGTH 10