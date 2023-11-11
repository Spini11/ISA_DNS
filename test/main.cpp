#include "main.h"

int main()
{
    int failedTests = 0;
    failedTests = RunArgumentParserTests();
    failedTests += RunQueryCreateTests();
    failedTests += RunReadQueryTests();
    failedTests += RunCompleteTests();

    int ArgumentParserTests = 6;
    int QueryCreateTests = 3;
    int ReadQueryTests = 9;
    int CompleteTests = 1;
    
    int totalTests = ArgumentParserTests + QueryCreateTests + ReadQueryTests + CompleteTests;
    std::cout << std::endl << "Total tests: " << totalTests << std::endl;
    std::cout << "Failed tests: " << failedTests << std::endl;
    std::cout << "Passed tests: " << totalTests - failedTests << std::endl;
    return 0;
}