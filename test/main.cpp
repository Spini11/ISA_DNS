#include "main.h"

int main()
{
    int failedTests = 0;
    failedTests = RunArgumentParserTests();
    failedTests += RunQueryCreateTests();
    failedTests += RunReadQueryTests();
    return 0;
}