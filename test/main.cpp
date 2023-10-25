#include "main.h"

int main()
{
    int failedTests = 0;
    failedTests = RunArgumentParserTests();
    failedTests += RunQueryCreateTests();
    return 0;
}