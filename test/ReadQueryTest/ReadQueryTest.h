#pragma once
#include "../../dns.h"
#include "../QueryCreateTest/QueryCreateTest.h"
#include <vector>

bool operator==(std::vector<answer_struct>& exp, std::vector<answer_struct>& act);
bool operator==(std::vector<authority_struct>& exp, std::vector<authority_struct>& act);
bool ReadResponseTest();
bool ReadAuthAdditTest();
bool ReverseResponseTest();
bool MalformedResponseTest();
bool MalformedResponse2Test();
bool MalformedResponse3Test();
bool MalformedResponse4Test();
bool TruncatedResponse();
bool LongPointer();
int RunReadQueryTests();
bool operator==(response_struct& exp, response_struct& act);