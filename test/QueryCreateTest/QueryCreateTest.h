#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "../../dns.h"

bool QueryCreateTest();
bool QueryIPv6Test();
bool ReverseIPv6QueryTest();
int RunQueryCreateTests();
std::vector<uint8_t> queryConvertor(std::string query);