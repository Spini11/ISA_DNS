#pragma once
#include "../../arguments.h"

bool operator==(arguments_struct& exp, arguments_struct& act);
bool StandardRequestTest();
bool IPv6RequestTest();
bool MalformedDnsTest();
bool MissingDomainTest();
bool NoArgumentTest();
bool ReverseIPv6Test();