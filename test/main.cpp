#include "../frequency_lists.hpp"

using namespace zxcppvbn;

int main()
{
	std::shared_ptr<frequency_lists> fl = frequency_lists::load();
	return 0;
}