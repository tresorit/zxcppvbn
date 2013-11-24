#include "../frequency_lists.hpp"
#include "../adjacency_graphs.hpp"

using namespace zxcppvbn;

int main()
{
	std::shared_ptr<frequency_lists> fl = frequency_lists::load();
	std::shared_ptr<adjacency_graphs> ag = adjacency_graphs::load();
	return 0;
}