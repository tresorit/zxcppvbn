#ifndef ADJACENCY_GRAPHS_HPP
#define ADJACENCY_GRAPHS_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <map>
#include <vector>

namespace zxcppvbn
{

class adjacency_graphs
{
private:
	static const uint8_t data[];
	std::map<std::string, std::map<char, std::vector<std::string>>> graphs;

	adjacency_graphs();
	adjacency_graphs(const adjacency_graphs& fl) /* = delete */;
	adjacency_graphs& operator=(const adjacency_graphs& fl) /* = delete */;
public:
	static std::shared_ptr<adjacency_graphs> load();

};

}

#endif
