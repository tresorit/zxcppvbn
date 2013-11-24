#ifndef FREQUENCY_LISTS_HPP
#define FREQUENCY_LISTS_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <map>
#include <vector>

namespace zxcppvbn
{

class frequency_lists
{
private:
	static const uint8_t data[];
	std::map<std::string, std::vector<std::string>> lists;

	frequency_lists();
	frequency_lists(const frequency_lists& fl) /* = delete */;
	frequency_lists& operator=(const frequency_lists& fl) /* = delete */;
public:
	static std::shared_ptr<frequency_lists> load();

	const std::vector<std::string>& get(const std::string& dictionary) const;
};

}

#endif
