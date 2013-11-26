#ifndef ZXCPPVBN_HPP
#define ZXCPPVBN_HPP

#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <map>
#include <vector>
#include <chrono>

// Password estimation, implemented entirely in one class
class zxcppvbn
{
public:
	// Type of a specific submatch
	enum class match_pattern
	{
		DICTIONARY,
		L33T,
		SPATIAL
	};

	// Submatch
	struct match_result {
		match_pattern pattern;
		size_t i;
		size_t j;
		std::string token;

		// DICTIONARY + L33T
		std::string dictionary_name;
		std::string matched_word;
		int rank;

		// L33T
		std::map<char, char> sub;
		std::string sub_display;

		// SPATIAL
		std::string graph;
		size_t turns;
		size_t shifted_count;
	};

	// Password estimation result
	struct result {
		std::chrono::seconds crack_time;
		std::string crack_time_display;
		int score;
		std::vector<match_result> matches;
		std::chrono::milliseconds calc_time;
	};

private:
	// Compressed databases (frequency_lists.cpp, adjacency_graphs.cpp)
	static const uint8_t frequency_lists[];
	static const size_t frequency_lists_size;
	static const uint8_t adjacency_graphs[];
	static const size_t adjacency_graphs_size;

	// Databases
	std::map<std::string /* dictionary name */, std::map<std::string /* word */, int /* rank */>> ranked_dictionaries;
	std::map<std::string /* keyboard name */, std::map<char /* key */, std::vector<std::vector<char /* key */>> /* neigbors */>> graphs;
	std::map<char /* original */, std::vector<char /* l33t */>> l33t_table;

	// Matcher function prototype
	typedef std::function<std::vector<match_result>(const std::string&)> matcher_func;

	// Matcher functions
	std::vector<matcher_func> dictionary_matchers;
	std::vector<matcher_func> matchers;

	// Initializer functions (init.cpp)

	// Database loading
	size_t calc_decompressed_size(const uint8_t* comp_data, size_t comp_size);
	bool build_ranked_dicts();
	bool build_graphs();
	void build_l33t_table();
	// Matcher creation
	void build_dict_matchers();
	void build_matchers();

	// Matching functions (matching.cpp)

	// Utility functions
	std::string to_lower(const std::string& password);
	std::string translate(const std::string& password, const std::map<char, char>& chr_map);
	std::string substr(const std::string& password, size_t i, size_t j);
	// Complex matching
	std::vector<match_result> omnimatch(const std::string& password);
	// Dictionary matching
	std::vector<match_result> dictionary_match(const std::string& password, const std::string& dictionary);
	// L33t matching
	std::map<char, std::vector<char>> relevent_l33t_subtable(const std::string& password);
	std::vector<std::map<char, char>> enumerate_l33t_subs(const std::map<char, std::vector<char>>& table);
	std::vector<match_result> l33t_match(const std::string& password);
	// Spatial matching
	std::vector<match_result> spatial_match_helper(const std::string& password, const std::string& graph_name, const std::map<char, std::vector<std::vector<char>>>& graph);
	std::vector<match_result> spatial_match(const std::string& password);

public:
	zxcppvbn();

	result operator()(const std::string& password, const std::vector<std::string>& user_inputs = std::vector<std::string>());
};

#endif