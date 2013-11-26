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
		SPATIAL,
		REPEAT,
		SEQUENCE
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

		// REPEAT
		char repeated_char;

		// SEQUENCE
		std::string sequence_name;
		size_t sequence_space;
		bool ascending;
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
	std::map<std::string /* keyboard name */, std::map<char /* key */, std::vector<std::string /* keys */> /* neigbors */>> graphs;
	std::map<char /* original */, std::vector<char /* l33t */>> l33t_table;
	std::map<std::string /* sequence name */, std::string /* sequence chars */> sequences;
	std::vector<std::tuple<char /* min */, char /* max */, size_t /* cardinality */>> char_classes_cardinality;

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
	void build_sequences();
	void build_cardinalities();
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
	std::vector<match_result> spatial_match_helper(const std::string& password, const std::string& graph_name, const std::map<char, std::vector<std::string>>& graph);
	std::vector<match_result> spatial_match(const std::string& password);
	// Repeats and sequences matching
	std::vector<match_result> repeat_match(const std::string& password);
	std::vector<match_result> sequence_match(const std::string& password);

	// Scoring functions (scoring.cpp)

	// Utility functions
	uint64_t nCk(uint64_t n, uint64_t k);
	double lg(double n);
	size_t calc_bruteforce_cardinality(const std::string& password);
	std::string calc_display_time(uint64_t seconds);

public:
	zxcppvbn();

	result operator()(const std::string& password, const std::vector<std::string>& user_inputs = std::vector<std::string>());
};

#endif