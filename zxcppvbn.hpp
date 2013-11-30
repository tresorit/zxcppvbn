#ifndef ZXCPPVBN_HPP
#define ZXCPPVBN_HPP

#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <regex>

// Password estimation, implemented entirely in one class
class zxcppvbn
{
public:
	// Type of a specific submatch
	enum class pattern : uint8_t
	{
		DICTIONARY,
		L33T,
		SPATIAL,
		REPEAT,
		SEQUENCE,
		DIGITS,
		YEAR,
		DATE,
		BRUTEFORCE
	};

	// Submatch
	struct match {
		pattern pattern;
		size_t i;
		size_t j;
		std::string token;
		double entropy;

		// DICTIONARY + L33T
		std::string dictionary_name;
		std::string matched_word;
		int rank;
		double base_entropy;
		double uppercase_entropy;

		// L33T
		std::map<char, char> sub;
		std::string sub_display;
		double l33t_entropy;

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

		// DATE
		uint16_t year;
		uint16_t month;
		uint16_t day;
		std::string separator;

		// BRUTEFORCE
		size_t cardinality;

		match(zxcppvbn::pattern p);
	};

	// Password estimation result
	struct result {
		std::string password;
		double entropy;
		std::chrono::seconds crack_time;
		std::string crack_time_display;
		int score;
		std::vector<std::unique_ptr<match>> matches;
		std::chrono::milliseconds calc_time;

		result();
		result(const result& o);
		result(result&& o);
		result& operator=(const result& o);
		result& operator=(result && o);
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
	std::map<uint8_t /* keyboard type */, std::tuple<std::vector<std::string> /* keyboard names */, double /* average degree */, double /* starting positions */>> graph_stats;
	std::map<char /* original */, std::vector<char /* l33t */>> l33t_table;
	std::map<std::string /* sequence name */, std::string /* sequence chars */> sequences;
	std::vector<std::tuple<char /* min */, char /* max */, size_t /* cardinality */>> char_classes_cardinality;

	// Function prototypes
	typedef std::function<std::vector<std::unique_ptr<match>>(const std::string&)> matcher_func;
	typedef std::function<double(match&)> entropy_func;

	// Function maps
	std::vector<matcher_func> dictionary_matchers;
	std::vector<matcher_func> matchers;
	std::map<pattern, entropy_func> entropy_functions;

	// Initializer functions (init.cpp)

	// Database loading
	size_t calc_decompressed_size(const uint8_t* comp_data, size_t comp_size) const;
	bool build_ranked_dicts();
	bool build_graphs();
	void build_graph_stats();
	void build_l33t_table();
	void build_sequences();
	void build_cardinalities();
	// Function map creation
	void build_dict_matchers();
	void build_matchers();
	void build_entropy_functions();

	// Matching functions (matching.cpp)

	// Utility functions
	std::string to_lower(const std::string& password) const;
	std::string translate(const std::string& password, const std::map<char, char>& chr_map) const;
	std::string substr(const std::string& password, size_t i, size_t j) const;
	// Complex matching
	std::vector<std::unique_ptr<match>> omnimatch(const std::string& password) const;
	// Dictionary matching
	std::vector<std::unique_ptr<match>> dictionary_match(const std::string& password, const std::string& dictionary) const;
	// L33t matching
	std::map<char, std::vector<char>> relevent_l33t_subtable(const std::string& password) const;
	std::vector<std::map<char, char>> enumerate_l33t_subs(const std::map<char, std::vector<char>>& table) const;
	std::vector<std::unique_ptr<match>> l33t_match(const std::string& password) const;
	// Spatial matching
	std::vector<std::unique_ptr<match>> spatial_match_helper(const std::string& password, const std::string& graph_name, const std::map<char, std::vector<std::string>>& graph) const;
	std::vector<std::unique_ptr<match>> spatial_match(const std::string& password) const;
	// Repeats and sequences matching
	std::vector<std::unique_ptr<match>> repeat_match(const std::string& password) const;
	std::vector<std::unique_ptr<match>> sequence_match(const std::string& password) const;
	// Digits, years and dates matching
	std::vector<std::pair<size_t, size_t>> findall(const std::string& password, const std::regex& rx) const;
	std::vector<std::tuple<size_t, size_t, std::vector<std::string>>> splitall(const std::string& password, const std::regex& rx, const std::regex& subrx) const;
	static const std::regex digits_rx;
	std::vector<std::unique_ptr<match>> digits_match(const std::string& password) const;
	static const std::regex year_rx;
	std::vector<std::unique_ptr<match>> year_match(const std::string& password) const;
	std::vector<std::unique_ptr<match>> date_match(const std::string& password) const;
	static const std::regex date_rx_without_sep;
	std::vector<std::unique_ptr<match>> date_without_sep_match(const std::string& password) const;
	static const std::regex date_rx_year_suffix;
	static const std::regex date_rx_year_prefix;
	static const std::regex date_rx_split;
	std::vector<std::unique_ptr<match>> date_sep_match(const std::string& password) const;

	// Scoring functions (scoring.cpp)

	// Utility functions
	uint64_t nCk(uint64_t n, uint64_t k) const;
	size_t calc_bruteforce_cardinality(const std::string& password) const;
	// Complex scoring
	result minimum_entropy_match_sequence(const std::string& password, std::vector<std::unique_ptr<match>>& matches) const;
	// Crack time constants and functions
	static const double single_guess;
	static const double num_attackers;
	uint64_t entropy_to_crack_time(double entropy) const;
	int crack_time_to_score(uint64_t seconds) const;
	std::string calc_display_time(uint64_t seconds) const;
	// Entropy calculation constants and functions
	double calc_entropy(match& match) const;
	// Dictionary entropy
	double dictionary_entropy(match& match) const;
	double extra_uppercase_entropy(const match& match) const;
	// L33t entropy
	double l33t_entropy(match& match) const;
	double extra_l33t_entropy(const match& match) const;
	// Spatial entropy
	double spatial_entropy(const match& match) const;
	// Repeats and sequences entropy
	double repeat_entropy(const match& match) const;
	double sequence_entropy(const match& match) const;
	// Digits, years and dates entropy
	double digits_entropy(const match& match) const;
	static const uint16_t min_year;
	static const uint16_t max_year;
	static const uint16_t min_month;
	static const uint16_t max_month;
	static const uint16_t min_day;
	static const uint16_t max_day;
	double year_entropy(const match& match) const;
	double date_entropy(const match& match) const;
	bool check_date(uint16_t year, uint16_t& month, uint16_t& day) const;

public:
	zxcppvbn();

	result operator()(const std::string& password, const std::vector<std::string>& user_inputs = std::vector<std::string>());
};

#endif