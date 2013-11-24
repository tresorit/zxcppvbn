#ifndef ZXCPPVBN_HPP
#define ZXCPPVBN_HPP

#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <map>
#include <vector>
#include <chrono>

class zxcppvbn
{
public:
	enum class match_pattern
	{
		DICTIONARY
	};

	struct match_result
	{
		match_pattern pattern;
		size_t i;
		size_t j;
		std::string token;
	};

	struct dictionary_match_result : match_result
	{
		std::string dictionary_name;
		std::string matched_word;
		int rank;
	};

	struct result
	{
		std::chrono::seconds crack_time;
		std::string crack_time_display;
		int score;
		std::vector<std::unique_ptr<match_result>> matches;
		std::chrono::milliseconds calc_time;
	};

private:
	static const uint8_t frequency_lists[];
	static const size_t frequency_lists_size;
	static const uint8_t adjacency_graphs[];
	static const size_t adjacency_graphs_size;

	typedef std::function<std::vector<std::unique_ptr<match_result>>(const std::string&)> matcher_func;

	std::map<std::string, std::map<std::string, int>> ranked_dictionaries;
	std::map<std::string, std::map<char, std::vector<std::string>>> graphs;

	std::vector<matcher_func> dictionary_matchers;
	std::vector<matcher_func> matchers;

	size_t calc_decompressed_size(const uint8_t* comp_data, size_t comp_size);
	bool build_ranked_dicts();
	bool build_graphs();
	void build_dict_matchers();
	void build_matchers();

	std::string to_lower(const std::string& password);

	std::vector<std::unique_ptr<match_result>> omnimatch(const std::string& password);
	std::vector<std::unique_ptr<match_result>> dictionary_match(const std::string& password, const std::string& dictionary);

	zxcppvbn(const zxcppvbn&) /* = delete */;
	zxcppvbn& operator=(const zxcppvbn&) /* = delete */;
public:
	zxcppvbn();

	std::unique_ptr<result> operator()(const std::string& password, const std::vector<std::string>& user_inputs = std::vector<std::string>());
};

#endif