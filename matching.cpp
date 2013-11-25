#include "zxcppvbn.hpp"

#include <algorithm>
#include <cctype>
#include <set>

std::string zxcppvbn::to_lower(const std::string& password)
{
	std::string data = password; 
	std::transform(data.begin(), data.end(), data.begin(), ::tolower);
	return data;
}

std::vector<std::unique_ptr<zxcppvbn::match_result>> zxcppvbn::omnimatch(const std::string& password)
{
	std::vector<std::unique_ptr<match_result>> results;
	for(auto& matcher : matchers) {
		std::vector<std::unique_ptr<match_result>> matches = matcher(password);
		for(auto& match : matches) {
			results.push_back(std::move(match));
		}
	}
	std::sort(results.begin(), results.end(), [](const std::unique_ptr<match_result>& match1, const std::unique_ptr<match_result>& match2) {
		return (match1->i < match2->i) || ((match1->i == match2->i) && (match1->j < match2->j));
	});
	return results;
}

std::vector<std::unique_ptr<zxcppvbn::match_result>> zxcppvbn::dictionary_match(const std::string& password, const std::string& dictionary)
{
	const std::map<std::string, int>& ranked_dict = ranked_dictionaries.at(dictionary);
	std::vector<std::unique_ptr<match_result>> results;
	size_t len = password.length();
	std::string password_lower = to_lower(password);
	for(size_t i = 0; i < len; i++) {
		for(size_t j = i; j < len; j++) {
			std::string password_part = password_lower.substr(i, j - i + 1);
			auto it = ranked_dict.find(password_part);
			if(it != ranked_dict.end()) {
				std::unique_ptr<dictionary_match_result> result(new dictionary_match_result());
				result->pattern = match_pattern::DICTIONARY;
				result->i = i;
				result->j = j;
				result->token = password_part;
				result->dictionary_name = dictionary;
				result->matched_word = it->first;
				result->rank = it->second;
				results.push_back(std::move(result));
			}
		}
	}
	return results;
}

std::map<char, std::vector<char>> zxcppvbn::relevent_l33t_subtable(const std::string& password)
{
	std::map<char, std::vector<char>> filtered;
	for(auto& l : l33t_table) {
		std::vector<char> relevent_subs;
		for(auto& sub : l.second) {
			if(password.find(sub) != std::string::npos) {
				relevent_subs.push_back(sub);
			}
		}
		if(!relevent_subs.empty()) {
			filtered.insert(std::make_pair(l.first, relevent_subs));
		}
	}
	return filtered;
}

void zxcppvbn::enumerate_l33t_subs(std::map<char, std::vector<char>>& table)
{
}

std::vector<std::unique_ptr<zxcppvbn::match_result>> zxcppvbn::l33t_match(const std::string& password)
{
	std::vector<std::unique_ptr<zxcppvbn::match_result>> matches;
	return matches;
}
