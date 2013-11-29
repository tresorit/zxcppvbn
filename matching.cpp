#include "zxcppvbn.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>

//////////////////////////////////////////////////////////////////////////
// Utility functions
//////////////////////////////////////////////////////////////////////////

// Convert an ASCII string to lowercase
std::string zxcppvbn::to_lower(const std::string& password) const
{
	std::string data = password;
	std::transform(data.begin(), data.end(), data.begin(), ::tolower);
	return std::move(data);
}

// Replace characters in an ASCII string
std::string zxcppvbn::translate(const std::string& password, const std::map<char, char>& chr_map) const
{
	std::string data = password;
	std::transform(data.begin(), data.end(), data.begin(), [&chr_map](char chr) {
		auto it = chr_map.find(chr);
		if (it == chr_map.end()) {
			return chr;
		} else {
			return it->second;
		}
	});

	return std::move(data);
}

// Return substring from ith to jth character
std::string zxcppvbn::substr(const std::string& password, size_t i, size_t j) const
{
	return password.substr(i, j - i + 1);
}

//////////////////////////////////////////////////////////////////////////
/// Complex matching
//////////////////////////////////////////////////////////////////////////

// Combine match results
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::omnimatch(const std::string& password) const
{
	std::vector<std::unique_ptr<match>> results;
	// Invoke all matchers and collect results
	for (auto& matcher : matchers) {
		std::vector<std::unique_ptr<match>> matches = matcher(password);
		results.insert(results.end(), std::make_move_iterator(matches.begin()), std::make_move_iterator(matches.end()));
	}
	// Sort match results according to their position in the input
	std::sort(results.begin(), results.end(), [](const std::unique_ptr<match>& match1, const std::unique_ptr<match>& match2) {
		return (match1->i < match2->i) || ((match1->i == match2->i) && (match1->j < match2->j));
	});
	return std::move(results);
}

//////////////////////////////////////////////////////////////////////////
// Dictionary matching
//////////////////////////////////////////////////////////////////////////

// Find matches in known dictionary
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::dictionary_match(const std::string& password, const std::string& dictionary) const
{
	const std::map<std::string, int>& ranked_dict = ranked_dictionaries.at(dictionary);
	std::vector<std::unique_ptr<match>> results;
	size_t len = password.length();
	std::string password_lower = to_lower(password);
	// Try to match any substring of the password
	for (size_t i /* substring start index */ = 0; i < len; i++) {
		for (size_t j /* substring end index */ = i; j < len; j++) {
			// Find a matching word in the dictionary
			std::string password_part = substr(password_lower, i, j);
			auto it = ranked_dict.find(password_part);
			if (it != ranked_dict.end()) {
				// If found a matching word, add a match result
				std::unique_ptr<match> result(new match(pattern::DICTIONARY));
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
	return std::move(results);
}

//////////////////////////////////////////////////////////////////////////
// L33t matching
//////////////////////////////////////////////////////////////////////////

// Get a subtable of the l33t substitution table that contains only those substitutions that is in the password
std::map<char, std::vector<char>> zxcppvbn::relevent_l33t_subtable(const std::string& password) const
{
	std::map<char /* original */, std::vector<char /* l33t */>> filtered;
	// For every possible original character in the l33t table
	for (auto& l : l33t_table) {
		// For this original -> l33t* substitutions, find those l33t characters that appear in the password
		std::vector<char /* l33t */> relevent_subs;
		for (auto& sub : l.second) {
			if (password.find(sub) != std::string::npos) {
				relevent_subs.push_back(sub);
			}
		}
		// If there were at least one valid l33t character, then put this into the filtered results
		if (!relevent_subs.empty()) {
			filtered.insert(std::make_pair(l.first, relevent_subs));
		}
	}
	return std::move(filtered);
}

// Calculate all possible inverse l33t substitution maps
std::vector<std::map<char, char>> zxcppvbn::enumerate_l33t_subs(const std::map<char, std::vector<char>>& table) const
{
	// First, we create the inverse of the original -> l33t* table to get a l33t -> original* mapping
	std::map<char /* l33t */, std::vector<char /* original */>> inverse_map;
	for (const auto& l : table) {
		for (const auto& sub : l.second) {
			inverse_map[sub].push_back(l.first);
		}
	}
	// Convert table to an indexable form
	std::vector<std::pair<char /* l33t */, std::vector<char /* original */>>> inverse_table(inverse_map.begin(), inverse_map.end());

	std::vector<std::map<char /* l33t */, char /* original */>> sub_dicts;

	// The algorithm below does not work with empty table
	if (inverse_table.size() == 0) {
		return std::move(sub_dicts);
	}

	// Try to find all permutations where each l33t character has only one original substitution (l33t -> original)*
	std::vector<size_t /* index of original*/> choices(1, 0);       // Contain 1-based indexes in the inverse table -> which original character we choose out of the possible l33t->original* choices
	while (!choices.empty()) {
		size_t current = choices.size() - 1;

		// Select next choice at this level
		choices[current]++;

		// If there are no more choices at this level
		if (choices[current] > inverse_table[current].second.size()) {
			// Go back one level
			choices.pop_back();
			continue;
		}

		// If we have a complete permutation
		if (choices.size() == inverse_table.size()) {
			// Copy this mapping to the results
			std::map<char /* l33t */, char /* original */> permutation;
			for (size_t i = 0; i < inverse_table.size(); i++) {
				permutation[inverse_table[i].first] = inverse_table[i].second[choices[i] - 1];
			}
			sub_dicts.push_back(permutation);
		}

		// If there is more choices at this level
		if (choices[current] <= inverse_table[current].second.size()) {
			// If possible, go to the next level, before continuing this level
			if (choices.size() < inverse_table.size()) {
				choices.push_back(0);
			}
		}
	}

	return std::move(sub_dicts);
}

// Find all matches that can be found using possible l33t substitutions
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::l33t_match(const std::string& password) const
{
	std::vector<std::unique_ptr<match>> matches;

	std::map<char /* orig */, std::vector<char /* l33t */>> relevent = relevent_l33t_subtable(password);
	if (relevent.empty()) {
		return std::move(matches);
	}

	std::vector<std::map<char /* l33t */, char /* orig */>> substitutions = enumerate_l33t_subs(relevent);
	// For each possible l33t->original substitutions
	for (auto& sub : substitutions) {
		std::string subbed_password = translate(password, sub);
		// Call each dictionary matcher
		for (auto& matcher : dictionary_matchers) {
			std::vector<std::unique_ptr<match>> results = matcher(subbed_password);
			// Enumerate match results
			for (auto& match : results) {
				std::string token = substr(password, match->i, match->j);
				// Skip match that not used l33t substitution at all
				if (token == match->matched_word) {
					continue;
				}

				// Modify result
				match->pattern = pattern::L33T;
				match->token = token;

				// Select actual substitutions in use
				for (auto& it : sub) {
					if (token.find(it.first) != std::string::npos) {
						match->sub.insert(it);
						if (!match->sub_display.empty()) {
							match->sub_display.append(", ");
						}
						match->sub_display.append(1, it.first).append(" -> ").append(1, it.second);
					}
				}

				matches.push_back(std::move(match));
			}
		}
	}

	return std::move(matches);
}

//////////////////////////////////////////////////////////////////////////
// Spatial matching
//////////////////////////////////////////////////////////////////////////

// Find sequences of neighboring keyboard characters for a given keyboard layout
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::spatial_match_helper(const std::string& password, const std::string& graph_name, const std::map<char /* key */, std::vector<std::string /* keys */> /* neighbors */>& graph) const
{
	std::vector<std::unique_ptr<match>> results;

	size_t password_size = password.size();
	if (password_size == 0) {
		return results;
	}

	for (size_t i = 0; i < password_size - 1; /* empty */) {
		size_t j = i + 1;
		int last_direction = -1;
		size_t turns = 0;
		size_t shifted_count = 0;

		// Try to find a sequence
		while (true) {
			char prev_char = password[j - 1];
			bool found = false;
			int found_direction = -1;
			int cur_direction = -1;

			std::vector<std::string /* keys */> adjacents;
			auto it = graph.find(prev_char);
			if (it != graph.end()) {
				adjacents = it->second;
			}

			// Consider growing pattern by one character if j hasn't gone over the edge.
			if (j < password_size) {
				char cur_char = password[j];
				for (auto& adj : adjacents) {
					cur_direction += 1;
					size_t pos = adj.find(cur_char);
					if (pos != std::string::npos) {
						found = true;
						found_direction = cur_direction;
						if (pos == 1) {
							// Index 1 in the adjacency means the key is shifted, 0 means unshifted : A vs a, % vs 5, etc.
							// for example, 'q' is adjacent to the entry '2@'. @ is shifted w / index 1, 2 is unshifted.
							shifted_count += 1;
						}
						if (last_direction != found_direction) {
							// Adding a turn is correct even in the initial case when last_direction is null :
							// every spatial pattern starts with a turn.
							turns += 1;
							last_direction = found_direction;
						}
						break;
					}
				}
			}

			if (found) {
				// If the current pattern continued, extend j and try to grow again
				j += 1;
			} else {
				// Otherwise push the pattern discovered so far, if any...
				if (j - i > 2) {
					// Don't consider chains of length 1 or 2.
					std::unique_ptr<match> result(new match(pattern::SPATIAL));
					result->i = i;
					result->j = j - 1;
					result->token = substr(password, i, j - 1);
					result->graph = graph_name;
					result->turns = turns;
					result->shifted_count = shifted_count;
					results.push_back(std::move(result));
				}
				// ...and then start a new search for the rest of the password.
				i = j;
				break;
			}
		}
	}
	return std::move(results);
}

// Find sequences of neighboring keyboard characters
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::spatial_match(const std::string& password) const
{
	std::vector<std::unique_ptr<match>> results;
	// Invoke matcher for all keyboard graphs and collect results
	for (auto& graph : graphs) {
		std::vector<std::unique_ptr<match>> matches = spatial_match_helper(password, graph.first, graph.second);
		results.insert(results.end(), std::make_move_iterator(matches.begin()), std::make_move_iterator(matches.end()));
	}
	return std::move(results);
}

//////////////////////////////////////////////////////////////////////////
// Repeats and sequences matching
//////////////////////////////////////////////////////////////////////////

// Find repeating characters
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::repeat_match(const std::string& password) const
{
	std::vector<std::unique_ptr<match>> results;

	// Iterate over the whole password
	size_t password_size = password.size();
	for (size_t i = 0; i < password_size; /* empty */) {
		size_t j = i + 1;
		while (true) {
			// Try to consume as much repeating characters as possible
			if (j < password_size && password[j - 1] == password[j]) {
				j += 1;
			} else {
				// Don't consider chains of length 1 or 2
				if (j - i > 2) {
					std::unique_ptr<match> result(new match(pattern::REPEAT));
					result->i = i;
					result->j = j - 1;
					result->token = substr(password, i, j - 1);
					result->repeated_char = password[i];
					results.push_back(std::move(result));
				}
				break;
			}
		}
		i = j;
	}

	return std::move(results);
}

// Find character sequences
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::sequence_match(const std::string& password) const
{
	// Calculate direction from string positions
	auto getDirection = [](size_t n, size_t m) -> int {
		if (n < m)
		{
			return -(int)(m - n);
		} else if (n > m)
		{
			return (int)(n - m);
		} else
		{
			return 0;
		}
	};

	std::vector<std::unique_ptr<match>> results;

	// Iterate over the whole password
	size_t password_size = password.size();
	for (size_t i = 0; i < password_size; /* empty */) {
		size_t j = i + 1;

		// Try to find a sequence that contains both endpoints of the given password slice
		auto seq_candidate = sequences.begin();
		int seq_direction = 0;
		for (/* empty */; seq_candidate != sequences.end(); ++seq_candidate) {
			size_t i_n = seq_candidate->second.find(password[i]);
			size_t j_n = seq_candidate->second.find(password[j]);
			if (i_n != std::string::npos && j_n != std::string::npos) {
				int direction = getDirection(j_n, i_n);
				if (direction == 1 || direction == -1) {
					// Remember desired direction
					seq_direction = direction;
					break;
				}
			}
		}

		// If we have a candidate sequence
		if (seq_candidate != sequences.end()) {
			// Try to consume as much characters as possible from the given sequence in the given direction
			while (true) {
				char prev_char = password[j - 1];
				char cur_char = password[j];
				char prev_n = seq_candidate->second.find(prev_char);
				char cur_n = seq_candidate->second.find(cur_char);

				if (j < password_size && getDirection(cur_n, prev_n) == seq_direction) {
					j += 1;
				} else {
					// Don't consider chains of length 1 or 2
					if (j - i > 2) {
						std::unique_ptr<match> result(new match(pattern::SEQUENCE));
						result->i = i;
						result->j = j - 1;
						result->token = substr(password, i, j - 1);
						result->sequence_name = seq_candidate->first;
						result->sequence_space = seq_candidate->second.size();
						result->ascending = (seq_direction == 1);
						results.push_back(std::move(result));
					}
					break;
				}
			}
		}
		i = j;
	}

	return std::move(results);
}

//////////////////////////////////////////////////////////////////////////
// Digits, years and dates matching
//////////////////////////////////////////////////////////////////////////

// Find positions of all non-overlapping matches of the given regular expression
std::vector<std::pair<size_t, size_t>> zxcppvbn::findall(const std::string& password, const std::regex& rx) const
{
	std::vector<std::pair<size_t, size_t>> matches;

	std::sregex_iterator it(password.begin(), password.end(), rx);
	std::sregex_iterator end;
	for (/* empty */; it != end; ++it) {
		size_t i = it->position();
		size_t j = i + it->length() - 1;
		matches.push_back(std::make_pair(i, j));
	}
	return std::move(matches);
}

// Find positions of all non-overlapping matches of the given regular expression, and split all matches to strings using another regular expression
std::vector<std::tuple<size_t, size_t, std::vector<std::string>>> zxcppvbn::splitall(const std::string& password, const std::regex& rx, const std::regex& subrx) const
{
	std::vector<std::tuple<size_t, size_t, std::vector<std::string>>> results;

	std::vector<std::pair<size_t, size_t>> matches = findall(password, rx);
	for (auto& match : matches) {
		std::vector<std::string> parts;
		std::vector<std::pair<size_t, size_t>> subs = findall(substr(password, match.first, match.second), subrx);
		size_t k = 0;
		for (auto& sub : subs) {
			if (k < sub.first) {
				parts.push_back(substr(password, k, sub.first - 1));
			}
			parts.push_back(substr(password, sub.first, sub.second));
			k = sub.second + 1;
		}
		if (k < match.second) {
			parts.push_back(substr(password, k, match.second));
		}

		results.push_back(std::make_tuple(match.first, match.second, std::move(parts)));
	}

	return std::move(results);
}

// Regular expression for matching digits
const std::regex zxcppvbn::digits_rx("\\d{3,}");

// Find all digit sequences
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::digits_match(const std::string& password) const
{
	std::vector<std::unique_ptr<match>> results;
	for (auto& match : findall(password, digits_rx)) {
		std::unique_ptr<zxcppvbn::match> result(new zxcppvbn::match(pattern::DIGITS));
		result->i = match.first;
		result->j = match.second;
		result->token = substr(password, match.first, match.second);
		results.push_back(std::move(result));
	}
	return std::move(results);
}

// Regular expression for matching years
const std::regex zxcppvbn::year_rx("19\\d\\d|200\\d|201\\d");

// Find all year numbers
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::year_match(const std::string& password) const
{
	std::vector<std::unique_ptr<match>> results;
	for (auto& match : findall(password, year_rx)) {
		std::unique_ptr<zxcppvbn::match> result(new zxcppvbn::match(pattern::YEAR));
		result->i = match.first;
		result->j = match.second;
		result->token = substr(password, match.first, match.second);
		results.push_back(std::move(result));
	}
	return std::move(results);
}

// Find all dates
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::date_match(const std::string& password) const
{
	std::vector<std::unique_ptr<zxcppvbn::match>> results = date_without_sep_match(password);
	std::vector<std::unique_ptr<zxcppvbn::match>> matches = date_sep_match(password);
	results.insert(results.end(), std::make_move_iterator(matches.begin()), std::make_move_iterator(matches.end()));
	return std::move(results);
}

// Regular expression to match all dates without separators
const std::regex zxcppvbn::date_rx_without_sep("\\d{4,8}");

std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::date_without_sep_match(const std::string& password) const
{
	std::vector<std::unique_ptr<zxcppvbn::match>> results;

	for (auto& match : findall(password, date_rx_without_sep)) {
		size_t i = match.first;
		size_t j = match.second;
		std::string token = substr(password, i, j);
		size_t end = token.size();

		// Parse year alternatives
		std::vector<std::tuple<size_t /* i */, size_t /* j */, std::string /* year */, std::string /* daymonth */>> candidates_round1;
		if (end <= 6) {
			// 2-digit year prefix
			candidates_round1.push_back(std::make_tuple(i, j, substr(token, 0, 1), substr(token, 2, end - 1)));
			// 2-digit year suffix
			candidates_round1.push_back(std::make_tuple(i, j, substr(token, end - 2, end - 1), substr(token, 0, end - 3)));
		}
		if (end >= 6) {
			// 4-digit year prefix
			candidates_round1.push_back(std::make_tuple(i, j, substr(token, 0, 3), substr(token, 4, end - 1)));
			// 4-digit year suffix
			candidates_round1.push_back(std::make_tuple(i, j, substr(token, end - 4, end - 1), substr(token, 0, end - 5)));
		}

		// Parse day/month alternatives
		std::vector<std::tuple<size_t /* i */, size_t /* j */, std::string /* year */, std::string /* day */, std::string /* month */>> candidates_round2;
		for (auto& candidate : candidates_round1) {
			size_t i = std::get<0>(candidate), j = std::get<1>(candidate);
			std::string& year = std::get<2>(candidate);
			std::string& daymonth = std::get<3>(candidate);

			if (daymonth.size() == 2) {
				candidates_round2.push_back(std::make_tuple(i, j, year, substr(daymonth, 0, 0), substr(daymonth, 1, 1)));
			} else if (daymonth.size() == 3) {
				candidates_round2.push_back(std::make_tuple(i, j, year, substr(daymonth, 0, 1), substr(daymonth, 2, 2)));
				candidates_round2.push_back(std::make_tuple(i, j, year, substr(daymonth, 0, 0), substr(daymonth, 1, 2)));
			} else if (daymonth.size() == 4) {
				candidates_round2.push_back(std::make_tuple(i, j, year, substr(daymonth, 0, 1), substr(daymonth, 2, 3)));
			}
		}

		// Final loop: reject invalid dates
		for (auto& candidate : candidates_round2) {
			// Convert string to int
			uint16_t y;
			uint16_t m;
			uint16_t d;
			std::istringstream(std::get<2>(candidate)) >> y;
			std::istringstream(std::get<3>(candidate)) >> m;
			std::istringstream(std::get<4>(candidate)) >> d;

			// Add result if valid date
			if (check_date(y, m, d)) {
				std::unique_ptr<zxcppvbn::match> result(new zxcppvbn::match(pattern::DATE));
				result->i = std::get<0>(candidate);
				result->j = std::get<1>(candidate);
				result->token = substr(password, result->i, result->j);
				result->day = d;
				result->month = m;
				result->year = y;
				results.push_back(std::move(result));
			}
		}
	}

	return std::move(results);
}

// Regular expression to match all dates with separators (mm/dd/yyyy)
const std::regex zxcppvbn::date_rx_year_suffix("(\\d{1,2})(\\s|-|/|\\\\|_|\\.)(\\d{1,2})\\2(19\\d{2}|200\\d|201\\d|\\d{2})");
// Regular expression to match all dates with separators (yyyy/mm/dd)
const std::regex zxcppvbn::date_rx_year_prefix("(19\\d{2}|200\\d|201\\d|\\d{2})(\\s|-|/|\\\\|_|\\.)(\\d{1,2})\\2(\\d{1,2})");
// Regular expression to find numbers in dates with separators
const std::regex zxcppvbn::date_rx_split("\\d{1,4}");

// Find dates with separator characters
std::vector<std::unique_ptr<zxcppvbn::match>> zxcppvbn::date_sep_match(const std::string& password) const
{
	std::vector<std::unique_ptr<zxcppvbn::match>> results;

	// Check date value, and if it seems a valid date, add as a match result
	auto append_result = [this, &results, &password](size_t i, size_t j, const std::string & year, const std::string & daymonth1, const std::string & daymonth2, const std::string & sep) {
		// Convert string to int
		uint16_t y;
		uint16_t m;
		uint16_t d;
		std::istringstream(year) >> y;
		std::istringstream(daymonth1) >> m;
		std::istringstream(daymonth2) >> d;

		// Add result if valid date
		if (check_date(y, m, d)) {
			std::unique_ptr<zxcppvbn::match> result(new zxcppvbn::match(pattern::DATE));
			result->i = i;
			result->j = j;
			result->token = substr(password, i, j);
			result->separator = sep;
			result->day = d;
			result->month = m;
			result->year = y;
			results.push_back(std::move(result));
		}
	};

	// Search for dates with year first
	for (auto& match : splitall(password, date_rx_year_suffix, date_rx_split)) {
		std::vector<std::string>& subs = std::get<2>(match);
		append_result(std::get<0>(match), std::get<1>(match), subs[4], subs[2], subs[0], subs[1]);
	}
	// Search for dates with year last
	for (auto& match : splitall(password, date_rx_year_prefix, date_rx_split)) {
		std::vector<std::string>& subs = std::get<2>(match);
		append_result(std::get<0>(match), std::get<1>(match), subs[0], subs[2], subs[4], subs[1]);
	}

	return std::move(results);
}

// Check whether a given date is valid or not
bool zxcppvbn::check_date(uint16_t year, uint16_t& month, uint16_t& day) const
{
	// tolerate both day - month and month - day order
	if (max_month <= month && month <= max_day && day <= max_month) {
		std::swap(month, day);
	}

	if (day > max_day || month > max_month) {
		return false;
	}
	if (year < min_year || year > max_year) {
		return false;
	}

	return true;
}
