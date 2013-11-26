#include "zxcppvbn.hpp"

#include <algorithm>
#include <cctype>
#include <set>

//////////////////////////////////////////////////////////////////////////
// Utility functions
//////////////////////////////////////////////////////////////////////////

// Convert an ASCII string to lowercase
std::string zxcppvbn::to_lower(const std::string& password)
{
	std::string data = password;
	std::transform(data.begin(), data.end(), data.begin(), ::tolower);
	return data;
}

// Replace characters in an ASCII string
std::string zxcppvbn::translate(const std::string& password, const std::map<char, char>& chr_map)
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

	return data;
}

// Return substring from ith to jth character
std::string zxcppvbn::substr(const std::string& password, size_t i, size_t j)
{
	return password.substr(i, j - i + 1);
}

//////////////////////////////////////////////////////////////////////////
/// Complex matching
//////////////////////////////////////////////////////////////////////////

// Combine match results
std::vector<zxcppvbn::match_result> zxcppvbn::omnimatch(const std::string& password)
{
	std::vector<match_result> results;
	// Invoke all matchers and collect results
	for (auto& matcher : matchers) {
		std::vector<match_result> matches = matcher(password);
		results.insert(results.end(), matches.begin(), matches.end());
	}
	// Sort match results according to their position in the input
	std::sort(results.begin(), results.end(), [](const match_result & match1, const match_result & match2) {
		return (match1.i < match2.i) || ((match1.i == match2.i) && (match1.j < match2.j));
	});
	return results;
}

//////////////////////////////////////////////////////////////////////////
// Dictionary matching
//////////////////////////////////////////////////////////////////////////

// Find matches in known dictionary
std::vector<zxcppvbn::match_result> zxcppvbn::dictionary_match(const std::string& password, const std::string& dictionary)
{
	const std::map<std::string, int>& ranked_dict = ranked_dictionaries.at(dictionary);
	std::vector<match_result> results;
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
				match_result result;
				result.pattern = match_pattern::DICTIONARY;
				result.i = i;
				result.j = j;
				result.token = password_part;
				result.dictionary_name = dictionary;
				result.matched_word = it->first;
				result.rank = it->second;
				results.push_back(std::move(result));
			}
		}
	}
	return results;
}

//////////////////////////////////////////////////////////////////////////
// L33t matching
//////////////////////////////////////////////////////////////////////////

// Get a subtable of the l33t substitution table that contains only those substitutions that is in the password
std::map<char, std::vector<char>> zxcppvbn::relevent_l33t_subtable(const std::string& password)
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
	return filtered;
}

// Calculate all possible inverse l33t substitution maps
std::vector<std::map<char, char>> zxcppvbn::enumerate_l33t_subs(const std::map<char, std::vector<char>>& table)
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

	return sub_dicts;
}

// Find all matches that can be found using possible l33t substitutions
std::vector<zxcppvbn::match_result> zxcppvbn::l33t_match(const std::string& password)
{
	std::vector<zxcppvbn::match_result> matches;

	std::map<char /* orig */, std::vector<char /* l33t */>> relevent = relevent_l33t_subtable(password);
	if (relevent.empty()) {
		return matches;
	}

	std::vector<std::map<char /* l33t */, char /* orig */>> substitutions = enumerate_l33t_subs(relevent);
	// For each possible l33t->original substitutions
	for (auto& sub : substitutions) {
		std::string subbed_password = translate(password, sub);
		// Call each dictionary matcher
		for (auto& matcher : dictionary_matchers) {
			std::vector<match_result> results = matcher(subbed_password);
			// Enumerate match results
			for (auto& match : results) {
				std::string token = substr(password, match.i, match.j);
				// Skip match that not used l33t substitution at all
				if (token == match.matched_word) {
					continue;
				}

				// Modify result
				match.pattern = match_pattern::L33T;
				match.token = token;

				// Select actual substitutions in use
				for (auto& it : sub) {
					if (token.find(it.first) != std::string::npos) {
						match.sub.insert(it);
						if (!match.sub_display.empty()) {
							match.sub_display.append(", ");
						}
						match.sub_display.append(1, it.first).append(" -> ").append(1, it.second);
					}
				}

				matches.push_back(match);
			}
		}
	}

	return matches;
}

//////////////////////////////////////////////////////////////////////////
// Spatial matching
//////////////////////////////////////////////////////////////////////////

std::vector<zxcppvbn::match_result> zxcppvbn::spatial_match_helper(const std::string& password, const std::string& graph_name, const std::map<char /* key */, std::vector<std::string /* keys */> /* neighbors */>& graph)
{
	std::vector<zxcppvbn::match_result> results;

	size_t password_size = password.size();
	for (size_t i = 0; i < password_size - 1; /* empty */) {
		size_t j = i + 1;
		int last_direction = -1;
		size_t turns = 0;
		size_t shifted_count = 0;

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
					match_result result;
					result.pattern = match_pattern::SPATIAL;
					result.i = i;
					result.j = j - 1;
					result.token = substr(password, i, j - 1);
					result.graph = graph_name;
					result.turns = turns;
					result.shifted_count = shifted_count;
					results.push_back(result);
				}
				// ...and then start a new search for the rest of the password.
				i = j;
				break;
			}
		}
	}
	return results;
}

std::vector<zxcppvbn::match_result> zxcppvbn::spatial_match(const std::string& password)
{
	std::vector<match_result> results;
	// Invoke matcher for all keyboard graphs and collect results
	for (auto& graph : graphs) {
		std::vector<match_result> matches = spatial_match_helper(password, graph.first, graph.second);
		results.insert(results.end(), matches.begin(), matches.end());
	}
	return results;
}

//////////////////////////////////////////////////////////////////////////
// Repeats and sequences matching
//////////////////////////////////////////////////////////////////////////

std::vector<zxcppvbn::match_result> zxcppvbn::repeat_match(const std::string& password)
{
	std::vector<match_result> results;

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
					match_result result;
					result.pattern = match_pattern::REPEAT;
					result.i = i;
					result.j = j - 1;
					result.token = substr(password, i, j - 1);
					result.repeated_char = password[i];
					results.push_back(result);
				}
				break;
			}
		}
		i = j;
	}

	return results;
}

std::vector<zxcppvbn::match_result> zxcppvbn::sequence_match(const std::string& password)
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

	std::vector<match_result> results;

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
						match_result result;
						result.pattern = match_pattern::SEQUENCE;
						result.i = i;
						result.j = j - 1;
						result.token = substr(password, i, j - 1);
						result.sequence_name = seq_candidate->first;
						result.sequence_space = seq_candidate->second.size();
						result.ascending = (seq_direction == 1);
						results.push_back(result);
					}
					break;
				}
			}
		}
		i = j;
	}

	return results;
}
