#include "zxcppvbn.hpp"

#include <cmath>
#include <sstream>

//////////////////////////////////////////////////////////////////////////
// Utility functions
//////////////////////////////////////////////////////////////////////////

// Combination without putback
uint64_t zxcppvbn::nCk(uint64_t n, uint64_t k)
{
	if (k > n) {
		return 0;
	}
	uint64_t r = 1;
	for (uint64_t d = 1; d <= k; d++) {
		r *= n--;
		r /= d;
	}
	return r;
}

// Sum the cardinalities of the various character classes present in the password
size_t zxcppvbn::calc_bruteforce_cardinality(const std::string& password)
{
	size_t char_classes_count = char_classes_cardinality.size();
	std::vector<bool> char_class_present(char_classes_count, false);

	// Find which character classes present in the password
	for (char ord : password) {
		for (size_t i = 0; i < char_classes_count; i++) {
			auto c = char_classes_cardinality[i];
			if (std::get<0>(c) <= ord && ord <= std::get<1>(c)) {
				char_class_present[i] = true;
				break;
			}
		}
	}

	// Sum the cardinalities of those character classes
	size_t c = 0;
	for (size_t i = 0; i < char_classes_count; i++) {
		if (char_class_present[i]) {
			c += std::get<2>(char_classes_cardinality[i]);
		}
	}
	return c;
}

//////////////////////////////////////////////////////////////////////////
// Complex scoring
//////////////////////////////////////////////////////////////////////////

zxcppvbn::result zxcppvbn::minimum_entropy_match_sequence(const std::string& password, const std::vector<match_result>& matches)
{
	double min_entropy = 2.0;
	uint64_t crack_seconds = entropy_to_crack_time(min_entropy);

	// assemble result
	result res;
	res.password = password;
	res.matches = matches;
	res.entropy = min_entropy;
	res.crack_time = std::chrono::seconds(crack_seconds);
	res.crack_time_display = calc_display_time(crack_seconds);
	res.score = crack_time_to_score(crack_seconds);
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Crack time constants and functions
//////////////////////////////////////////////////////////////////////////

// Threat model: stolen hash catastrophe scenario
//
// Assumes:
// * Passwords are stored as salted hashes, different random salt per user (making rainbow attacks infeasible).
// * Hashes and salts were stolen. attacker is guessing passwords at max rate.
// * Attacker has several CPUs at their disposal.

// For a hash function like bcrypt / scrypt / PBKDF2, 10ms per guess is a safe lower bound.
// (usually a guess would take longer -- this assumes fast hardware and a small work factor.)
// adjust for your site accordingly if you use another hash function, possibly by
// several orders of magnitude!
const double zxcppvbn::single_guess = 0.01;
const double zxcppvbn::num_attackers = 100.0;

// Calculate estimated time to crack using the threat model above
uint64_t zxcppvbn::entropy_to_crack_time(double entropy)
{
	double seconds_per_guess = single_guess / num_attackers;
	// average, not total
	double seconds = 0.5 * pow(2, entropy) * seconds_per_guess;
	return (uint64_t)floor(seconds);
}

// Return an easily interpretable score value (on a scale from 0 to 5)
int zxcppvbn::crack_time_to_score(uint64_t seconds)
{
	if (seconds < 100) {
		return 0;
	} else if (seconds < 10000) {
		return 1;
	} else if (seconds < 1000000) {
		return 2;
	} else if (seconds < 100000000) {
		return 3;
	} else {
		return 4;
	}
}

// Convert seconds to a human-readable time duration string
std::string zxcppvbn::calc_display_time(uint64_t seconds)
{
	const uint64_t minute = 60;
	const uint64_t hour = minute * 60;
	const uint64_t day = hour * 24;
	const uint64_t month = day * 31;
	const uint64_t year = month * 12;
	const uint64_t century = year * 100;

	std::ostringstream oss;

	if (seconds < minute) {
		oss << "instant";
	} else if (seconds < hour) {
		oss << seconds / minute << " minutes";
	} else if (seconds < day) {
		oss << seconds / hour << " hours";
	} else if (seconds < month) {
		oss << seconds / day << " days";
	} else if (seconds < year) {
		oss << seconds / month << " months";
	} else if (seconds < century) {
		oss << seconds / year << " years";
	} else {
		oss << "centuries";
	}

	return oss.str();
}

//////////////////////////////////////////////////////////////////////////
// Entropy calculation constants and functions
//////////////////////////////////////////////////////////////////////////

// Calculate entropy of a given submatch
double zxcppvbn::calc_entropy(match_result& match)
{
	// Only calculate once
	if (match.entropy <= 0.0) {
		match.entropy = entropy_functions[match.pattern](match);
	}
	return match.entropy;
}

// Calculate entropy of non-l33t dictionary word
double zxcppvbn::dictionary_entropy(match_result& match)
{
	match.base_entropy = log2((double)match.rank);
	match.uppercase_entropy = extra_uppercase_entropy(match);
	return match.base_entropy + match.uppercase_entropy;
}

// Calculate extra entropy from uppercase letters
double zxcppvbn::extra_uppercase_entropy(match_result& match)
{
	const std::string& word = match.token;
	size_t len = word.size();
	std::string& upper = sequences["upper"];
	std::string& lower = sequences["lower"];

	// Determine casing characteristics
	bool firstUpper = false;
	bool lastUpper = false;
	size_t numNonUpper = 0;
	size_t numNonLower = 0;
	size_t numUpper = 0;
	size_t numLower = 0;
	for (size_t i = 0; i < len; i++) {
		if (upper.find(word[i]) == std::string::npos) {
			numNonUpper++;
		} else {
			if (i == 0) {
				firstUpper = true;
			}
			if (i == len - 1) {
				lastUpper = true;
			}
			numUpper++;
		}
		if (lower.find(word[i]) == std::string::npos) {
			numNonLower++;
		} else {
			numLower++;
		}
	}

	// All lower
	if (numNonUpper == len) {
		return 0;
	}

	// A capitalized word is the most common capitalization scheme,
	// so it only doubles the search space(uncapitalized + capitalized) : 1 extra bit of entropy.
	// Allcaps and end-capitalized are common enough too, underestimate as 1 extra bit to be safe.

	// First upper or last upper
	if ((firstUpper || lastUpper) && (numNonUpper == len - 1)) {
		return 1;
	}
	// All upper
	if (numNonLower == len) {
		return 1;
	}

	// Otherwise calculate the number of ways to capitalize U + L uppercase + lowercase letters with U uppercase letters or less.
	// Or, if there's more uppercase than lower (for e.g. PASSwORD), the number of ways to lowercase U+L letters with L lowercase letters or less.
	uint64_t possibilities = 0;
	for (size_t i = 0; i <= std::min(numUpper, numLower); i++) {
		possibilities += nCk(numUpper + numLower, i);
	}
	return log2((double)possibilities);
}

// Calculate entropy of l33t-substituted dictionary word
double zxcppvbn::l33t_entropy(match_result& match)
{
	match.l33t_entropy = extra_l33t_entropy(match);
	return dictionary_entropy(match) + match.l33t_entropy;
}

// Calculate extra entropy caused by l33t substitutions
double zxcppvbn::extra_l33t_entropy(match_result& match)
{
	uint64_t possibilities = 0;
	for (auto& it : match.sub) {
		size_t S = std::count(match.token.begin(), match.token.end(), it.second);
		size_t U = std::count(match.token.begin(), match.token.end(), it.first);

		for (size_t i = 0; i <= std::min(U, S); i++) {
			possibilities += nCk(U + S, i);
		}
	}

	// corner case: return 1 bit for single-letter subs, like 4pple -> apple, instead of 0.
	if (possibilities < 2) {
		return 1.0;
	} else {
		return log2((double)possibilities);
	}
}

// Calculate entropy of a neighboring keyboard keystroke sequence
double zxcppvbn::spatial_entropy(match_result& match)
{
	double s, d;

	// Find matching stats
	for (auto& stat : graph_stats) {
		std::vector<std::string>& names = std::get<0>(stat.second);
		auto it = std::find(names.begin(), names.end(), match.graph);
		if (it != names.end()) {
			s = std::get<2>(stat.second);
			d = std::get<1>(stat.second);
			break;
		}
	}

	double possibilities = 0;
	size_t L = match.token.length();
	size_t t = match.turns;

	// Estimate the number of possible patterns w/ length L or less with match.turns turns or less.
	for (size_t i = 2; i <= L; i++) {
		size_t possible_turns = std::min(t, i - 1);
		for (size_t j = 1; j <= possible_turns; j++) {
			possibilities += nCk(i - 1, j - 1) * s * pow(d, j);
		}
	}
	double entropy = log2(possibilities);

	// Add extra entropy for shifted keys. (% instead of 5, A instead of a.)
	// Math is similar to extra entropy from uppercase letters in dictionary matches.
	if (match.shifted_count > 0) {
		size_t S = match.shifted_count;
		size_t U = L - S;   // Unshifted count
		size_t possible_shifts = std::min(S, U);
		possibilities = 0;
		for (size_t i = 0; i <= possible_shifts; i++) {
			possibilities += nCk(S + U, i);
		}
		entropy += log2(possibilities);
	}
	return entropy;
}

// Calculate entropy of a repeat match
double zxcppvbn::repeat_entropy(match_result& match)
{
	size_t cardinality = calc_bruteforce_cardinality(match.token);
	return log2((double)(cardinality * match.token.length()));
}

// Calculate entropy of a sequence match
double zxcppvbn::sequence_entropy(match_result& match)
{
	double base_entropy = 0;
	char first_chr = match.token[0];
	if (first_chr == 'a' || first_chr == '1') {
		// Punish trivial sequences
		base_entropy = 1;
	} else {
		// Base entropy depends on the characters in the sequence
		for (auto& seq : sequences) {
			if (seq.second.find(first_chr) != std::string::npos) {
				base_entropy = log2((double)seq.second.size());
				// Extra bit for uppercase
				if (seq.first == "upper") {
					base_entropy += 1.0;
				}
				break;
			}
		}
	}
	// Extra bit for descending
	if (!match.ascending) {
		base_entropy += 1;
	}
	return base_entropy + log2(match.token.length());
}

double zxcppvbn::digits_entropy(match_result& match)
{
	return log2(pow(10.0, (double)match.token.length()));
}

const size_t zxcppvbn::num_years = 119;
const size_t zxcppvbn::num_months = 12;
const size_t zxcppvbn::num_days = 31;

double zxcppvbn::year_entropy(match_result& match)
{
	return log2((double)num_years);
}
