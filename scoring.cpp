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

//////////////////////////////////////////////////////////////////////////
// Complex scoring
//////////////////////////////////////////////////////////////////////////

double zxcppvbn::minimum_entropy_match_sequence(const std::string& password, std::vector<match_result>& matches)
{
	return 2.0;
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

uint64_t zxcppvbn::entropy_to_crack_time(double entropy)
{
	double seconds_per_guess = single_guess / num_attackers;
	// average, not total
	double seconds = 0.5 * pow(2, entropy) * seconds_per_guess;
	return (uint64_t)floor(seconds);
}

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
// Entropy functions
//////////////////////////////////////////////////////////////////////////

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

