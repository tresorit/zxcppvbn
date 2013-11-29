#include "../zxcppvbn.hpp"

#include <iostream>

void render_match(const zxcppvbn::match& match)
{
	std::cout << "  token: " << match.token << std::endl;;
	std::cout << "   pattern: " << '0' + (std::underlying_type<zxcppvbn::pattern>::type)match.pattern;
	std::cout << ", i: " << match.i << ", j: " << match.j;
	std::cout << ", entropy: " << match.entropy << std::endl;
	switch (match.pattern) {
		case zxcppvbn::pattern::L33T:
			std::cout << "   subs: " << match.sub_display;
			std::cout << ", l33t entropy: " << match.l33t_entropy << std::endl;
		case zxcppvbn::pattern::DICTIONARY:
			std::cout << "   dictionary: " << match.dictionary_name;
			std::cout << ", word: " << match.matched_word;
			std::cout << ", rank: " << match.rank;
			std::cout << ", base entropy: " << match.base_entropy;
			std::cout << ", uppercase entropy: " << match.uppercase_entropy << std::endl;
			break;
		case zxcppvbn::pattern::SPATIAL:
			std::cout << "   keyboard: " << match.graph;
			std::cout << ", turns: " << match.turns;
			std::cout << ", shift count: " << match.shifted_count << std::endl;
			break;
		case zxcppvbn::pattern::REPEAT:
			std::cout << "   repeated char: " << match.repeated_char << std::endl;
			break;
		case zxcppvbn::pattern::SEQUENCE:
			std::cout << "   sequence name: " << match.sequence_name;
			std::cout << ", sequence space: " << match.sequence_space;
			std::cout << ", ascending: " << match.ascending << std::endl;
			break;
		case zxcppvbn::pattern::DATE:
			std::cout << "   year: " << match.year;
			std::cout << ", month: " << match.month;
			std::cout << ", day: " << match.day;
			std::cout << ", separator: " << match.separator << std::endl;
			break;
		case zxcppvbn::pattern::BRUTEFORCE:
			std::cout << "   cardinality: " << match.cardinality << std::endl;
			break;
	}
}

void render_result(const zxcppvbn::result& result)
{
	std::cout << "password: " << result.password << std::endl;
	std::cout << " entropy: " << result.entropy;
	std::cout << ", crack time: " << result.crack_time_display << " (" << result.crack_time.count() << " s)";
	std::cout << ", score: " << result.score;
	std::cout << ", calculation time: " << result.calc_time.count() << " ms" << std::endl;
	std::cout << " matches: " << std::endl;
	for (auto& match : result.matches) {
		render_match(*match);
	}
}

int main()
{
	zxcppvbn zxcvbn;

	std::vector<std::string> test_passwords {
		"zxcvbn",
		"qwER43@!",
		"Tr0ub4dour & 3",
		"correcthorsebatterystaple",
		"coRrecth0rseba++ery9.23.2007staple$",

		"D0g..................",
		"abcdefghijk987654321",
		"neverforget13 / 3 / 1997",
		"1qaz2wsx3edc",

		"temppass22",
		"briansmith",
		"briansmith4mayor",
		"password1",
		"viking",
		"thx1138",
		"ScoRpi0ns",
		"do you know",

		"ryanhunter2000",
		"rianhunter2000",

		"asdfghju7654rewq",
		"AOEUIDHG&*()LS_",

		"12345678",
		"defghi6789",

		"rosebud",
		"Rosebud",
		"ROSEBUD",
		"rosebuD",
		"ros3bud99",
		"r0s3bud99",
		"R0$38uD99",

		"verlineVANDERMARK",

		"eheuczkqyq",
		"rWibMFACxAUGZmxhVncy",
		"Ba9ZyWABu99[BK#6MBgbH88Tofv)vs$w"
	};

	for (auto& password : test_passwords) {
		zxcppvbn::result result = zxcvbn(password);
		render_result(result);
		std::cout << std::endl;
	}
}