#include "../zxcppvbn.hpp"

#include <iostream>

void render_match(const zxcppvbn::match_result& match)
{
}

void render_result(const zxcppvbn::result& result)
{
	std::cout << "password: " << result.password;
	std::cout << ", entropy: " << result.entropy;
	std::cout << ", crack time: " << result.crack_time_display << " (" << result.crack_time.count() << " s)";
	std::cout << ", score: " << result.score;
	std::cout << ", calculation time: " << result.calc_time.count() << " ms";
	std::cout << std::endl;
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
	}
}