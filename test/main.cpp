#include "../zxcppvbn.hpp"

int main()
{
	zxcppvbn zxcvbn;
	std::unique_ptr<zxcppvbn::result> result = zxcvbn("HelloWorld");
}