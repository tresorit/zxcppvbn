#include "frequency_lists.hpp"

#include "tools/tinf/tinf.h"

namespace zxcppvbn
{

#include "frequency_lists.inc"

frequency_lists::frequency_lists()
	: lists()
{
}

std::shared_ptr<frequency_lists> frequency_lists::load()
{
	std::shared_ptr<frequency_lists> result(new frequency_lists());
	tinf_init();

	size_t clen = sizeof(data) / sizeof(uint8_t);
	size_t dlen = data[clen - 1];
    dlen = 256*dlen + data[clen - 2];
    dlen = 256*dlen + data[clen - 3];
    dlen = 256*dlen + data[clen - 4];

	std::unique_ptr<uint8_t[]> raw(new uint8_t[dlen]);
	if(tinf_gzip_uncompress(raw.get(), &dlen, data, clen) != TINF_OK) {
		return nullptr;
	}

	size_t i = 0;
	while(raw[i] != 0) {
		size_t dbegin = i;
		while(raw[i] != 2) i++;
		std::string d(&raw[dbegin], &raw[i++]);

		std::vector<std::string> l;
		while(raw[i] != 1) {
			size_t wbegin = i;
			while(raw[i] != 2) i++;
			std::string w(&raw[wbegin], &raw[i++]);

			l.push_back(w);
		}

		result->lists.insert(std::make_pair(d, l));
		i++;
	}
	return result;
}

const std::vector<std::string>& frequency_lists::get(const std::string& dictionary) const
{
	return lists.at(dictionary);
}


}
