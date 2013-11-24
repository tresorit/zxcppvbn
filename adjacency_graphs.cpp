#include "adjacency_graphs.hpp"

#include "tools/tinf/tinf.h"

namespace zxcppvbn
{

#include "adjacency_graphs.inc"

adjacency_graphs::adjacency_graphs()
	: graphs()
{
}

std::shared_ptr<adjacency_graphs> adjacency_graphs::load()
{
	std::shared_ptr<adjacency_graphs> result(new adjacency_graphs());
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
		size_t kbegin = i;
		while(raw[i] != 2) i++;
		std::string k(&raw[kbegin], &raw[i++]);

		std::map<char, std::vector<std::string>> m;
		while(raw[i] != 1) {
			char c = raw[i++];
			i++;

			std::vector<std::string> l;
			while(raw[i] != 2) {
				size_t wbegin = i;
				while(raw[i] != 3) i++;
				std::string w(&raw[wbegin], &raw[i++]);

				l.push_back(w);
			}

			m.insert(std::make_pair(c, l));
			i++;
		}

		result->graphs.insert(std::make_pair(k, m));
		i++;
	}
	return result;
}

}