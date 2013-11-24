#include "zxcppvbn.hpp"

#include "tools/tinf/tinf.h"

size_t zxcppvbn::calc_decompressed_size(const uint8_t* comp_data, size_t comp_size)
{
	size_t dsize = comp_data[comp_size - 1];
    dsize = 256 * dsize + comp_data[comp_size - 2];
    dsize = 256 * dsize + comp_data[comp_size - 3];
    dsize = 256 * dsize + comp_data[comp_size - 4];
	return dsize;
}

bool zxcppvbn::build_ranked_dicts()
{
	tinf_init();

	size_t dsize = calc_decompressed_size(frequency_lists, frequency_lists_size);
	std::unique_ptr<uint8_t[]> raw(new uint8_t[dsize]);
	if(tinf_gzip_uncompress(raw.get(), &dsize, frequency_lists, frequency_lists_size) != TINF_OK) {
		return false;
	}

	size_t i = 0;
	while(raw[i] != 0) {
		size_t dbegin = i;
		while(raw[i] != 2) i++;
		std::string d(&raw[dbegin], &raw[i++]);

		int rank = 1;
		std::map<std::string, int> l;
		while(raw[i] != 1) {
			size_t wbegin = i;
			while(raw[i] != 2) i++;
			std::string w(&raw[wbegin], &raw[i++]);

			l.insert(std::make_pair(w, rank++));
		}

		ranked_dictionaries.insert(std::make_pair(d, l));
		i++;
	}
	return true;
}

bool zxcppvbn::build_graphs()
{
	tinf_init();

	size_t dsize = calc_decompressed_size(adjacency_graphs, adjacency_graphs_size);
	std::unique_ptr<uint8_t[]> raw(new uint8_t[dsize]);
	if(tinf_gzip_uncompress(raw.get(), &dsize, adjacency_graphs, adjacency_graphs_size) != TINF_OK) {
		return false;
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

		graphs.insert(std::make_pair(k, m));
		i++;
	}
	return true;
}

void zxcppvbn::build_dict_matchers()
{
	for(auto& dict : ranked_dictionaries) {
		std::string dict_name = dict.first;
		matcher_func dict_matcher = [this, dict_name](const std::string& password) {
			return dictionary_match(password, dict_name);
		};

		dictionary_matchers.push_back(dict_matcher);
	}
}

void zxcppvbn::build_matchers()
{
	matchers.insert(matchers.end(), dictionary_matchers.cbegin(), dictionary_matchers.cend());
}

zxcppvbn::zxcppvbn()
{
	if(!build_ranked_dicts()) {
		return;
	}
	if(!build_graphs()) {
		return;
	}

	ranked_dictionaries.insert(std::make_pair("user_inputs", std::map<std::string, int>()));
	build_dict_matchers();
	build_matchers();
}

std::unique_ptr<zxcppvbn::result> zxcppvbn::operator()(const std::string& password, const std::vector<std::string>& user_inputs /* = std::vector<std::string>() */)
{
	std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
	std::map<std::string, int>& ranked_user_inputs_dict = ranked_dictionaries.at("user_inputs");
	ranked_user_inputs_dict.clear();
	for(size_t i = 0; i < user_inputs.size(); i++) {
		ranked_user_inputs_dict[to_lower(user_inputs[i])] = i + 1;
	}

	std::unique_ptr<result> res(new result());
	res->matches = omnimatch(password);
	res->calc_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start);
	return res;
}
