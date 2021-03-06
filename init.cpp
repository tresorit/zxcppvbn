#include "zxcppvbn.hpp"

#include "tools/tinf/tinf.h"

#include <numeric>

// Init to empty, no submatch without a valid pattern
zxcppvbn::match::match(zxcppvbn::pattern p)
	: pattern(p), i(0), j(0), token(), entropy(0.0),
	  dictionary_name(), matched_word(), rank(0), base_entropy(0), uppercase_entropy(0),
	  sub(), sub_display(), l33t_entropy(),
	  graph(), turns(0), shifted_count(0),
	  repeated_char('\0'),
	  sequence_name(), sequence_space(0), ascending(false),
	  year(0), month(0), day(0), separator()
{
}

// Init to empty
zxcppvbn::result::result()
	: password(), entropy(0.0), crack_time(0), crack_time_display(), score(0), matches(), calc_time(0)
{
}

zxcppvbn::result::result(const result& o)
	: result()
{
	*this = o;
}

zxcppvbn::result::result(result&& o)
	: result()
{
	*this = o;
}

zxcppvbn::result& zxcppvbn::result::operator=(const result& o)
{
	if (this != &o) {
		password = o.password;
		entropy = o.entropy;
		crack_time = o.crack_time;
		crack_time_display = o.crack_time_display;
		score = o.score;
		for (auto& match : o.matches) {
			matches.push_back(std::unique_ptr<zxcppvbn::match>(new zxcppvbn::match(*match)));
		}
		calc_time = o.calc_time;
	}
	return *this;
}

zxcppvbn::result& zxcppvbn::result::operator=(result && o)
{
	if (this != &o) {
		password = std::move(o.password);
		entropy = o.entropy;
		crack_time = std::move(o.crack_time);
		crack_time_display = std::move(o.crack_time_display);
		score = o.score;
		matches = std::move(o.matches);
		calc_time = std::move(o.calc_time);
	}
	return *this;
}

// Read compressed size from the end of the gzipped data
size_t zxcppvbn::calc_decompressed_size(const uint8_t* comp_data, size_t comp_size) const
{
	size_t dsize = comp_data[comp_size - 1];
	dsize = 256 * dsize + comp_data[comp_size - 2];
	dsize = 256 * dsize + comp_data[comp_size - 3];
	dsize = 256 * dsize + comp_data[comp_size - 4];
	return dsize;
}

// Decompress and read dictionaries
bool zxcppvbn::build_ranked_dicts()
{
	// Decompress from byte array
	tinf_init();
	unsigned int dsize = calc_decompressed_size(frequency_lists, frequency_lists_size);
	std::unique_ptr<uint8_t[]> raw(new uint8_t[dsize]);
	if (tinf_gzip_uncompress(raw.get(), &dsize, frequency_lists, frequency_lists_size) != TINF_OK) {
		return false;
	}

	// Read simple format (file end - 0, dictionary end - 1, dictionary name and value separator - 2)
	size_t i = 0;
	while (raw[i] != 0) {
		// Dictionary name
		size_t dbegin = i;
		while (raw[i] != 2) {
			i++;
		}
		std::string d(&raw[dbegin], &raw[i++]);

		// Dictionary words
		int rank = 1;
		std::map<std::string, int> l;
		while (raw[i] != 1) {
			// Word
			size_t wbegin = i;
			while (raw[i] != 2) {
				i++;
			}
			std::string w(&raw[wbegin], &raw[i++]);

			l.insert(std::make_pair(std::move(w), rank++));
		}

		ranked_dictionaries.insert(std::make_pair(std::move(d), std::move(l)));
		i++;
	}
	return true;
}

// Decompress and read keyboard adjacency graphs
bool zxcppvbn::build_graphs()
{
	// Decompress from byte array
	tinf_init();
	unsigned int dsize = calc_decompressed_size(adjacency_graphs, adjacency_graphs_size);
	std::unique_ptr<uint8_t[]> raw(new uint8_t[dsize]);
	if (tinf_gzip_uncompress(raw.get(), &dsize, adjacency_graphs, adjacency_graphs_size) != TINF_OK) {
		return false;
	}

	// Read simple format (file end - 0, keyboard end - 1, keyboard name and keys separator - 2, key and neighbors separator - 3)
	size_t i = 0;
	while (raw[i] != 0) {
		// Keyboard name
		size_t kbegin = i;
		while (raw[i] != 2) {
			i++;
		}
		std::string k(&raw[kbegin], &raw[i++]);

		// Keyboard neighbor maps
		std::map<char, std::vector<std::string>> m;
		while (raw[i] != 1) {
			// Key
			char c = raw[i++];
			i++;

			// Neighbor list
			std::vector<std::string> l;
			while (raw[i] != 2) {
				// Neighbor characters
				size_t wbegin = i;
				while (raw[i] != 3) {
					i++;
				}
				std::string w(&raw[wbegin], &raw[i++]);

				l.push_back(std::move(w));
			}

			m.insert(std::make_pair(std::move(c), std::move(l)));
			i++;
		}

		graphs.insert(std::make_pair(std::move(k), std::move(m)));
		i++;
	}
	return true;
}

// Calculate keyboard statistics
void zxcppvbn::build_graph_stats()
{
	// Calculate average number of neighboring characters
	auto calc_average_degree = [](const std::map<char /* key */, std::vector<std::string /* keys */> /* neigbors */>& graph) -> double {
		double average = 0;
		for (auto& key : graph)
		{
			average += std::accumulate(key.second.begin(), key.second.end(), 0.0, [](double a, const std::string & s) -> double { return a + (double)s.size(); });
		}
		return average / (double)graph.size();
	};
	// Calculate number of keys
	auto calc_starting_positions = [](const std::map<char /* key */, std::vector<std::string /* keys */> /* neigbors */>& graph) -> double {
		return (double)graph.size();
	};

	// Calculate stats
	for (auto& graph : graphs) {
		// 1- alphanumeric, 2 - keypad
		uint8_t type = (graph.first.find("keypad") == std::string::npos) ? 1 : 2;
		double degree = calc_average_degree(graph.second);
		double start = calc_starting_positions(graph.second);

		// Update stats for the given type
		auto it = graph_stats.find(type);
		if (it == graph_stats.end()) {
			graph_stats.insert(std::make_pair(type, std::make_tuple(std::vector<std::string>(1, graph.first), degree, start)));
		} else {
			std::vector<std::string>& k = std::get<0>(it->second);
			double& d = std::get<1>(it->second);
			double& s = std::get<2>(it->second);

			double n = (double)k.size();
			k.push_back(graph.first);
			d = (d * n + degree) / (n + 1);
			s = (s * n + start) / (n + 1);
		}
	}
}

// Initialize forward l33t substitution table (so small it does not worth compressing)
void zxcppvbn::build_l33t_table()
{
	auto append_l33t_table = [this](char orig, const std::string & subst) {
		l33t_table.insert(std::make_pair(orig, std::vector<char>(subst.begin(), subst.end())));
	};
	append_l33t_table('a', "4@");
	append_l33t_table('b', "8");
	append_l33t_table('c', "({[<");
	append_l33t_table('e', "3");
	append_l33t_table('g', "69");
	append_l33t_table('i', "1!|");
	append_l33t_table('l', "1|7");
	append_l33t_table('o', "0");
	append_l33t_table('s', "$5");
	append_l33t_table('t', "+7");
	append_l33t_table('x', "%");
	append_l33t_table('z', "2");
}

// Initialize character sequence tables
void zxcppvbn::build_sequences()
{
	auto append_sequences = [this](const std::string & name, char start, char end) {
		std::string sequence(end - start + 1, '\0');
		for (char c = start, i = 0; c <= end; c++, i++) {
			sequence[i] = c;
		}
		sequences.insert(std::make_pair(name, std::move(sequence)));
	};

	append_sequences("lower", 'a', 'z');
	append_sequences("upper", 'A', 'Z');
	append_sequences("digit", '0', '9');
}

// Initialize character classes with their cardinalities
void zxcppvbn::build_cardinalities()
{
	auto add_class_cardinality = [this](char start, char end, size_t size) {
		char_classes_cardinality.push_back(std::tuple<char, char, size_t>(start, end, size == 0 ? end - start + 1 : size));
	};
	add_class_cardinality('0', '9', 0);
	add_class_cardinality('a', 'z', 0);
	add_class_cardinality('A', 'Z', 0);
	add_class_cardinality('\0', '\x7f', 33);
	add_class_cardinality('\0', '\xff', 100);
}

// Create dictionary matcher functions for each dictionaries
void zxcppvbn::build_dict_matchers()
{
	for (auto& dict : ranked_dictionaries) {
		dictionary_matchers.push_back(std::bind(&zxcppvbn::dictionary_match, this, std::placeholders::_1, dict.first));
	}
}

// Create general matcher functions
void zxcppvbn::build_matchers()
{
	// Add dictionary matchers to general matchers
	matchers.insert(matchers.end(), dictionary_matchers.begin(), dictionary_matchers.end());
	matchers.push_back(std::bind(&zxcppvbn::l33t_match, this, std::placeholders::_1));
	matchers.push_back(std::bind(&zxcppvbn::spatial_match, this, std::placeholders::_1));
	matchers.push_back(std::bind(&zxcppvbn::repeat_match, this, std::placeholders::_1));
	matchers.push_back(std::bind(&zxcppvbn::sequence_match, this, std::placeholders::_1));
	matchers.push_back(std::bind(&zxcppvbn::digits_match, this, std::placeholders::_1));
	matchers.push_back(std::bind(&zxcppvbn::year_match, this, std::placeholders::_1));
	matchers.push_back(std::bind(&zxcppvbn::date_match, this, std::placeholders::_1));
}

// Create entropy calculation functions
void zxcppvbn::build_entropy_functions()
{
	entropy_functions.insert(std::make_pair(pattern::DICTIONARY, std::bind(&zxcppvbn::dictionary_entropy, this, std::placeholders::_1)));
	entropy_functions.insert(std::make_pair(pattern::L33T, std::bind(&zxcppvbn::l33t_entropy, this, std::placeholders::_1)));
	entropy_functions.insert(std::make_pair(pattern::SPATIAL, std::bind(&zxcppvbn::spatial_entropy, this, std::placeholders::_1)));
	entropy_functions.insert(std::make_pair(pattern::REPEAT, std::bind(&zxcppvbn::repeat_entropy, this, std::placeholders::_1)));
	entropy_functions.insert(std::make_pair(pattern::SEQUENCE, std::bind(&zxcppvbn::sequence_entropy, this, std::placeholders::_1)));
	entropy_functions.insert(std::make_pair(pattern::DIGITS, std::bind(&zxcppvbn::digits_entropy, this, std::placeholders::_1)));
	entropy_functions.insert(std::make_pair(pattern::YEAR, std::bind(&zxcppvbn::year_entropy, this, std::placeholders::_1)));
	entropy_functions.insert(std::make_pair(pattern::DATE, std::bind(&zxcppvbn::date_entropy, this, std::placeholders::_1)));
}


// Initialize the class
zxcppvbn::zxcppvbn()
{
	// Initialize databases
	build_ranked_dicts();
	ranked_dictionaries.insert(std::make_pair("user_inputs", std::map<std::string, int>()));
	build_graphs();
	build_graph_stats();
	build_l33t_table();
	build_sequences();
	build_cardinalities();

	// Initialize matchers
	build_dict_matchers();
	build_matchers();
	build_entropy_functions();
}

zxcppvbn::result zxcppvbn::operator()(const std::string& password, const std::vector<std::string>& user_inputs /* = std::vector<std::string>() */)
{
	std::chrono::system_clock::time_point start = std::chrono::system_clock::now();

	// Initialize user input dictionary (we assume that rank is proportional to the position in the array)
	std::map<std::string, int>& ranked_user_inputs_dict = ranked_dictionaries.at("user_inputs");
	ranked_user_inputs_dict.clear();
	for (size_t i = 0; i < user_inputs.size(); i++) {
		ranked_user_inputs_dict[to_lower(user_inputs[i])] = i + 1;
	}

	// calculate result
	std::vector<std::unique_ptr<match>> matches = omnimatch(password);
	result res = minimum_entropy_match_sequence(password, matches);
	res.calc_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - start);
	return std::move(res);
}
