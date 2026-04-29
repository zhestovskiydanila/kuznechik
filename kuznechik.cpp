#include "kuznechik.hpp"
#include <cstdlib>
#include <string>
#include <fstream>

Kuznechik::Kuznechik()
    : MAC{}, master_key{}, round_key(init_round_keys(master_key)),
      MAC_key(init_OMAC_keys()) {};

Kuznechik::Kuznechik(key_t &mkey)
    : MAC{}, master_key{mkey}, round_key(init_round_keys(master_key)),
      MAC_key(init_OMAC_keys()) {
        flush_master_key(mkey);
      };

Kuznechik::~Kuznechik() {
    flush_master_key(master_key);
    flush_round_keys(round_key);
    flush_OMAC_keys(MAC_key);
}

void Kuznechik::authenticate_message(block_t &msg) {
  XOR(MAC, msg);
  encrypt_func(MAC);
}

Kuznechik::block_t Kuznechik::process_sequence(const char& filename) {
  std::string fname{filename};
  std::fstream file;
  file.open(fname, std::ios_base::in | std::ios_base::binary);
  file.read

}

Kuznechik::block_t Kuznechik::process_sequence(std::vector<uint8_t> &filebuf) {
  
}

/* int main() {
  std::string
  while (true) {
    
  }
} */


  
