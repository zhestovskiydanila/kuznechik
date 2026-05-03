#include "kuznechik.hpp"
#include <cstdlib>
#include <fstream>
#include <string>
#include <iostream>
#include <filesystem>

Kuznechik::Kuznechik()
    : MAC{}, master_key{}, round_key(init_round_keys(master_key)),
      MAC_key(init_OMAC_keys()) {
        LOG_EVENT(KEY_DIGEST, MSG_ID_KEY_DIGEST, module_name);
      };

Kuznechik::Kuznechik(kkey_t &mkey)
    : MAC{}, master_key{mkey}, round_key(init_round_keys(master_key)),
      MAC_key(init_OMAC_keys()) {
  LOG_EVENT(KEY_DIGEST, MSG_ID_KEY_DIGEST, module_name);
  flush_master_key(mkey);
};

Kuznechik::~Kuznechik() {
  flush_master_key(master_key);
  flush_round_keys(round_key);
  flush_OMAC_keys(MAC_key);
  LOG_EVENT(KEY_FLUSH, MSG_ID_KEY_FLUSH, module_name);
}

Kuznechik::Kuznechik(kkey_t &mkey, kblock_t &some_MAC)
    : MAC{some_MAC}, master_key{mkey}, round_key(init_round_keys(master_key)),
      MAC_key(init_OMAC_keys()) {
  LOG_EVENT(KEY_DIGEST, MSG_ID_KEY_DIGEST, module_name);
  flush_master_key(mkey);
}

void Kuznechik::authenticate_message(const kblock_t &msg) {
  XOR(MAC, msg);
  encrypt_func(MAC);
}

Kuznechik::kblock_t Kuznechik::process_sequence(const std::string &fname) {
  std::fstream file;
  file.open(fname, std::ios_base::in | std::ios_base::binary);

  if (!file.is_open() || file.fail()) {
    LOG_EVENT(FILE_OPEN_FAIL, MSG_ID_OPEN_FAIL, module_name);
    exit(EXIT_FAILURE);
  } else {
    LOG_EVENT(FILE_OPEN_SUCCESS, MSG_ID_OPEN_SUCCESS, module_name);
  }


  std::vector<uint8_t> file_buff(BUFF_SIZE);
  kblock_t msg{}, last_block{};
  std::size_t data_size = 0, lb_len = 0, offset = 0, processed_size = 0;
  while (!file.eof()) {

    std::size_t block_count = 0, processed_blocks = 0;
    file.read(reinterpret_cast<char *>(file_buff.data()), BUFF_SIZE);
    data_size = file.gcount(), lb_len = data_size % BLOCK_SIZE,
    block_count = data_size / BLOCK_SIZE;

    if (data_size == 0) {
      break;
    }

    std::cout << "Прочитано из файла байт " << data_size << std::endl;

    while (offset + BLOCK_SIZE < data_size && processed_blocks < block_count) {

      memmove(msg.data(), file_buff.data() + offset, BLOCK_SIZE);

      if (file.eof() && processed_blocks == block_count - 1 && lb_len == 0) {
        last_block = {msg};
        std::cout << "Ловушка" << std::endl;
        break;
      }

      authenticate_message(msg);
      std::cout << "Промежуточный результат " << MAC << std::endl;
      offset += BLOCK_SIZE;
      processed_blocks++;
    }

    if (file.eof() && processed_blocks == block_count - 1 && lb_len == 0) {
      break;
    }

    if (offset < data_size && processed_blocks == block_count) {
      std::size_t tail_size = data_size - offset;
      memmove(last_block.data(), file_buff.data() + offset, tail_size);

      pad_last_block(last_block, tail_size);
      XOR(last_block, MAC_key[1]);
      std::cout << "Последний блок ";
      print_block(std::cout, last_block);
      std::cout << std::endl;
      authenticate_message(last_block);

      processed_size += tail_size; 
    
      break;
    }
    processed_size += data_size;
  }

  if (lb_len == 0) {
    memmove(last_block.data(), file_buff.data() + offset, BLOCK_SIZE);
    XOR(last_block, MAC_key[0]);
    std::cout << "Последний блок ";
    print_block(std::cout, last_block);
    std::cout << std::endl;
    authenticate_message(last_block);
  }

  std::cout << "Обработано байт " << processed_size << std::endl;
  flush_data(file_buff);
  return MAC;
}

Kuznechik::kkey_t scan_key_from_string(const std::string &key) {
  Kuznechik::kkey_t mkey{};
  if (key.size() != KEY_SIZE * 2) {
    std::cout << "Ошибка скана ключа, неверный размер" << std::endl;
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < KEY_SIZE; ++i) {
    uint8_t byte = static_cast<uint8_t>(std::stoi(key.substr(2 * i, 2), nullptr, 16));
    mkey[i] = byte;
  }
  return mkey;
}

//Kuznechik::kblock_t Kuznechik::process_sequence(std::vector<uint8_t> &filebuf) {}

int main() {
  std::string fname;
  std::string mkey;
  std::cout << "Введите имя файла" << std::endl;
  std::cin >> fname;
  std::cout << "Введите ключ" << std::endl;
  std::cin >> mkey;
  Kuznechik::kkey_t key;
  /* try {
    key = scan_key_from_string(mkey);
  } catch (...) {
    std::cout << "Ошибка скана ключа" << std::endl;
    exit(EXIT_FAILURE);
  }
  Kuznechik cipher{key};
  try {
    Kuznechik::kblock_t MAC = cipher.process_sequence(fname);
    std::cout << MAC << std::endl;
  }
  catch (...) {
    exit(EXIT_FAILURE);
  } */

  key = scan_key_from_string(mkey);
  Kuznechik cipher{key};
  Kuznechik::kblock_t MAC = cipher.process_sequence(fname);
  std::cout << MAC << std::endl;
  return 0;
}
