#include "kuznechik.hpp"
#include "auth.h"
#include "log.h"


/*
    Функция `authenticate_user` реализует простейшее взаимодействие
    программы с PAM‑модулем «unix», запрашивая у пользователя пароль.
    Если аутентификация прошла успешно – возвращаем 0,
    иначе – отрицательное значение.

    Внутри используется «conversation‑callback» `my_conv`, объявленная
    в `auth.h`.  Поскольку в этом учебном проекте нам нужен лишь
    ввод пароля, `my_conv` умеет отвечать лишь на сообщения типа
    `PAM_PROMPT_ECHO_OFF`.  Для остальных типов сообщений он
    возвращает `PAM_CONV_ERR`.

    Оба публичных интерфейса объявлены в `auth.h` и могут быть
    включены в любой месте проекта:
        #include "auth.h"

    Пример использования (можно разместить в `main`):
        if (authenticate_user() != 0) {
            std::cerr << "Authentication failed\n";
            return EXIT_FAILURE;
        }
*/

/* ---------------------------------------------------------------------- */
/*  Conversation callback – отвечает PAM‑модулю на запросы пользователя. */
/* ---------------------------------------------------------------------- */
int my_conv(int num_msg, const pam_message **msg, pam_response **resp,
            void *appdata_ptr) {

  pam_response *answers =
      static_cast<pam_response *>(calloc(num_msg, sizeof(pam_response)));
  if (!answers)
    return PAM_CONV_ERR;

  for (int i = 0; i < num_msg; ++i) {
    const pam_message *m = msg[i];
    if (!m) {
      free(answers);
      return PAM_CONV_ERR;
    }

    switch (m->msg_style) {
    case PAM_PROMPT_ECHO_OFF: // запрос пароля без эхо
    {

      const char *pwd = static_cast<const char *>(appdata_ptr);
      answers[i].resp = strdup(pwd);
      answers[i].resp_retcode = 0;
      break;
    }
    case PAM_PROMPT_ECHO_ON: {
      const char *login = static_cast<const char *>(appdata_ptr);
      answers[i].resp = strdup(login);
      answers[i].resp_retcode = 0;
      break;
    }
    case PAM_ERROR_MSG:
    case PAM_TEXT_INFO: {

      answers[i].resp = nullptr;
      answers[i].resp_retcode = 0;
      break;
    }
    default:
      free(answers);
      return PAM_CONV_ERR;
    }
  }

  *resp = answers;
  return PAM_SUCCESS;
}

/* ---------------------------------------------------------------------- */
/*  Основная функция аутентификации.                                      */
/* ---------------------------------------------------------------------- */
int authenticate_user() {
  const char *service_name = module_name;
  const uid_t user_uid = geteuid();
  const passwd* user_pwd = getpwuid(user_uid);
  const char *username = user_pwd->pw_name;

  if (!username) {
    std::cerr << "Unable to obtain current user name\n";
    return -1;
  }

  std::string password;
  std::cout << "Password for " << username << ": " << std::flush;

  struct termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  std::cin >> password;
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  std::cout << std::endl;

  pam_handle_t *pamh = nullptr;
  struct pam_conv conv = {my_conv, const_cast<char *>(password.c_str())};

  int ret = pam_start(service_name, username, &conv, &pamh);
  if (ret != PAM_SUCCESS) {
    std::cerr << "pam_start failed: " << pam_strerror(pamh, ret) << '\n';
    return -1;
  }

  ret = pam_authenticate(pamh, 0);
  if (ret != PAM_SUCCESS) {
    std::cerr << "Authentication error" << std::endl;
    pam_end(pamh, ret);
    return -1;
  }

  ret = pam_acct_mgmt(pamh, 0);
  if (ret != PAM_SUCCESS) {
    std::cerr << "Account management error" << std::endl;
    pam_end(pamh, ret);
    return -1;
  }

  pam_end(pamh, PAM_SUCCESS);
  return 0;
}

std::string file_path_builder() {
  const char* file_path = __FILE__;
  std::string path{file_path};
  
  return path;
}

std::random_device Kuznechik::rd;
std::uniform_int_distribution<uint8_t> Kuznechik::dist(0, 255);

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

/*
    Реализация метода Kuznechik::process_sequence, полностью повторяющая
    логику функции process_sequence из оригинального C‑кода (kuznechik.c).
    Все необходимые инициализации (таблицы GF, T/SL, константы,
    раундовые и OMAC‑ключи) выполняются в конструкторе, поэтому в методе
    оставляем только чтение файла, обработку полного и последнего (с
    паддингом) блоков и возврат рассчитанного MAC.
*/
Kuznechik::kblock_t Kuznechik::process_sequence(const std::string &fname) {
  std::fstream file;
  file.open(fname, std::ios::in | std::ios::binary);
  if (!file.is_open() || file.fail()) {
    LOG_EVENT(FILE_OPEN_FAIL, MSG_ID_OPEN_FAIL, module_name);
    std::exit(EXIT_FAILURE);
  } else {
    LOG_EVENT(FILE_OPEN_SUCCESS, MSG_ID_OPEN_SUCCESS, module_name);
  }

  const std::size_t file_size = std::filesystem::file_size(fname);
  const std::size_t block_count = file_size / BLOCK_SIZE;
  const std::size_t lb_len = file_size % BLOCK_SIZE;

  std::vector<uint8_t> buffer(BUFF_SIZE);
  kblock_t msg{}, last_block{};

  std::timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);

  std::size_t processed_blocks = 0;
  std::size_t offset = 0;

  while (file.read(reinterpret_cast<char *>(buffer.data()), BUFF_SIZE) ||
         file.gcount() > 0) {
    const std::size_t bytes_read = file.gcount();

    offset = 0;
    while (offset + BLOCK_SIZE <= bytes_read &&
           processed_blocks < block_count) {
      if (processed_blocks == block_count - 1 && lb_len == 0) {
        memmove(last_block.data(), buffer.data() + offset, BLOCK_SIZE);
        break;
      }

      memmove(msg.data(), buffer.data() + offset, BLOCK_SIZE);
      authenticate_message(msg);

      offset += BLOCK_SIZE;
      processed_blocks++;
    }

    if (processed_blocks == block_count - 1 && lb_len == 0) {
      break;
    }

    if (offset < bytes_read && processed_blocks == block_count) {
      const std::size_t tail_size = bytes_read - offset;
      memmove(last_block.data(), buffer.data() + offset, tail_size);
      pad_last_block(last_block, static_cast<int>(tail_size));
      XOR(last_block, MAC_key[1]);
      authenticate_message(last_block);
      file.close();
      return MAC;
    }
  }

  if (lb_len == 0) {
    memmove(last_block.data(), buffer.data() + offset, BLOCK_SIZE);
    XOR(last_block, MAC_key[0]);
    authenticate_message(last_block);
  }

  file.close();
  flush_data(buffer);

  clock_gettime(CLOCK_MONOTONIC, &end);
  long seconds_diff = end.tv_sec - start.tv_sec;
  long nanos_diff = end.tv_nsec - start.tv_nsec;

  if (nanos_diff < 0) {
    seconds_diff--;
    nanos_diff += 1000000000L;
  }

  long double time_diff = seconds_diff + nanos_diff / 1000000000.0;

  long double work_speed = file_size / time_diff;

  std::cout << "Время выработки имитовставки " << time_diff << " секунд"
            << std::endl;
  std::cout << "Скорость выработки имитовставки " << std::defaultfloat
            << work_speed / (1024.0 * 1024.0) << " МБ/c" << std::endl;

  return MAC;
}

Kuznechik::kkey_t scan_key_from_string(const std::string &key) {
  Kuznechik::kkey_t mkey{};
  if (key.size() != KEY_SIZE * 2) {
    std::cout << "Ошибка скана ключа, неверный размер" << std::endl;
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < KEY_SIZE; ++i) {
    uint8_t byte =
        static_cast<uint8_t>(std::stoi(key.substr(2 * i, 2), nullptr, 16));
    mkey[i] = byte;
  }
  return mkey;
}

// Kuznechik::kblock_t Kuznechik::process_sequence(std::vector<uint8_t>
// &filebuf) {}

/*
    Реализация метода process_sequence с поддержкой смены ключа каждые N блоков.
    Параметры:
        filename - имя файла для выработки имитовставки
        keyfile - имя файла с ключевой информацией
        key_upd_interval - количество блоков после смены ключа
*/
Kuznechik::kblock_t Kuznechik::process_sequence(const std::string &filename,
                                                const std::string &keyfile,
                                                int key_upd_interval) {
  std::fstream file;
  file.open(filename, std::ios::in | std::ios::binary);
  if (!file.is_open() || file.fail()) {
    LOG_EVENT(FILE_OPEN_FAIL, MSG_ID_OPEN_FAIL, module_name);
    std::exit(EXIT_FAILURE);
  } else {
    LOG_EVENT(FILE_OPEN_SUCCESS, MSG_ID_OPEN_SUCCESS, module_name);
  }

  std::fstream key_fs;
  key_fs.open(keyfile, std::ios::in | std::ios::binary);
  if (!key_fs.is_open() || key_fs.fail()) {
    LOG_EVENT(FILE_OPEN_FAIL, MSG_ID_OPEN_FAIL, module_name);
    std::exit(EXIT_FAILURE);
  }

  const std::size_t file_size = std::filesystem::file_size(filename);
  const std::size_t block_count = file_size / BLOCK_SIZE;
  const std::size_t lb_len = file_size % BLOCK_SIZE;

  auto key_file_size = std::filesystem::file_size(keyfile);
  auto key_count = key_file_size / KEY_SIZE;
  kkey_t *all_keys = new kkey_t[key_count];
  if (key_fs.read(reinterpret_cast<char *>(all_keys), key_file_size).gcount() !=
      key_file_size) {
    perror("Failed to read keys");
    std::exit(EXIT_FAILURE);
  }
  key_fs.close();

  kkey_t current_master_key = all_keys[0];
  
  round_key = init_round_keys(current_master_key);
  MAC_key = init_OMAC_keys();
  LOG_EVENT(KEY_DIGEST, MSG_ID_KEY_DIGEST, module_name);

  flush_master_key(all_keys[0]);
  LOG_EVENT(KEY_FLUSH, MSG_ID_KEY_FLUSH, module_name);

  std::vector<uint8_t> buffer(BUFF_SIZE);
  kblock_t msg{}, last_block{};

  std::timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);

  std::size_t processed_blocks = 0;
  std::size_t offset = 0;

  while (file.read(reinterpret_cast<char *>(buffer.data()), BUFF_SIZE) ||
         file.gcount() > 0) {
    const std::size_t bytes_read = file.gcount();

    offset = 0;
    while (offset + BLOCK_SIZE <= bytes_read &&
           processed_blocks < block_count) {
      if (processed_blocks == block_count - 1 && lb_len == 0) {
        memmove(last_block.data(), buffer.data() + offset, BLOCK_SIZE);
        break;
      }

      memmove(msg.data(), buffer.data() + offset, BLOCK_SIZE);
      authenticate_message(msg);

      if (processed_blocks > 0 && processed_blocks % key_upd_interval == 0) {
        int key_index = processed_blocks / key_upd_interval;
        if (key_index >= key_count) {
          fprintf(stderr, "Недостаточно ключевой информации для всех блоков\n");
          std::exit(EXIT_FAILURE);
        }
        current_master_key = all_keys[key_index];
        round_key = init_round_keys(current_master_key);
        MAC_key = init_OMAC_keys();
        LOG_EVENT(KEY_DIGEST, MSG_ID_KEY_DIGEST, module_name);

        flush_master_key(all_keys[key_index]);
        LOG_EVENT(KEY_FLUSH, MSG_ID_KEY_FLUSH, module_name);

      }

      offset += BLOCK_SIZE;
      processed_blocks++;
    }

    if (processed_blocks == block_count - 1 && lb_len == 0) {
      break;
    }

    if (offset < bytes_read && processed_blocks == block_count) {
      const std::size_t tail_size = bytes_read - offset;
      memmove(last_block.data(), buffer.data() + offset, tail_size);
      pad_last_block(last_block, static_cast<int>(tail_size));
      XOR(last_block, MAC_key[1]);
      authenticate_message(last_block);
      file.close();
      delete[] all_keys;
      return MAC;
    }
  }

  if (lb_len == 0) {
    memmove(last_block.data(), buffer.data() + offset, BLOCK_SIZE);
    XOR(last_block, MAC_key[0]);
    authenticate_message(last_block);
  }

  file.close();
  flush_data(buffer);
  delete[] all_keys;

  clock_gettime(CLOCK_MONOTONIC, &end);
  long seconds_diff = end.tv_sec - start.tv_sec;
  long nanos_diff = end.tv_nsec - start.tv_nsec;

  if (nanos_diff < 0) {
    seconds_diff--;
    nanos_diff += 1000000000L;
  }

  long double time_diff = seconds_diff + nanos_diff / 1000000000.0;
  long double work_speed = file_size / time_diff;

  std::cout << "Время выработки имитовставки " << time_diff << " секунд"
            << std::endl;
  std::cout << "Скорость выработки имитовставки " << std::defaultfloat
            << work_speed / (1024.0 * 1024.0) << " МБ/c" << std::endl;
  return MAC;
}

std::filesystem::path get_exe_fullpath() {
  char filename[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", filename, PATH_MAX - 1);
  if (len == -1) {
    exit(EXIT_FAILURE);
  }
  filename[len] = '\0';
  return std::filesystem::path(filename);
}

int check_integrity(const std::filesystem::path &full_path) {
  const std::string cmd = "evmctl ima_verify \"" + full_path.string() + "\" > /dev/null 2>&1";
  int status = std::system(cmd.c_str());
  return status;
}

int main() {
  
  LOG_EVENT(MODULE_STARTUP, MSG_ID_MODULE_START, module_name);

  int status = check_integrity(get_exe_fullpath());

  if (status != 0) {
    LOG_EVENT(INTEGRITY_CHECK_FAIL, MSG_ID_INTEGRITY_FAIL, module_name);
    return -1;
  } else {
    LOG_EVENT(INTEGRITY_CHECK_SUCCESS, MSG_ID_INTEGRITY_FAIL, module_name);
  }

  if (authenticate_user() != 0) {
    LOG_EVENT(AUTH_FAIL, MSG_ID_AUTH_FAIL, module_name);
    return -1;
  } else {
    LOG_EVENT(AUTH_SUCCESS, MSG_ID_AUTH_SUCCESS, module_name);
  }

  int num, key_upd_int;
  std::string keyfname, fname, mkey;
  printf("Выберите режим работы:\n 1. Выработка имитовставки \n 2. Выработка "
         "имитовставки со сменой ключа \n");
  std::cin >> num;
  if (num == 2) {
    printf("Введите имя файла\n");
    std::cin >> fname;
    printf("Введите имя файла с ключевой информацией\n");
    std::cin >> keyfname;
    printf("Введите количество блоков обрабатываемых одним ключом \n");
    std::cin >> key_upd_int;

    Kuznechik cipher{};
    Kuznechik::kblock_t MAC = cipher.process_sequence(fname, keyfname, key_upd_int);

    std::cout << "Значение имитовставки " << MAC << "\n";

  } else if (num == 1) {
    printf("Введите имя файла\n");
    std::cin >> fname;
    printf("Введите ключ\n");
    
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::cin >> mkey;
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    
    std::cout << std::endl;

    Kuznechik::kkey_t key = scan_key_from_string(mkey);

    Kuznechik cipher{key};
    Kuznechik::kblock_t MAC = cipher.process_sequence(fname);
    std::cout << "Значение имитовставки " << MAC << "\n";
  } else {
    std::cout << "Ошибка выбора меню\n";
  }

  return 0;
}
