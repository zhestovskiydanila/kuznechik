# Kuznechik OMAC
Моя реализация алгоритма Кузнечик ГОСТ 34.12-2015 в режиме выработки имитовставки ГОСТ 34.13-2015

My implementation of Kuznechik algorithm as in GOST R 34.12-2015, OMAC mode as listed in GOST R 34.13-2015 

> :warning: Disclaimer
> 
> Данный проект является учебной реализацией и не предполагает коммерческого использования. Используйте на свой страх и риск.
>
> This is an educational project and hereby is not supposed to be used in commercial products. Consider your risks when using it.

Код написан на C++ и использует стандартную библиотеку ОС Linux (PAM, systemd-journal) и процессорные инструкции SSE (заголовочный файл immintrin.h)
Компиляция производится следующей командой: g++ -03 -std=c++17 -funroll-loops -march=native -mtune=native -lsystemd -lpam kuznechik.cpp -o kuznechik_mac
Так же следует создать ключ и сертификат для цифровой подписи с помощью openssl и установить пакет ima-evm-utils для подписи файла (без подписи файл будет блокировать запуск).
Ключ и сертификат следует разместить в /etc/keys с именами privkey_evm.pem и x509_evm.der соответственно
