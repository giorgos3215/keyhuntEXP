/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "libbase58.h"
#include "rmd160.h"
#include "oldbloom.h"
#include "bloom.h"
#include "sha3.h"
#include "util.h"

#include "SECP256K1.h"
#include "Point.h"
#include "Int.h"
#include "IntGroup.h"
#include "Random.h"

#include "sha256.h"
#include "ripemd160.h"

#if defined(_WIN64) && !defined(__CYGWIN__)
#include "getopt.h"
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#endif

#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#endif
#endif

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3
#define MODE_PUB2RMD 4
#define MODE_MINIKEYS 5
#define MODE_VANITY 6

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2

uint32_t  THREADBPWORKLOAD = 1048576;

struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

struct bPload	{
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};

#if defined(_WIN64) && !defined(__CYGWIN__)
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
PACK(struct publickey
{
	uint8_t parity;
	union {
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
});
#else
struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};
#endif

const char *Ccoinbuffer_default = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char *Ccoinbuffer = (char*) Ccoinbuffer_default;
char *str_baseminikey = NULL;
char *raw_baseminikey = NULL;
char *minikeyN = NULL;
int minikey_n_limit;

const char *version = "0.2.230519 Satoshi Quest";

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

void menu();
void init_generator();

int searchbinary(struct address_value *buffer,char *data,int64_t array_length);
void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a,struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);

void bsgs_sort(struct bsgs_xvalue *arr,int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);

int bsgs_searchbinary(struct bsgs_xvalue *arr,char *data,int64_t array_length,uint64_t *r_value);
int bsgs_secondcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);
int bsgs_thirdcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);

void sha256sse_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
void sha256sse_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);

bool vanityrmdmatch(unsigned char *rmdhash);
void writevanitykey(bool compress,Int *key);
int addvanity(char *target);
int minimum_same_bytes(unsigned char* A,unsigned char* B, int length);

void writekey(bool compressed,Int *key);
void writekeyeth(Int *key);

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

bool isBase58(char c);
bool isValidBase58String(char *str);

bool readFileAddress(char *fileName);
bool readFileVanity(char *fileName);
bool forceReadFileAddress(char *fileName);
bool forceReadFileAddressEth(char *fileName);
bool forceReadFileXPoint(char *fileName);
bool processOneVanity();

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);

void writeFileIfNeeded(const char *fileName);

void calcualteindex(int i,Int *key);
#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_vanity(LPVOID vargp);
DWORD WINAPI thread_process_minikeys(LPVOID vargp);
DWORD WINAPI thread_process(LPVOID vargp);
DWORD WINAPI thread_process_bsgs(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_backward(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_both(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_random(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_dance(LPVOID vargp);
DWORD WINAPI thread_bPload(LPVOID vargp);
DWORD WINAPI thread_bPload_2blooms(LPVOID vargp);
#else
void *thread_process_vanity(void *vargp);
void *thread_process_minikeys(void *vargp);
void *thread_process(void *vargp);
void *thread_process_bsgs(void *vargp);
void *thread_process_bsgs_backward(void *vargp);
void *thread_process_bsgs_both(void *vargp);
void *thread_process_bsgs_random(void *vargp);
void *thread_process_bsgs_dance(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPload_2blooms(void *vargp);
#endif

char *pubkeytopubaddress(char *pkey,int length);
void pubkeytopubaddress_dst(char *pkey,int length,char *dst);
void rmd160toaddress_dst(char *rmd,char *dst);
void set_minikey(char *buffer,char *rawbuffer,int length);
bool increment_minikey_index(char *buffer,char *rawbuffer,int index);
void increment_minikey_N(char *rawbuffer);

void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst);
void generate_binaddress_eth(Point &publickey,unsigned char *dst_address);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] = {"sequential","backward","both","random","dance"};
const char *modes[7] = {"xpoint","address","bsgs","rmd160","pub2rmd","minikeys","vanity"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_fileName = "addresses.txt";

#if defined(_WIN64) && !defined(__CYGWIN__)
HANDLE* tid = NULL;
HANDLE write_keys;
HANDLE write_random;
HANDLE bsgs_thread;
HANDLE *bPload_mutex = NULL;
#else
pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;
pthread_mutex_t *bPload_mutex = NULL;
#endif

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;

uint8_t byte_encode_crypto = 0x00;		/* Bitcoin  */


int vanity_rmd_targets = 0;
int vanity_rmd_total = 0;
int *vanity_rmd_limits = NULL;
uint8_t ***vanity_rmd_limit_values_A = NULL,***vanity_rmd_limit_values_B = NULL;
int vanity_rmd_minimun_bytes_check_length = 999999;
char **vanity_address_targets = NULL;
struct bloom *vanity_bloom = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;

Int OUTPUTSECONDS;

int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;

int FLAGBLOOMMULTIPLIER = 1;
int FLAGVANITY = 0;
int FLAGBASEMINIKEY = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;


int FLAGSTRIDE = 0;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGRAWDATA	= 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;

int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
BSGS Variables
*/
int *bsgs_found;
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;

uint64_t bytes;
char checksum[32],checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;

struct oldbloom oldbloom_bP;

struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd; //2nd Bloom filter check
struct bloom *bloom_bPx3rd; //3rd Bloom filter check

struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;

#if defined(_WIN64) && !defined(__CYGWIN__)
std::vector<HANDLE> bloom_bP_mutex;
std::vector<HANDLE> bloom_bPx2nd_mutex;
std::vector<HANDLE> bloom_bPx3rd_mutex;
#else
pthread_mutex_t *bloom_bP_mutex;
pthread_mutex_t *bloom_bPx2nd_mutex;
pthread_mutex_t *bloom_bPx3rd_mutex;
#endif




uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;
uint64_t bsgs_m3;
uint64_t bsgs_aux;
uint32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];




Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_N_double;
Int BSGS_M;					//M is squareroot(N)
Int BSGS_M_double;
Int BSGS_M2;				//M2 is M/32
Int BSGS_M2_double;			//M2_double is M2 * 2
Int BSGS_M3;				//M3 is M2/32
Int BSGS_M3_double;			//M3_double is M3 * 2

Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;			//MP values this is m * P
Point BSGS_MP2;			//MP2 values this is m2 * P
Point BSGS_MP3;			//MP3 values this is m3 * P

Point BSGS_MP_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP2_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP3_double;			//MP3 values this is m3 * P * 2


std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp,point_temp2;	//Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Int lambda,lambda2,beta,beta2;

Secp256K1 *secp;

/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "util.h"
#include "hashing.h"

#include "gmp256k1/GMP256K1.h"
#include "gmp256k1/Point.h"
#include "gmp256k1/Int.h"
#include "gmp256k1/IntGroup.h"
#include "gmp256k1/Random.h"


#if defined(_WIN64) && !defined(__CYGWIN__)
#include "getopt.h"
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#endif

#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#endif
#endif

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3
#define MODE_PUB2RMD 4
#define MODE_MINIKEYS 5
#define MODE_VANITY 6

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2

uint32_t  THREADBPWORKLOAD = 1048576;

struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

struct bPload	{
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};

#if defined(_WIN64) && !defined(__CYGWIN__)
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
PACK(struct publickey
{
	uint8_t parity;
	union {
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
});
#else
struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};
#endif

const char *Ccoinbuffer_default = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char *Ccoinbuffer = (char*) Ccoinbuffer_default;
char *str_baseminikey = NULL;
char *raw_baseminikey = NULL;
char *minikeyN = NULL;
int minikey_n_limit;

const char *version = "0.2.230519 Satoshi Quest (legacy)";

#define CPU_GRP_SIZE 1024
//reserve
std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

void menu();
void init_generator();

int searchbinary(struct address_value *buffer,char *data,int64_t array_length);
void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a,struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);

void bsgs_sort(struct bsgs_xvalue *arr,int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);

int bsgs_searchbinary(struct bsgs_xvalue *arr,char *data,int64_t array_length,uint64_t *r_value);
int bsgs_secondcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);
int bsgs_thirdcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);

void sha256sse_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
void sha256sse_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);

bool vanityrmdmatch(unsigned char *rmdhash);
void writevanitykey(bool compress,Int *key);
int addvanity(char *target);
int minimum_same_bytes(unsigned char* A,unsigned char* B, int length);

void writekey(bool compressed,Int *key);
void writekeyeth(Int *key);

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

bool isBase58(char c);
bool isValidBase58String(char *str);

bool readFileAddress(char *fileName);
bool readFileVanity(char *fileName);
bool forceReadFileAddress(char *fileName);
bool forceReadFileAddressEth(char *fileName);
bool forceReadFileXPoint(char *fileName);
bool processOneVanity();

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);

void writeFileIfNeeded(const char *fileName);

void calcualteindex(int i,Int *key);

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_vanity(LPVOID vargp);
DWORD WINAPI thread_process_minikeys(LPVOID vargp);
DWORD WINAPI thread_process(LPVOID vargp);
DWORD WINAPI thread_process_bsgs(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_backward(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_both(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_random(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_dance(LPVOID vargp);
DWORD WINAPI thread_bPload(LPVOID vargp);
DWORD WINAPI thread_bPload_2blooms(LPVOID vargp);
DWORD WINAPI thread_pub2rmd(LPVOID vargp);
#else
void *thread_process_vanity(void *vargp);
void *thread_process_minikeys(void *vargp);
void *thread_process(void *vargp);
void *thread_process_bsgs(void *vargp);
void *thread_process_bsgs_backward(void *vargp);
void *thread_process_bsgs_both(void *vargp);
void *thread_process_bsgs_random(void *vargp);
void *thread_process_bsgs_dance(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPload_2blooms(void *vargp);
void *thread_pub2rmd(void *vargp);
#endif

char *pubkeytopubaddress(char *pkey,int length);
void pubkeytopubaddress_dst(char *pkey,int length,char *dst);
void rmd160toaddress_dst(char *rmd,char *dst);
void set_minikey(char *buffer,char *rawbuffer,int length);
bool increment_minikey_index(char *buffer,char *rawbuffer,int index);
void increment_minikey_N(char *rawbuffer);


void generate_binaddress_eth(Point &publickey,unsigned char *dst_address);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] = {"sequential","backward","both","random","dance"};
const char *modes[7] = {"xpoint","address","bsgs","rmd160","pub2rmd","minikeys","vanity"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_fileName = "addresses.txt";

#if defined(_WIN64) && !defined(__CYGWIN__)
HANDLE* tid = NULL;
HANDLE write_keys;
HANDLE write_random;
HANDLE bsgs_thread;
HANDLE *bPload_mutex;
#else
pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;
pthread_mutex_t *bPload_mutex;
#endif

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;

uint8_t byte_encode_crypto = 0x00;		/* Bitcoin  */


int vanity_rmd_targets = 0;
int vanity_rmd_total = 0;
int *vanity_rmd_limits = NULL;
uint8_t ***vanity_rmd_limit_values_A = NULL,***vanity_rmd_limit_values_B = NULL;
int vanity_rmd_minimun_bytes_check_length = 999999;
char **vanity_address_targets = NULL;
struct bloom *vanity_bloom = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;

Int OUTPUTSECONDS;

int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;

int FLAGBLOOMMULTIPLIER = 1;
int FLAGVANITY = 0;
int FLAGBASEMINIKEY = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;


int FLAGSTRIDE = 0;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGRAWDATA	= 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;

int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
BSGS Variables
*/
int *bsgs_found;
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;

uint64_t bytes;
char checksum[32],checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;

struct oldbloom oldbloom_bP;

struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd; //2nd Bloom filter check
struct bloom *bloom_bPx3rd; //3rd Bloom filter check

struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;

#if defined(_WIN64) && !defined(__CYGWIN__)
std::vector<HANDLE> bloom_bP_mutex;
std::vector<HANDLE> bloom_bPx2nd_mutex;
std::vector<HANDLE> bloom_bPx3rd_mutex;
#else
pthread_mutex_t *bloom_bP_mutex;
pthread_mutex_t *bloom_bPx2nd_mutex;
pthread_mutex_t *bloom_bPx3rd_mutex;
#endif




uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;
uint64_t bsgs_m3;
unsigned long int bsgs_aux;
uint32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];




Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_N_double;
Int BSGS_M;					//M is squareroot(N)
Int BSGS_M_double;
Int BSGS_M2;				//M2 is M/32
Int BSGS_M2_double;			//M2_double is M2 * 2
Int BSGS_M3;				//M3 is M2/32
Int BSGS_M3_double;			//M3_double is M3 * 2

Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;			//MP values this is m * P
Point BSGS_MP2;			//MP2 values this is m2 * P
Point BSGS_MP3;			//MP3 values this is m3 * P

Point BSGS_MP_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP2_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP3_double;			//MP3 values this is m3 * P * 2



std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp,point_temp2;	//Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Int lambda,lambda2,beta,beta2;

Secp256K1 *secp;
