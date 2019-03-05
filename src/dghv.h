/* Copyright (C) 2018-2019 SAU Network Communication Research Room.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

 #ifndef _DGHV_H_
 #define _DGHV_H_
 #include <stdio.h>
 #include <stdlib.h>
 #include <stddef.h>
 #include <stdbool.h>
 #include <time.h>
 #include <sys/time.h>
 #include <string.h>
 #include <math.h>
 #include <gmp.h>

 #define TOY                   0
 #define SMALL                 1
 #define MEDIUM                2
 #define LARGE                 3

 #define PROB_EXP              50
 #define BASE                  2
 #define PRIHL                 7
 #define PUBHL                 8

 #define W                     (GMP_NUMB_BITS/2)
 #define _LSBMASK              1ul
 #define _MSBMASK              (1ul << (2 * W - 1))
 #define _BOT_N_MASK(n)        ((_LSBMASK << n) - 1)
 #define _TOP_N_MASK(n)        (_BOT_N_MASK(n) << (2 * W - n))

 #define R_N_SHIFT(x, n)       (x >> n)
 #define L_N_SHIFT(x, n)       (x << n)
 #define MP_EXP(x)             (x->_mp_exp)
 #define MP_SIZE(x)            (x->_mp_size)
 #define MP_PREC(x)            (x->_mp_prec)
 #define MP_ALLOC(x)           (x->_mp_alloc)
 #define LIMB(x, i)            (((i)<((x)->_mp_size))?((x)->_mp_d[i]):(0L))
 #define LSB(x)                (x & _LSBMASK)
 #define MSB(x)                (x & _MSBMASK)
 #define MSBN(x, n)            (x & (_TOP_N_MASK(n)))
 #define LSBN(x, n)            (x & (_BOT_N_MASK(n)))
 #define MIN_ETA(x)            (21 * x + 50)

 typedef struct securitySetting{
     size_t lam;
     size_t Rho;
     size_t rho;
     size_t eta;
     size_t gam;
     size_t Theta;
     size_t theta;
     size_t tau;
     size_t prec;
     size_t n;

 }__sec_setting;


 typedef struct privatekey{
     mpz_t sk;
     mpz_t* sk_rsub;
     size_t rsub_size;
     size_t rsub_hw;
     size_t sk_bit_cnt;
     char gen_time[20];
 }__prikey;

 typedef struct publickeyset{
     mpz_t x0;
     mpz_t* pks;
     mpz_t* cs;
     mpf_t* y;
     size_t pks_size;
     size_t y_size;
     size_t pk_bit_cnt;
     char gen_time[20];
 }__pubkey_set;

typedef struct sc_privatekey{
    mpz_t sk;
    unsigned long** s0;
    unsigned long** s1;
    unsigned long* fill_s;
    size_t s0_group_cnt;
    size_t s1_group_cnt;
    size_t every_group_length;
    size_t last_group_length;
    size_t fill_cnt;
    size_t rsub_size;
    size_t rsub_hw;
    size_t sk_bit_cnt;
    char gen_time[20];
}__sc_prikey;

typedef struct sc_publickeyset{
    mpz_t x0;
    mpz_t* pk_vector1;         //Xi0
    mpz_t* pk_vector2;         //Xj1
    mpz_t* s0_vector;         //S(0)向量
    mpz_t* s1_vector;         //S(1)向量
    mpz_t* s_fills;
    mpf_t* y;
    unsigned long seed;
    size_t beta;
    size_t s0_group_cnt;
    size_t s1_group_cnt;
    size_t every_group_length;
    size_t last_group_length;
    size_t fill_cnt;
    size_t pks_size;
    size_t y_size;
    size_t pk_bit_cnt;
    char gen_time[20];
}__sc_pubkey_set;

typedef struct rc_privatekey{
    mpz_t sk;
    mpz_t rsk;
    mpz_t* sk_rsub;
    size_t rsub_size;
    size_t rsub_hw;
    size_t sk_bit_cnt;
    size_t rsk_bit_cnt;
    char gen_time[20];
}__rc_prikey;

typedef struct rc_publickey_set{
    mpz_t x0;
    mpz_t rx0;
    mpz_t* delta;
    mpf_t* y;
    mpz_t** sigma;
    size_t sx;
    size_t sy;
    size_t pks_size;
    size_t y_size;
    size_t pk_bit_cnt;
    char gen_time[20];
    unsigned long seed;
}__rc_pubkey_set;


 typedef struct ciphertext{
     mpz_t c;
     mpf_t *z;
     mpz_t *zt;
     size_t z_size;

 }__cit;   //ciphertext

 typedef struct hamming_weight_table{
     mpz_t **table;
     size_t x;
     size_t y;
 }__hw_table;

 typedef struct evaluation_table{
     mpz_t **table;
     size_t x;
     size_t y;
 }__ev_table;

 typedef gmp_randstate_t  randstate;
 typedef __prikey*        c_prikey;
 typedef __sc_prikey*     sc_prikey;
 typedef __rc_prikey*     rc_prikey;
 typedef __pubkey_set*    c_pubkeys;
 typedef __sc_pubkey_set* sc_pubkeys;
 typedef __rc_pubkey_set* rc_pubkeys;
 typedef __sec_setting*   c_parameters;
 typedef __cit*           c_cit;


/**************** Security Parameters Setting.  ****************/

 void init_sec_para(__sec_setting** para);

 void set_default_para(__sec_setting* para, int level);

 bool para_valid(__sec_setting* para);

/****************  Initialized Key.  ****************/

 void init_sk(__prikey** prikey, __sec_setting* para);

 void init_pkset(__pubkey_set** pubkey, __sec_setting* para);

 void clear_sk(__prikey* prikey);

 void clear_pkset(__pubkey_set* pubkey);


 /****************  Initialized Square Compress Key.  ****************/

 void init_sc_sk(__sc_prikey** prikey, __sec_setting* para);

 void init_sc_pkset(__sc_pubkey_set** pubkey, __sc_prikey* prikey, __sec_setting* para);

 void clear_sc_sk(__sc_prikey* prikey);

 void clear_sc_pkset(__sc_pubkey_set* pubkey );


 /****************  Initialized Ramdom Compress Key.  ****************/

void init_rc_sk(__rc_prikey** prikey, __sec_setting* para);

void init_rc_pkset(__rc_pubkey_set** pubkey, __sec_setting* para);

void clear_rc_sk(__rc_prikey* prikey);

void clear_rc_pkset(__rc_pubkey_set* pubkey);

/****************  Generated Ramdom Number.  ****************/

 unsigned long get_seed();

 void set_randstate(randstate rs, unsigned long seed);

 void gen_rrandomb(mpz_t rn, randstate rs, unsigned long n);

 void gen_urandomm(mpz_t rn, randstate rs, mpz_t ub);


/****************  Generated Square Compress Private Key & Public Key.  ****************/

 void randomize_scs(__sc_prikey* prikey);

 void gen_sc_prikey(__sc_prikey* prikey, randstate rs);

 void expand_sc_p2y(__sc_pubkey_set* pubkey, __sc_prikey* prikey, size_t prec, randstate rs);

 void scXX(__sc_pubkey_set* pubkey, unsigned long index, randstate rs, size_t Rho, int type);

 void encrypt_sc_sk(__sc_pubkey_set* pubkey, __sc_prikey* prikey, randstate rs, size_t Rho);

 void gen_sc_pubkey(__sc_pubkey_set* pubkey, __sc_prikey* prikey, __sec_setting* para, randstate rs, int model);


 /****************  Generated Random Compress Private Key & Public Key.  ****************/

  void gen_rc_prikey(__rc_prikey* prikey, randstate rs);

  void gen_rc_pubkey(__rc_pubkey_set* pubkey, __rc_prikey* prikey, __sec_setting* para);

  void randomize_rsk(mpz_t* yy, mpz_t p, size_t rsk_bit_cnt, size_t ss_hw, size_t prec);

  void expand_rc_p2y(__rc_pubkey_set* pubkey, __rc_prikey* prikey, size_t prec, randstate rs);


 /****************  Generated Private Key & Public Key.  ****************/

 void gen_prime(mpz_t p, size_t n, randstate rs);

 void mpf_round_mpz(mpz_t rop, mpf_t op);

 void div_round_q(mpz_t q, mpz_t  n, mpz_t d);

 bool is_a_rough(mpz_t a, mpz_t b);

 void getQs(mpz_t* q, mpz_t p, size_t gam, size_t tau, size_t lam, randstate rs);

 void randomize_ss(mpz_t* ss, size_t ss_hw, size_t ss_size);

 void randomize_sk(mpz_t* yy, mpz_t p, size_t ss_hw, size_t prec);

 void expand_p2y(__pubkey_set* pubkey, __prikey* prikey, size_t prec, randstate rs);

 void gen_prikey(__prikey* prikey, randstate rs);

 void gen_pubkey(__pubkey_set* pubkey, __prikey* prikey, __sec_setting* para, randstate rs, int model);


/****************  Initialized Ciphertext.  ****************/

 void init_cit(__cit** ciph, size_t Theta);

 void expend_cit(__cit* ciph, __pubkey_set* pubkey);

 void expend_sc_cit(__cit* ciph, __sc_pubkey_set* pubkey);

 void expend_rc_cit(__cit* ciph, __rc_pubkey_set* pubkey, unsigned long rsk_bit_cnt);

 void clear_cit(__cit* ciph);

 void swap_cit(__cit* ciph1, __cit* ciph2);


/****************  Encrypt & Decrypt.  ****************/

 void DGHV_encrypt(__cit* ciphertext, unsigned long plaintext, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

 unsigned long DGHV_decrypt(__cit* ciphertext, __prikey* prikey);

 void CMNT_encrypt(__cit* ciphertext, unsigned long plaintext, __sc_pubkey_set* pubkey, __sec_setting* para, randstate rs);

 unsigned long CMNT_decrypt(__cit* ciphertext, __sc_prikey* prikey);

 void CNT_encrypt(__cit* ciphertext, unsigned long plaintext, __rc_pubkey_set* pubkey, __sec_setting* para);

 unsigned long CNT_decrypt(__cit* ciphertext, __rc_prikey* prikey);


/****************  Squashed Decrypt Circuitry.  ****************/

 void init_hw_table(__hw_table** hwtable, size_t x, size_t y);

 void init_ev_table(__ev_table** evtable, size_t x, size_t y);

 void clear_hw_table(__hw_table* hwtable);

 void clear_ev_table(__ev_table* evtable);

 void set_ev_table(unsigned long i, mpf_t z, __ev_table* ev_table);

 void get_hw(int i, __ev_table* ev_table, __sec_setting* para);

 unsigned long get_ciph_lsb(__cit* ciph);

 unsigned long get_ciphdivp_lsb(__cit* ciph, __prikey* prikey, __sec_setting* para);

 unsigned long get_sc_ciphdivp_lsb(__cit* ciph, __sc_prikey* prikey, __sec_setting* para);


/****************  Evaluated Addition & Multiplication.  ****************/

 void evaluate_add(__cit* sum, __cit* c1, __cit* c2, mpz_t x0);

 void evaluate_mul(__cit* product, __cit* c1, __cit* c2, mpz_t x0);


/****************  Bootstrapping.  ****************/

 void c_get_hw(int i, __ev_table* ev_table, __sec_setting* para, mpz_t x0);

 void c_get_ciph_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

 void c_get_ciphdivp_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para);

 void bootstrap(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);

 void c_get_sc_ciph_lsb(__cit* cc, __cit* ciph, __sc_pubkey_set* pubkey, __sec_setting* para, randstate rs);

 void c_get_sc_ciphdivp_lsb(__cit* cc, __cit* ciph, __sc_pubkey_set* pubkey, __sec_setting* para);

 void sc_bootstrap(__cit* cc, __cit* ciph, __sc_pubkey_set* pubkey, __sec_setting* para, randstate rs);


/****************  Key Switching.  ****************/

void Powersof2(mpf_t** s_expand, mpz_t* s, unsigned long length, unsigned long k);

void gen_switch_key(__rc_prikey* prikey, __rc_pubkey_set* pubkey, __sec_setting* para);


/****************  Modulus Switching.  ****************/

void BitDecomp(unsigned long** c_expand, mpz_t* z, unsigned long length, unsigned long k);

void mod_switch(__cit* new, __cit* old, __rc_pubkey_set* pubkey, __sec_setting* para);


/****************  Base64 Encode & Decode.  ****************/

//int base64_encode(char *indata, int inlen, char *outdata, int *outlen);

int base64_encode(char *in, int inlen, char *out);

//int base64_decode(char *indata, int inlen, char *outdata, int *outlen);

int base64_decode(char *in, int inlen, char *out) ;


/****************  Format Ciphertext & Key Convert into String.  ****************/

char* format_ciphertext_str(__cit* ciph);

int format_privatekey_str(__prikey* prikey, char** buffer, int *length);

int format_publickey_str(__pubkey_set* pubkey, char** buffer, int *length);


/****************  Format String Convert into Ciphertext & Key.  ****************/

int format_str_ciphertext(char* buffer,  __cit* ciph);

int format_str_privatekey(char** buffer, int length, __prikey* prikey);

int format_str_publickey(char** buffer, int length, __pubkey_set* pubkey);


/****************  Read & Write Key.  ****************/

int save_sec_para(__sec_setting* para, const char* filename);

int save_prikey(__prikey* prikey, const char* prikey_filename);

int save_pubkey(__pubkey_set* pubkey, const char* pubkey_filename);

int save_str(char** buffer, int length, const char* filename);

int read_sec_para(__sec_setting* para, const char* filename);

int read_prikey(__prikey* prikey, const char* prikey_filename);

int read_pubkey(__pubkey_set* pubkey, const char* pubkey_filename);

char** read_str(const char* filename);

 #endif
