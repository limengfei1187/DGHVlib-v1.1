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

#include "dghv.h"

void DGHV_encrypt(__cit* ciphertext, unsigned long plaintext, __pubkey_set* pubkey, __sec_setting* para, randstate rs){

 	unsigned long i, r;
 	mpz_t rn;
 	mpz_init(rn);

 	for(i = 0; i < para->lam / 2; i++){
        do{
            gen_rrandomb(rn, rs, para->lam / 2);
            mpz_mod_ui(rn, rn, para->tau + 1);
     		r = mpz_get_ui(rn);
        }while(r == 0);
 		mpz_add(ciphertext->c,ciphertext->c,pubkey->pks[r]);
 	}
 	mpz_mul_ui(ciphertext->c,ciphertext->c,2);
 	mpz_mod(ciphertext->c,ciphertext->c,pubkey->pks[0]);
 	gen_rrandomb(rn,rs, para->Rho);
 	mpz_mul_ui(rn,rn,2);
 	mpz_add_ui(rn,rn,plaintext);
 	mpz_add(ciphertext->c,ciphertext->c,rn);
 	mpz_clear(rn);
 }


 unsigned long DGHV_decrypt(__cit* ciphertext, __prikey* prikey){
 	mpz_t plaintext;
 	mpz_init(plaintext);
 	mpz_mod(plaintext,ciphertext->c,prikey->sk);
 	mpz_mod_ui(plaintext,plaintext,2);
    unsigned long pl = mpz_get_ui(plaintext);
    mpz_clear(plaintext);
 	return pl;
 }

 void CMNT_encrypt(__cit* ciphertext, unsigned long plaintext, __sc_pubkey_set* pubkey, __sec_setting* para, randstate rs){
     unsigned long i, r1, r2;
  	 mpz_t rn;
     mpz_t pro;
     mpz_init(pro);
  	 mpz_init(rn);

     for(i = 0; i < para->lam / 2; i++){

         gen_rrandomb(rn, rs, para->lam / 2);
         mpz_mod_ui(rn, rn, pubkey->beta);
         r1 = mpz_get_ui(rn);

         gen_rrandomb(rn, rs, para->lam / 2);
         mpz_mod_ui(rn, rn, pubkey->beta);
         r2 = mpz_get_ui(rn);

         mpz_mul(pro, pubkey->pk_vector1[r1], pubkey->pk_vector2[r2]);
         mpz_add(ciphertext->c, ciphertext->c, pro);
     }

     mpz_mul_ui(ciphertext->c, ciphertext->c, 2);
     mpz_mod(ciphertext->c,ciphertext->c,pubkey->x0);
  	 gen_rrandomb(rn,rs, para->Rho);
  	 mpz_mul_ui(rn,rn,2);
     mpz_add_ui(rn,rn,plaintext);
  	 mpz_add(ciphertext->c,ciphertext->c,rn);

     mpz_clear(rn);
     mpz_clear(pro);
 }

 unsigned long CMNT_decrypt(__cit* ciphertext, __sc_prikey* prikey){
 	 mpz_t plaintext;
 	 mpz_init(plaintext);
 	 mpz_mod(plaintext,ciphertext->c,prikey->sk);
 	 mpz_mod_ui(plaintext,plaintext,2);
     unsigned long pl = mpz_get_ui(plaintext);
     mpz_clear(plaintext);
 	 return pl;
 }

 void CNT_encrypt(__cit* ciphertext, unsigned long plaintext, __rc_pubkey_set* pubkey, __sec_setting* para){

  	unsigned long i;
    int r, index;
    randstate rs_rnd, rs_pks;
    mpz_t pk, pki, rnd, u_pks, u_rnd;

    set_randstate(rs_pks, pubkey->seed);
    set_randstate(rs_rnd, pubkey->seed * 2);
  	mpz_init(rnd);
    mpz_init_set_ui(pk, 0);
    mpz_init(pki);
    mpz_init(u_pks);
    mpz_init(u_rnd);

    mpz_ui_pow_ui(u_pks, BASE, pubkey->pk_bit_cnt);
    mpz_ui_pow_ui(u_rnd, BASE, para->Rho);

    for(i = 0; i < para->lam / 4; i++){

        set_randstate(rs_pks, pubkey->seed);
        gen_urandomm(rnd, rs_rnd, u_rnd);

        index = r = (int)(mpz_get_ui(rnd) % para->tau);

        while(r >= 0){
            
            gen_urandomm(pki, rs_pks, u_pks);
            r--;
        }

        mpz_sub(pki, pki, pubkey->delta[index]);
        mpz_add(pk, pk, pki);
    }

    mpz_mul_ui(pk, pk, 2);
    mpz_mod(pk, pk, pubkey->x0);
    gen_urandomm(rnd, rs_rnd, u_rnd);
    mpz_mul_ui(rnd, rnd, 2);
    mpz_add_ui(rnd, rnd, plaintext);
    mpz_add(ciphertext->c, rnd, pk);

    mpz_clear(pk);
    mpz_clear(pki);
    mpz_clear(rnd);
    mpz_clear(u_pks);
    mpz_clear(u_rnd);
  }

  unsigned long CNT_decrypt(__cit* ciphertext, __rc_prikey* prikey){
      mpz_t plaintext;
      mpz_init(plaintext);
      mpz_mod(plaintext,ciphertext->c,prikey->sk);
      mpz_mod_ui(plaintext,plaintext,2);
      unsigned long pl = mpz_get_ui(plaintext);
      mpz_clear(plaintext);
      return pl;
  }
