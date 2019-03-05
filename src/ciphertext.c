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

 void init_cit(__cit** ciph, size_t Theta){
     unsigned long i;
     *ciph = (__cit*)malloc(sizeof(__cit));
     (*ciph)->z = (mpf_t*)malloc(Theta * sizeof(mpf_t));
     (*ciph)->zt = (mpz_t*)malloc(Theta * sizeof(mpz_t));
     mpz_init((*ciph)->c);
     for(i = 0; i < Theta; i++){
         mpf_init((*ciph)->z[i]);
         mpz_init((*ciph)->zt[i]);
     }
     (*ciph)->z_size = Theta;
 }


 void expend_cit(__cit* ciph, __pubkey_set* pubkey){
     unsigned long i;
     mpf_t zz;
     mpf_init(zz);
     mpf_set_z(zz, ciph->c);
     for(i = 0; i < ciph->z_size; i++){
         mpf_mul(ciph->z[i], zz, pubkey->y[i]);
     }
     mpf_clear(zz);
 }

 void expend_sc_cit(__cit* ciph, __sc_pubkey_set* pubkey){
     unsigned long i;
     mpf_t zz;
     mpf_init(zz);
     mpf_set_z(zz, ciph->c);
     for(i = 0; i < ciph->z_size; i++){
         mpf_mul(ciph->z[i], zz, pubkey->y[i]);
     }
     mpf_clear(zz);
 }

 static void mpf_round2_mpz(mpz_t rop,mpf_t op, unsigned long kappa){
    int i,length;
    mpf_t a,b;
    char *str;
    mpf_init(a);
    mpf_init(b);
    str=(char *)malloc((2*kappa)*sizeof(char));
    mp_exp_t exponent;

    mpf_trunc(a,op);
    mpf_sub(b,op,a);
    if(mpf_cmp_d(b,0.5)>=0){
        mpf_add_ui(a,a,1);
        mpf_get_str(str,&exponent,2,0,a);
    }else{
        mpf_get_str(str,&exponent,2,0,a);
    }
    length = strlen(str);


    for(i=0;i<exponent-length;i++){
        strcat(str,"0");
    }
    mpz_set_str(rop,str,2);
    free(str);
    mpf_clear(a);
    mpf_clear(b);
}

 void expend_rc_cit(__cit* ciph, __rc_pubkey_set* pubkey, unsigned long rsk_bit_cnt){
     unsigned long i;
     mpf_t zz;
     mpf_t cz;
     mpz_t bz;
     mpf_init(zz);
     mpf_init(cz);
     mpz_init(bz);

     mpz_ui_pow_ui(bz, 2, rsk_bit_cnt + 1);
     mpf_set_z(zz, ciph->c);
     for(i = 0; i < ciph->z_size; i++){

         mpf_mul(cz, zz, pubkey->y[i]);
         mpf_round2_mpz(ciph->zt[i], cz, pubkey->pk_bit_cnt);
         mpz_mod(ciph->zt[i], ciph->zt[i], bz);


     }
     mpf_clear(zz);
     mpf_clear(cz);
     mpz_clear(bz);
 }


 void clear_cit(__cit* ciph){
     unsigned long i;
     mpz_clear(ciph->c);
     if(ciph->z != NULL){
         for(i = 0; i < ciph->z_size; i++){
             mpf_clear(ciph->z[i]);
         }
         free(ciph->z);
     }

     if(ciph->zt != NULL){
         for(i = 0; i < ciph->z_size; i++){
             mpz_clear(ciph->zt[i]);
         }
         free(ciph->zt);
     }

     free(ciph);
 }

 void swap_cit(__cit* ciph1, __cit* ciph2){
     mpz_swap(ciph1->c, ciph2->c);
 }
