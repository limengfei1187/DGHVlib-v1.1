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

 void init_rc_sk(__rc_prikey** prikey, __sec_setting* para){
     unsigned long i;
     *prikey = (__rc_prikey*)malloc(sizeof(__rc_prikey));
     //(*prikey)->sk_rsub = (mpz_t*)malloc(para->Theta * sizeof(mpz_t));

     mpz_init((*prikey)->sk);
     mpz_init((*prikey)->rsk);
     (*prikey)->sk_rsub = (mpz_t*)malloc(para->Theta * sizeof(mpz_t));
     for(i = 0; i < para->Theta; i++){
         mpz_init_set_ui((*prikey)->sk_rsub[i], 0);
     }
     (*prikey)->rsub_size = para->Theta;
     (*prikey)->rsub_hw = para->theta;
     (*prikey)->sk_bit_cnt = para->eta;
     (*prikey)->rsk_bit_cnt = para->eta - para->Rho;
 }

 void init_rc_pkset(__rc_pubkey_set** pubkey, __sec_setting* para){

     unsigned long i, j;
     *pubkey = (__rc_pubkey_set*)malloc(sizeof(__rc_pubkey_set));

     mpz_init((*pubkey)->x0);
     mpz_init((*pubkey)->rx0);
     (*pubkey)->delta = (mpz_t*)malloc(sizeof(mpz_t) * para->tau);
     for(i = 0; i < para->tau; i++){
         mpz_init((*pubkey)->delta[i]);
     }

     (*pubkey)->y = (mpf_t*)malloc(sizeof(mpf_t) * para->Theta);
     for(i = 0; i < para->Theta; i++){
         mpf_init((*pubkey)->y[i]);
     }

     (*pubkey)->sigma = (mpz_t**)malloc(sizeof(mpz_t*) *(para->eta - para->Rho + 1));
     for(i = 0; i < para->eta - para->Rho + 1; i++){
         (*pubkey)->sigma[i] = (mpz_t*)malloc(sizeof(mpz_t) * para->Theta);
         for(j = 0; j < para->Theta; j++){
             mpz_init_set_ui((*pubkey)->sigma[i][j], 0);
         }
     }

     (*pubkey)->sx = para->eta - para->Rho + 1;
     (*pubkey)->sy = para->Theta;
     (*pubkey)->pks_size = para->tau;
     (*pubkey)->y_size = para->Theta;
     (*pubkey)->pk_bit_cnt = para->gam;
 }

 void clear_rc_sk(__rc_prikey* prikey){

     unsigned long i;
     mpz_clear(prikey->sk);
     mpz_clear(prikey->rsk);
     for(i = 0; i < prikey->rsub_size; i++){
         mpz_clear(prikey->sk_rsub[i]);
     }
     if(prikey->sk_rsub != NULL) free(prikey->sk_rsub);
     free(prikey);
 }

 void clear_rc_pkset(__rc_pubkey_set* pubkey){
     unsigned long i, j;
     mpz_clear(pubkey->x0);
     mpz_clear(pubkey->rx0);
     for(i = 0; i < pubkey->pks_size; i++){
         mpz_clear(pubkey->delta[i]);
     }
     free(pubkey->delta);

     for(i = 0; i < pubkey->y_size; i++){
         mpf_clear(pubkey->y[i]);
     }
     free(pubkey->y);

     for(i = 0; i < pubkey->sx; i++){
         for(j = 0; j < pubkey->sy; j++){
             mpz_clear(pubkey->sigma[i][j]);
         }
         if(pubkey->sigma[i] != NULL) free(pubkey->sigma[i]);
     }
     if(pubkey->sigma != NULL) free(pubkey->sigma);
     free(pubkey);
 }
