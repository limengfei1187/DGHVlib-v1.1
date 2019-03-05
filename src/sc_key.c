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

 void init_sc_sk(__sc_prikey** prikey, __sec_setting* para){


     int i, t, b, rsub;
     int add_cnt = 0;
     int reduce_cnt = 0;

     *prikey = (__sc_prikey*)malloc(sizeof(__sc_prikey));

     //printf("Theta:%lu\nbeta:%lu\n",para->Theta,(size_t)sqrt(para->tau*1.0));
     t = (int)floor(sqrt(para->theta));
     //printf("theta:%lu\nsqrt(theta):%d\n",para->theta,t);

     if(t * 1.0 == sqrt(para->theta)){
         (*prikey)->s0_group_cnt = t;
         (*prikey)->s1_group_cnt = t;
     }

     if(para->theta <= t * (t + 1)){
         (*prikey)->s0_group_cnt = t + 1;
         (*prikey)->s1_group_cnt = t;
     }

     if((para->theta > t * (t + 1)) && (para->theta < (t + 1) * (t + 1))){
         (*prikey)->s0_group_cnt = t + 1;
         (*prikey)->s1_group_cnt = t + 1;
     }

     //printf("s0_group_cnt:%lu\ns1_group_cnt:%lu\n",(*prikey)->s0_group_cnt,(*prikey)->s1_group_cnt);

     (*prikey)->s0 = (unsigned long**)malloc((*prikey)->s0_group_cnt * sizeof(unsigned long*));
     (*prikey)->s1 = (unsigned long**)malloc((*prikey)->s1_group_cnt * sizeof(unsigned long*));

     b=(int)round(sqrt(para->Theta / ((*prikey)->s0_group_cnt * (*prikey)->s1_group_cnt) * 1.0));
     rsub=para->Theta - (*prikey)->s0_group_cnt * (*prikey)->s1_group_cnt * b * b;

     printf("b=sqrt(B):%d\n",b);

     if(rsub == 0){
         (*prikey)->every_group_length = b;
         (*prikey)->last_group_length = b;
         (*prikey)->fill_cnt = 0;
     }else if(rsub < 0){
         (*prikey)->every_group_length = b;
         reduce_cnt = (int)ceil(rsub * (-1) / ((*prikey)->s0_group_cnt*b*1.0));

         (*prikey)->last_group_length = b - reduce_cnt;
         (*prikey)->fill_cnt = reduce_cnt * (*prikey)->s0_group_cnt * b + rsub;
     }else if(rsub > 0){
         (*prikey)->every_group_length = b;
         add_cnt = (int)floor(rsub / ((*prikey)->s0_group_cnt*b*1.0)) * (-1);
         (*prikey)->last_group_length = b + add_cnt;
         (*prikey)->fill_cnt = rsub + add_cnt * (*prikey)->s0_group_cnt * b;
    }

    /*
    printf("every_group_length:%lu\n",(*prikey)->every_group_length);
    printf("last_group_length:%lu\n",(*prikey)->last_group_length);
    printf("add_cnt:%d\n",add_cnt);
    printf("reduce_cnt:%d\n",reduce_cnt);
    printf("fill_cnt:%lu\n",(*prikey)->fill_cnt);
    */

    for(i = 0; i < (*prikey)->s0_group_cnt; i++){
        (*prikey)->s0[i] = (unsigned long*)malloc(sizeof(unsigned long) * (*prikey)->every_group_length);
    }

    for(i = 0; i < (*prikey)->s1_group_cnt - 1; i++){
        (*prikey)->s1[i] = (unsigned long*)malloc(sizeof(unsigned long) * (*prikey)->every_group_length);
    }

    (*prikey)->s1[i] = (unsigned long*)malloc(sizeof(unsigned long) * (*prikey)->last_group_length);
    (*prikey)->fill_s = (unsigned long*)malloc(sizeof(unsigned long) * (*prikey)->fill_cnt);

    (*prikey)->rsub_size = para->Theta;
    (*prikey)->rsub_hw = para->theta;
    (*prikey)->sk_bit_cnt = para->eta;
 }

 void init_sc_pkset(__sc_pubkey_set** pubkey, __sc_prikey* prikey, __sec_setting* para){

     unsigned long i;
     *pubkey = (__sc_pubkey_set*)malloc(sizeof(__sc_pubkey_set));
     mpz_init((*pubkey)->x0);
     size_t beta = (size_t)sqrt(para->tau * 1.0);

     (*pubkey)->beta = beta;
     (*pubkey)->pk_vector1 = (mpz_t*)malloc(sizeof(mpz_t) * beta);
     (*pubkey)->pk_vector2 = (mpz_t*)malloc(sizeof(mpz_t) * beta);
     for(i = 0; i < beta; i++){
         mpz_init((*pubkey)->pk_vector1[i]);
         mpz_init((*pubkey)->pk_vector2[i]);
     }

     unsigned long s0_size = prikey->s0_group_cnt * prikey->every_group_length;
     unsigned long s1_size = (prikey->s1_group_cnt - 1) * prikey->every_group_length + prikey->last_group_length;

     /*
     printf("s0_size=%lu\n",s0_size);
     printf("s1_size=%lu\n",s1_size);
     */

     (*pubkey)->s0_vector = (mpz_t*)malloc(sizeof(mpz_t) * s0_size);
     for(i = 0; i < s0_size; i++) mpz_init((*pubkey)->s0_vector[i]);

     (*pubkey)->s1_vector = (mpz_t*)malloc(sizeof(mpz_t) * s1_size);
     for(i = 0; i < s1_size; i++) mpz_init((*pubkey)->s1_vector[i]);

     (*pubkey)->s_fills = (mpz_t*)malloc(sizeof(mpz_t) * prikey->fill_cnt);
     for(i = 0; i < prikey->fill_cnt; i++) mpz_init((*pubkey)->s_fills[i]);
     (*pubkey)->y = (mpf_t*)malloc(sizeof(mpf_t) * para->Theta);
     for(i = 0; i < para->Theta; i++) mpf_init((*pubkey)->y[i]);

     (*pubkey)->s0_group_cnt = prikey->s0_group_cnt;
     (*pubkey)->s1_group_cnt = prikey->s1_group_cnt;
     (*pubkey)->every_group_length = prikey->every_group_length;
     (*pubkey)->last_group_length = prikey->last_group_length;
     (*pubkey)->fill_cnt = prikey->fill_cnt;

     (*pubkey)->pks_size = beta * beta;
     (*pubkey)->y_size = para->Theta;
     (*pubkey)->pk_bit_cnt = para->gam;
 }

 void clear_sc_sk(__sc_prikey* prikey){

     unsigned long i;

     if(prikey->sk != NULL) mpz_clear(prikey->sk);

     for(i = 0; i < prikey->s0_group_cnt; i++){
         if(prikey->s0[i] != NULL){
             free(prikey->s0[i]);
         }
     }
     if(prikey->s0 != NULL) free(prikey->s0);

     for(i = 0; i < prikey->s1_group_cnt; i++){
         if(prikey->s1[i] != NULL){
             free(prikey->s1[i]);
         }
     }
     if(prikey->s1 != NULL) free(prikey->s1);

     if(prikey->fill_s != NULL) free(prikey->fill_s);
     if(prikey != NULL) free(prikey);


 }

 void clear_sc_pkset(__sc_pubkey_set* pubkey ){

     unsigned long i;

     if(pubkey->x0 != NULL) mpz_clear(pubkey->x0);


     for(i = 0; i < pubkey->beta; i++){
         if(pubkey->pk_vector1[i] != NULL){
             mpz_clear(pubkey->pk_vector1[i]);
         }
         if(pubkey->pk_vector2[i] != NULL){
             mpz_clear(pubkey->pk_vector2[i]);
         }
     }
     if(pubkey->pk_vector1 != NULL) free(pubkey->pk_vector1);
     if(pubkey->pk_vector2 != NULL) free(pubkey->pk_vector2);


     unsigned long s0_size = pubkey->s0_group_cnt * pubkey->every_group_length;
     unsigned long s1_size = (pubkey->s1_group_cnt - 1) * pubkey->every_group_length + pubkey->last_group_length;

     for(i = 0; i < s0_size; i++){
         if(pubkey->s0_vector[i] != NULL){
             mpz_clear(pubkey->s0_vector[i]);
         }
     }
     if(pubkey->s0_vector != NULL) free(pubkey->s0_vector);

     for(i = 0; i < s1_size; i++){
         if(pubkey->s1_vector[i] != NULL){
             mpz_clear(pubkey->s1_vector[i]);
         }
     }
     if(pubkey->s1_vector != NULL) free(pubkey->s1_vector);

     for(i = 0; i < pubkey->fill_cnt; i++){
         if(pubkey->s_fills[i] != NULL){
             mpz_clear(pubkey->s_fills[i]);
         }
     }
     if(pubkey->s_fills != NULL) free(pubkey->s_fills);

     for(i = 0; i < pubkey->y_size; i++){
         if(pubkey->y[i] != NULL){
             mpf_clear(pubkey->y[i]);
         }
     }
     if(pubkey->y != NULL) free(pubkey->y);

     if(pubkey != NULL) free(pubkey);
 }
