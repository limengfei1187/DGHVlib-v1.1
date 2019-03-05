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



void randomize_scs(__sc_prikey* prikey){

    unsigned long i, j, length, tag;
    unsigned long  seed = get_seed();

    srand(seed);
    for(i=0; i < prikey->s1_group_cnt; i++){
        printf("prikey->s1:[%lu]  ",i);
        if(i != prikey->s1_group_cnt - 1){
            length = prikey->every_group_length;
        }else{
            length = prikey->last_group_length;

        }
        if(i == prikey->s1_group_cnt - 1){
            tag = 0;
            prikey->s1[i][tag] = 1;
        }else{

            tag = rand() % length;
            prikey->s1[i][tag] = 1;
        }
        for(j = 0; j < length; j++){
            if(j != tag){
                prikey->s1[i][j] = 0;
            }
            printf("%lu  ", prikey->s1[i][j]);

        }
        printf("\n");

    }

    for(i = 0; i < prikey->s0_group_cnt; i++){
        printf("prikey->s0:[%lu]  ",i);
        length = prikey->every_group_length;
        tag = rand() % length;
        prikey->s0[i][tag] = 1;
        for(j = 0; j < length; j++){
            if(j != tag){
                prikey->s0[i][j] = 0;
            }
            printf("%lu  ", prikey->s0[i][j]);
        }
        printf("\n");
    }

    printf("sk.fill:");
    for(i = 0; i < prikey->fill_cnt; i++){
        prikey->fill_s[i] = 0;
        printf("%lu ", prikey->fill_s[i]);
    }
    printf("\n");
}

void gen_sc_prikey(__sc_prikey* prikey, randstate rs){

    gen_prime(prikey->sk, prikey->sk_bit_cnt, rs);
    randomize_scs(prikey);

    time_t t;
    struct tm *lt;
    t = time(NULL);
    lt = localtime(&t);
    strftime(prikey->gen_time, 20, "%Y-%m-%d %H:%M:%S", lt);

}

void expand_sc_p2y(__sc_pubkey_set* pubkey, __sc_prikey* prikey, size_t prec, randstate rs){
    unsigned long i, j, k, l, t, cnt, length;
    mpz_t* yy;
    mpz_t rn,ui;
    mpf_t nu,de, bb;  //de 分母 nu 分子

    mpz_init(rn);
    mpz_init(ui);
    mpf_init(nu);
    mpf_init(de);
    mpf_init_set_ui(bb, BASE);
    yy = (mpz_t*)malloc(prikey->rsub_hw * sizeof(mpz_t));
    randomize_sk(yy, prikey->sk, prikey->rsub_hw, prec);

    mpz_ui_pow_ui(ui,BASE,prec+1);
    mpf_pow_ui(de,bb,prec);


    cnt = t = 0;
    for(i = 0; i < prikey->s0_group_cnt; i++){
        for(j = 0; j < prikey->s1_group_cnt; j++){
            if(j == prikey->s1_group_cnt - 1){
                length = prikey->last_group_length;
            }else{
                length = prikey-> every_group_length;
            }

            for(k = 0; k < prikey->every_group_length; k++){
                for(l = 0; l < length; l++){
                    if(t < prikey->rsub_hw){
                        if(prikey->s0[i][k] * prikey->s1[j][l] == 1){
                            mpf_set_z(nu,yy[j]);
                            t++;
                        }else{
                            gen_urandomm(rn, rs, ui);
                            mpf_set_z(nu,rn);
                        }
                    }else{
                        gen_urandomm(rn, rs, ui);
                        mpf_set_z(nu,rn);
                    }
                    mpf_div(pubkey->y[i],nu,de);
                    cnt++;
                }
            }
        }
    }

    for(i = 0; i < prikey->fill_cnt; i++){
        gen_urandomm(rn, rs, ui);
        mpf_set_z(nu,rn);
        mpf_div(pubkey->y[cnt],nu,de);
        cnt++;
    }

    for(i = 0; i < prikey->rsub_hw; i++) mpz_clear(yy[i]);
    free(yy);
    mpz_clear(rn);
    mpz_clear(ui);
    mpf_clear(nu);
    mpf_clear(de);
    mpf_clear(bb);
}

void scXX(__sc_pubkey_set* pubkey, unsigned long index, randstate rs, size_t Rho, int type){

    unsigned long r;
    mpz_t rn;
    mpz_t pro;
    mpz_init(pro);
    mpz_init(rn);

    gen_rrandomb(rn, rs, Rho);
    r = LIMB(rn, 0);
    r = (r % pubkey->beta == 0 ? 1UL : r % pubkey->beta);
    mpz_mul(pro, pubkey->pk_vector1[r], pubkey->pk_vector2[r]);
    mpz_mul_ui(pro, pro, 2);
    mpz_mod(pro, pro, pubkey->x0);
    mpz_mul_ui(rn, rn, 2);
    mpz_add_ui(rn, rn, 1);
    if(type == 0){
        mpz_add(pubkey->s0_vector[index], rn, pro);
    }else if(type == 1){
        mpz_add(pubkey->s1_vector[index], rn, pro);
    }

    mpz_clear(rn);
    mpz_clear(pro);
}

void encrypt_sc_sk(__sc_pubkey_set* pubkey, __sc_prikey* prikey, randstate rs, size_t Rho){
    unsigned long i;

    for(i = 0; i < prikey->s0_group_cnt * prikey->every_group_length; i++){
        if(prikey->s0[i / prikey->every_group_length][i % prikey->every_group_length]==1){
            scXX(pubkey, i, rs, Rho, 0);
        }
    }

    for(i = 0; i < (prikey->s1_group_cnt - 1) * prikey->every_group_length; i++){
        if(prikey->s1[i / prikey->every_group_length][i % prikey->every_group_length]==1){
            scXX(pubkey, i, rs, Rho, 1);
        }
    }

    int t = (prikey->s1_group_cnt - 1) * prikey->every_group_length;

    for(i = 0; i < prikey->last_group_length; i++){
        if(prikey->s1[prikey->s1_group_cnt - 1][i] == 1){
            scXX(pubkey, t + i, rs, Rho, 1);
        }
    }
}

void gen_sc_pubkey(__sc_pubkey_set* pubkey, __sc_prikey* prikey, __sec_setting* para, randstate rs, int model){

    int i;
    mpz_t* qs;
    mpz_t rn;
    mpz_init(rn);
    qs = (mpz_t*)malloc(para->tau * sizeof(mpz_t));
    getQs(qs, prikey->sk, pubkey->pk_bit_cnt, 2 * pubkey->beta + 1, para->lam, rs);


    gen_rrandomb(rn, rs, para->rho);
    mpz_mul(pubkey->x0, prikey->sk, qs[0]);

    for(i = 1; i <= pubkey->beta; i++){

        gen_rrandomb(rn, rs, para->rho);//////modifiy
        mpz_mul(pubkey->pk_vector1[i - 1], prikey->sk, qs[i]);
        mpz_add(pubkey->pk_vector1[i - 1], pubkey->pk_vector1[i - 1], rn);

        gen_rrandomb(rn, rs, para->rho);//////modifiy
        mpz_mul(pubkey->pk_vector2[i - 1], prikey->sk, qs[i + pubkey->beta]);
        mpz_add(pubkey->pk_vector2[i - 1], pubkey->pk_vector2[i - 1], rn);

    }

    if(model == 1){
        encrypt_sc_sk(pubkey, prikey, rs, para->Rho);
    }
    time_t t;
    struct tm *lt;
    t = time(NULL);
    lt = localtime(&t);
    strftime(pubkey->gen_time, 20, "%Y-%m-%d %H:%M:%S", lt);
    mpz_clear(rn);
}
