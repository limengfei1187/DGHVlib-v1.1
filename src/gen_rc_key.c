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


void gen_rc_prikey(__rc_prikey* prikey, randstate rs){
    gen_prime(prikey->sk, prikey->sk_bit_cnt, rs);
    gen_prime(prikey->rsk, prikey->rsk_bit_cnt, rs);
    randomize_ss(prikey->sk_rsub, prikey->rsub_hw, prikey->rsub_size);
}


void gen_rc_pubkey(__rc_pubkey_set* pubkey, __rc_prikey* prikey, __sec_setting* para){

    unsigned long i;
    mpz_t kai, ksi, rnd, q;
    mpz_t u_kai, u_ksi, u_rnd;
    randstate rs_kai, rs_ksi, rs_rnd;

    mpz_init(q);
    mpz_init(kai);
    mpz_init(ksi);
    mpz_init(rnd);
    mpz_init(u_kai);
    mpz_init(u_ksi);
    mpz_init(u_rnd);

    pubkey->seed = get_seed();
    set_randstate(rs_kai, pubkey->seed);
    set_randstate(rs_ksi, pubkey->seed * 2);
    set_randstate(rs_rnd, pubkey->seed * 3);

    mpz_ui_pow_ui(u_kai, 2, para->gam);
    mpz_ui_pow_ui(u_ksi, 2, para->lam + para->eta);
    mpz_ui_pow_ui(u_rnd, 2, para->rho);
    mpz_fdiv_q(u_ksi, u_ksi, prikey->sk);

    for(i = 0; i < pubkey->pks_size; i++){
        gen_urandomm(kai, rs_kai, u_kai);
        gen_urandomm(ksi, rs_ksi, u_ksi);
        gen_urandomm(rnd, rs_rnd, u_rnd);

        mpz_mod(kai, kai, prikey->sk);
        mpz_mul(ksi, ksi, prikey->sk);

        mpz_add(pubkey->delta[i], kai, ksi);
        mpz_sub(pubkey->delta[i], pubkey->delta[i], rnd);

    }

    mpz_ui_pow_ui(q, 2, para->gam);
    mpz_fdiv_q(q, q, prikey->sk);
    gen_urandomm(q, rs_rnd, q);
    if(mpz_odd_p(q) == 0){
        gen_urandomm(q, rs_rnd, q);
    }
    mpz_mul(pubkey->x0, q, prikey->sk);

    time_t t;
    struct tm *lt;
    t = time(NULL);
    lt = localtime(&t);
    strftime(pubkey->gen_time, 20, "%Y-%m-%d %H:%M:%S", lt);


    mpz_clear(q);
    mpz_clear(kai);
    mpz_clear(ksi);
    mpz_clear(rnd);
    mpz_clear(u_kai);
    mpz_clear(u_ksi);
    mpz_clear(u_rnd);


}

void randomize_rsk(mpz_t* yy, mpz_t p, size_t rsk_bit_cnt, size_t ss_hw, size_t prec){

    unsigned long i, j;
    mpz_t qz, r,res, xp;
    mpf_t vf, pf, uf ,ba;

    mpz_init(qz);
    mpz_init(r);
    mpz_init(res);
    mpz_init(xp);
    mpf_init(vf);
    mpf_init(pf);
    mpf_init(uf);
    mpf_init_set_ui(ba, BASE);

    mpf_set_z(pf, p);
    mpf_pow_ui(uf, ba, rsk_bit_cnt);
    mpf_div(vf, uf, pf);


    mpz_ui_pow_ui(xp, BASE, prec);
    mpf_set_z(uf, xp);
    mpf_mul(vf, vf, uf);
    mpf_round_mpz(xp, vf);

    mpz_fdiv_qr_ui(qz, r, xp, ss_hw);
    for(i=0; i<ss_hw; i++){

        mpz_add(yy[i], yy[i], qz);
    }
    mpz_add(yy[i-1], yy[i-1], r);

    for(i=0; i<ss_hw; i++){
       mpz_fdiv_qr_ui(qz, r, yy[i], rand()%ss_hw+1);
       mpz_add(res, qz, r);
       mpz_sub(yy[i], yy[i], res);

       mpz_fdiv_qr_ui(qz, r, res, ss_hw);
       mpz_add(res,r,qz);

       for(j=0; j<ss_hw; j++){
           if(j==i){
               mpz_add(yy[j], yy[j], res);

           }else{
               mpz_add(yy[j], yy[j], qz);
           }
       }
   }

   mpz_clear(qz);
   mpz_clear(r);
   mpz_clear(res);
   mpz_clear(xp);
   mpf_clear(vf);
   mpf_clear(pf);
   mpf_clear(uf);
   mpf_clear(ba);

}

void expand_rc_p2y(__rc_pubkey_set* pubkey, __rc_prikey* prikey, size_t prec, randstate rs){
    int i, j;
    mpz_t* yy;
    mpz_t rn,ui;
    mpf_t nu,de, bb;  //de 分母 nu 分子

    mpz_init(rn);
    mpz_init(ui);
    mpf_init(nu);
    mpf_init(de);
    mpf_init_set_ui(bb, BASE);
    yy = (mpz_t*)malloc(prikey->rsub_hw * sizeof(mpz_t));
    for(i = 0; i < prikey->rsub_hw; i++){
        mpz_init_set_ui(yy[i], 0);
    }

    randomize_rsk(yy, prikey->sk, prikey->rsk_bit_cnt, prikey->rsub_hw, prec);

    mpz_ui_pow_ui(ui,BASE,prec+1);
    mpf_pow_ui(de,bb,prec);

    for(i=0, j=0; i<pubkey->y_size; i++){
       if(mpz_cmp_ui(prikey->sk_rsub[i], 0) == 0){
           gen_urandomm(rn, rs, ui);
           mpf_set_z(nu,rn);
       }else if(mpz_cmp_ui(prikey->sk_rsub[i], 1) == 0){
           mpf_set_z(nu,yy[j]);
           j++;
       }
       mpf_div(pubkey->y[i],nu,de);
    }

    for(i = 0; i < prikey->rsub_hw; i++) mpz_clear(yy[i]);
    if(yy != NULL) free(yy);
    mpz_clear(rn);
    mpz_clear(ui);
    mpf_clear(nu);
    mpf_clear(de);
    mpf_clear(bb);
}
