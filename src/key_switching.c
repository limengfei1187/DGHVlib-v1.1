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


void Powersof2(mpf_t** s_expand, mpz_t* s, unsigned long length, unsigned long k){
    int i, j;
    mpf_t weight, fb;
    mpf_init(weight);
    mpf_init_set_ui(fb, BASE);
    for(i = k - 1; i >= 0; i--){
        mpf_pow_ui(weight, fb, i);
        for(j = 0; j < length; j++){
            if(mpz_cmp_ui(s[j], 1) == 0){
                mpf_set(s_expand[k-i-1][j], weight);
            }
        }
    }
    mpf_clear(weight);
}

void gen_switch_key(__rc_prikey* prikey, __rc_pubkey_set* pubkey, __sec_setting* para){
    unsigned long i, j, seed;
    randstate rs;
    mpz_t r, ur, q, rq;
    mpf_t** s_expand;

    mpz_init(r);
    mpz_init(ur);

    mpz_init(q);
    mpz_init(rq);

    s_expand = (mpf_t**)malloc(sizeof(mpf_t*) * (prikey->rsk_bit_cnt + 1));
    for(i = 0; i < prikey->rsk_bit_cnt + 1; i++){
        s_expand[i] = (mpf_t*)malloc(sizeof(mpf_t) * prikey->rsub_size);
        for(j = 0; j < prikey->rsub_size; j++){
            mpf_init_set_ui(s_expand[i][j], 0);
        }
    }

    seed = get_seed();
    set_randstate(rs, seed);

    mpz_ui_pow_ui(q, 2, para->gam);
    mpz_fdiv_q(q, q, prikey->rsk);
    gen_urandomm(rq, rs, q);

    while(mpz_odd_p(rq) == 0){
        gen_urandomm(rq, rs, q);
    }
    mpz_mul(pubkey->rx0, rq, prikey->rsk);
    mpz_fdiv_q_ui(rq, rq, 4);

    Powersof2(s_expand, prikey->sk_rsub, prikey->rsub_size, prikey->rsk_bit_cnt + 1);

    mpz_ui_pow_ui(ur, BASE, para->rho);

    mpz_t N, tmp;
    mpf_t val, rpf, ref;

    mpz_init(N);
    mpz_init(tmp);
    mpf_init(val);
    mpf_init(rpf);
    mpf_init(ref);
    mpf_set_z(rpf, prikey->rsk);

    mpf_div_2exp(val, rpf, prikey->rsk_bit_cnt + 1);

    for(i = 0; i < prikey->rsk_bit_cnt + 1; i++){
        for(j = 0; j < prikey->rsub_size; j++){
            if(j == 0 && mpz_cmp_ui(prikey->sk_rsub[j], 1) == 0){
                gen_urandomm(q, rs, rq);
                gen_urandomm(r, rs, ur);
                mpz_mul(N, q, prikey->rsk);
                mpz_add(pubkey->sigma[i][j], N, r);

            }

            mpf_mul(ref, s_expand[i][j], val);
            mpf_round_mpz(tmp, ref);

            mpz_add(pubkey->sigma[i][j], pubkey->sigma[i][j], tmp);
        }
    }

    mpz_clear(r);
    mpz_clear(ur);
    mpz_clear(q);
    mpz_clear(rq);
    mpz_clear(N);
    mpz_clear(tmp);

    mpf_clear(val);
    mpf_clear(rpf);
    mpf_clear(ref);
    for(i = 0; i < prikey->rsk_bit_cnt + 1; i++){
        for(j = 0; j < prikey->rsub_size; j++){
            mpf_clear(s_expand[i][j]);
        }
        if(s_expand[i] != NULL) free(s_expand[i]);

    }

    if(s_expand != NULL) free(s_expand);

}
