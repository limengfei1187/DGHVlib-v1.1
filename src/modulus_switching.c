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

 void BitDecomp(unsigned long** c_expand, mpz_t* z, unsigned long length, unsigned long k){
     unsigned long i, j;
     int binary_length;
     char *binary_str;

     binary_str = (char *)malloc((k+2)*sizeof(char));

     for(i = 0; i < length; i++){
         mpz_get_str(binary_str, 2, z[i]);
         mpz_clear(z[i]);
         binary_length = strlen(binary_str);
         if(binary_length < k && binary_length >= 0){
             for(j = 0; j < k - binary_length; j++){
                 c_expand[i][j]=0;
             }
             for(j = k - binary_length; j < k; j++){
                 c_expand[i][j]=binary_str[j - k + binary_length] - '0';
             }
         }else if(binary_length >= k){
            for(j = 0; j < k; j++){
                c_expand[i][j]=binary_str[j] - '0';
            }
        }
    }
    free(binary_str);
 }

 void mod_switch(__cit* new, __cit* old, __rc_pubkey_set* pubkey, __sec_setting* para){

     unsigned long i, j;
     mpz_t pro, lsb;

     mpz_init(pro);
     mpz_init(lsb);

     unsigned long** c_expand = (unsigned long**)malloc(sizeof(unsigned long*) * para->Theta);

     for(i = 0; i < para->Theta; i++){
         c_expand[i] = (unsigned long*)malloc(sizeof(unsigned long) * (para->eta - para->Rho + 1));

     }

     BitDecomp(c_expand, old->zt, para->Theta,para->eta - para->Rho + 1);

     for(i = 0; i < para->eta - para->Rho + 1; i++){
         for(j = 0; j < para->Theta; j++){
             mpz_mul_ui(pro, pubkey->sigma[i][j], c_expand[j][i]);
             mpz_mul_ui(pro,pro,2);
             mpz_set_ui(new->c, 0);
             mpz_add(new->c, new->c, pro);
         }
     }

     mpz_mod(new->c, new->c, pubkey->rx0);
     mpz_mod_ui(lsb, old->c, 2);
     mpz_add(new->c, new->c, lsb);

     mpz_clear(lsb);
     mpz_clear(pro);

 }
