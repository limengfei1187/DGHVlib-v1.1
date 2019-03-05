#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "dghv.h"



int main(){

    int i, j;
    double duration;
    clock_t start,finish;


    unsigned long Num1[8] = {0, 0, 0, 1, 0, 0, 0, 0};
    unsigned long Num2[8] = {0, 0, 0, 1, 0, 0, 0, 1};
    unsigned long Sum[8];

    c_parameters para;
    c_prikey prikey;
    c_pubkeys pubkey;

    printf("初始化参数...\n");
    init_sec_para(&para);
    set_default_para(para, TOY);
    printf("参数级别位TOY...\n");
    printf("\t安全参数：lam = %lu\n", para->lam);
    printf("\t公钥噪音比特长度：rho = %lu\n", para->rho);
    printf("\t加密噪音比特长度：Rho = %lu\n", para->Rho);
    printf("\t密钥比特长度：eta = %lu\n", para->eta);
    printf("\t公钥比特长度：gam = %lu\n", para->gam);
    printf("\t随机稀疏子集：Theta = %lu\n", para->Theta);
    printf("\t随机稀疏子集汉明权重：theta = %lu\n", para->theta);
    printf("\t保留小数点位数：n = %lu\n", para->n);
    printf("\t公钥长度：tau = %lu\n", para->tau);
    printf("\t实数运算精度：prec = %lu\n", para->prec);

    mpf_set_default_prec(2 * para->eta + para->gam);

    unsigned long seed = get_seed();
    randstate rs;
    set_randstate(rs, seed);

    printf("初始化私钥\n");
    start = clock();
    init_sk(&prikey, para);
    gen_prikey(prikey, rs);
    finish = clock();
    printf( "产生私钥CPU时间:%.15f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
    save_prikey(prikey, "prikey");
    printf("私钥产生成功\n");

    printf("初始化公钥\n");
    start = clock();
    init_pkset(&pubkey, para);
    gen_pubkey(pubkey, prikey, para, rs, 1);
    finish = clock();
    printf( "产生公钥CPU时间:%.15f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
    save_pubkey(pubkey, "pubkey");
    printf("公钥产生成功\n");

    printf("秘钥扩展\n");
    start = clock();
    expand_p2y(pubkey, prikey, para->prec, rs);
    finish = clock();
    printf( "密钥扩展CPU时间:%.15f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
    printf("秘钥扩展成功\n");





//整数加法同态运算
    c_cit CNum1[8];
    c_cit CNum2[8];
    c_cit CSum[8];

    for(i = 0; i < 8; i++){
        init_cit(&CNum1[i], para->Theta);
        init_cit(&CNum2[i], para->Theta);
        init_cit(&CSum[i], para->Theta);
    }

    char** CNum1_buffer = (char**)malloc(sizeof(char*) * 8);
    char** CNum2_buffer = (char**)malloc(sizeof(char*) * 8);
    printf("开始加密CNum1=00010000\n");
    printf("开始加密CNum2=00010001\n");
    start = clock();
    for(i = 0; i < 8; i++){
        DGHV_encrypt(CNum1[i], Num1[i], pubkey, para, rs);
        CNum1_buffer[i] = (char*)malloc(sizeof(char) * para->prec);
        mpz_get_str(CNum1_buffer[i], 16, CNum1[i]->c);
        DGHV_encrypt(CNum2[i], Num2[i], pubkey, para, rs);
        CNum2_buffer[i] = (char*)malloc(sizeof(char) * para->prec);
        mpz_get_str(CNum2_buffer[i], 16, CNum1[i]->c);

        expend_cit(CNum1[i], pubkey);
        expend_cit(CNum2[i], pubkey);
       // printf("%lu", DGHV_decrypt(CNum2[i], prikey));


    }

    finish = clock();
    printf( "平均加密CPU时间:%.15f seconds\n", (double)(finish - start) / (CLOCKS_PER_SEC * 16));


    printf("加密成功\n");
    save_str(CNum1_buffer, 8, "CNum1");
    save_str(CNum2_buffer, 8, "CNum2");



    c_cit CPre, CNext, CTmp1, CTmp2, CTmp3, CNew;
    init_cit(&CPre, para->Theta);
    init_cit(&CNext, para->Theta);
    init_cit(&CTmp1, para->Theta);
    init_cit(&CTmp2, para->Theta);
    init_cit(&CTmp3, para->Theta);
    init_cit(&CNew, para->Theta);
    DGHV_encrypt(CPre, 0, pubkey, para, rs);
    expend_cit(CPre, pubkey);

    printf("执行同态加法运算：CNum1+CNum2\n");
    start = clock();
    for(i = 7; i >= 0; i--){
        evaluate_add(CSum[i], CNum1[i], CNum2[i], pubkey->x0);
        evaluate_add(CSum[i], CSum[i], CPre, pubkey->x0);
        expend_cit(CSum[i], pubkey);
        printf("第%d位运算成功\n", i+1);
        if(i > 0){
            evaluate_mul(CNext, CNum1[i], CNum2[i], pubkey->x0);
            evaluate_mul(CTmp1, CNum1[i], CPre, pubkey->x0);
            evaluate_mul(CTmp2, CPre, CNum2[i], pubkey->x0);
            evaluate_add(CTmp3, CTmp1, CTmp2, pubkey->x0);
            evaluate_add(CPre, CNext, CTmp3, pubkey->x0);

            expend_cit(CPre, pubkey);
            bootstrap(CNew, CPre, pubkey, para, rs);
            printf("进位密文刷新成功\n");
            mpz_set(CPre->c, CNew->c);
        }
    }

    finish = clock();
    printf( "同态加法运算CPU时间:%.15f seconds\n", (double)(finish - start) / (CLOCKS_PER_SEC ));

    printf("运算结果解密\n");
    for(i = 0; i < 8; i++){
        Sum[i] = DGHV_decrypt(CSum[i], prikey);
        mpz_get_str(CNum1_buffer[i], 16, CSum[i]->c);
        printf("%lu", Sum[i]);
    }

    save_str(CNum1_buffer, 8, "CSum");
    printf("\n");


    //求补同态运算

    printf("执行同态求补运算：comp(-CNum1)\n");
    DGHV_encrypt(CPre, 0, pubkey, para, rs);

    DGHV_encrypt(CNum1[0], 1, pubkey, para, rs);

    start = clock();
    for(i = 7; i >=1; i--){

        evaluate_mul(CTmp1, CNum1[0], CPre, pubkey->x0);
        evaluate_add(CSum[i], CNum1[i], CTmp1, pubkey->x0);

        evaluate_mul(CTmp2, CNum1[i], CPre, pubkey->x0);
        evaluate_add(CTmp3, CNum1[i], CPre, pubkey->x0);

        evaluate_add(CNext, CTmp2, CTmp3, pubkey->x0);
        expend_cit(CNext, pubkey);
        bootstrap(CNew, CNext, pubkey, para, rs);
        printf("第%d位运算成功\n", i);
        printf("进位密文刷新成功\n");
        mpz_set(CSum[0]->c, CNum1[0]->c);


    }
    mpz_set(CPre->c, CNext->c);

    DGHV_encrypt(CSum[1], 1, pubkey, para, rs);
    DGHV_encrypt(CSum[2], 1, pubkey, para, rs);

    finish = clock();
    printf( "同态求补运算CPU时间:%.15f seconds\n", (double)(finish - start) / (CLOCKS_PER_SEC ));

    printf("运算结果解密\n");
    for(i = 0; i < 8; i++){
        Sum[i] = DGHV_decrypt(CSum[i], prikey);
        mpz_get_str(CNum1_buffer[i], 16, CSum[i]->c);
        printf("%lu", Sum[i]);
    }

    save_str(CNum1_buffer, 8, "Comp");
    printf("\n");


    //减法同态运算

    printf("执行同态减法运算：CNum2-CNum1\n");

    DGHV_encrypt(CPre, 0, pubkey, para, rs);
    expend_cit(CPre, pubkey);


    start = clock();
    for(i = 7; i >= 0; i--){
        evaluate_add(CSum[i], CNum1[i], CNum2[i], pubkey->x0);
        evaluate_add(CSum[i], CSum[i], CPre, pubkey->x0);
        expend_cit(CSum[i], pubkey);
        printf("第%d位运算成功\n", i+1);

            evaluate_mul(CNext, CNum1[i], CNum2[i], pubkey->x0);
            evaluate_mul(CTmp1, CNum1[i], CPre, pubkey->x0);
            evaluate_mul(CTmp2, CPre, CNum2[i], pubkey->x0);
            evaluate_add(CTmp3, CTmp1, CTmp2, pubkey->x0);
            evaluate_add(CPre, CNext, CTmp3, pubkey->x0);

            expend_cit(CPre, pubkey);
            bootstrap(CNew, CPre, pubkey, para, rs);
            printf("进位密文刷新成功\n");
            mpz_set(CPre->c, CNew->c);

    }

    evaluate_add(CSum[0], CSum[0], CSum[0], pubkey->x0);

    finish = clock();
    printf( "同态减法运算CPU时间:%.15f seconds\n", (double)(finish - start) / (CLOCKS_PER_SEC ));

    printf("运算结果解密\n");
    for(i = 0; i < 8; i++){
        Sum[i] = DGHV_decrypt(CSum[i], prikey);
        mpz_get_str(CNum1_buffer[i], 16, CSum[i]->c);
        printf("%lu", Sum[i]);
    }

    save_str(CNum1_buffer, 8, "CSub");
    printf("\n");


    return 0;
}
