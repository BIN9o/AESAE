#include "aes.h"
#include <stdio.h>
//state 是80个大小的数组
uint8_t *key;//常量定义
uint8_t *AD;
uint8_t const0[16] = {
	   0x00, 0x01, 0x01, 0x02,
	   0x03, 0x05, 0x08, 0x0d,
	   0x15, 0x22, 0x37, 0x59,
	   0x90, 0xe9, 0x79, 0x62
};
uint8_t const1[16] = {
	   0xdb, 0x3d, 0x18, 0x55,
	   0x6d, 0xc2, 0x2f, 0xf1,
	   0x20, 0x11, 0x31, 0x42,
	   0x73, 0xb5, 0x28, 0xdd
};
uint8_t IV[16] = {
	   0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00 
};
uint8_t k[16] = {
	   0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00,
	   0x00, 0x00, 0x00, 0x00
};
void fuzhi(uint8_t *k) {
	key = k;
	printf("key:\n");
	for (int i = 0; i < 4; i++) {
		printf("%x %x %x %x ", key[4 * i + 0], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
	}
	printf("\n");
}

//ab异或运算 结果传d
uint8_t* add(uint8_t a[], uint8_t b[]) { 
	uint8_t *d=new uint8_t[16];
	for (int i = 0; i < 16; i++) {
		d[i] = a[i] ^ b[i];
	}
	return d;
}
//ab异或运算 结果传d
uint8_t* AND(uint8_t a[], uint8_t b[]) { 
	uint8_t *d = new uint8_t[16];
	for (int i = 0; i < 16; i++) {
		d[i] = a[i] & b[i];
	}
	return d;
}

//AES 轮函数 返回结果
uint8_t *AESRound(uint8_t *state, uint8_t *w) {//state 16byte w 16byte
	sub_bytes(state);
	shift_rows(state);
	mix_columns(state);
	add_round_key(state, w, 0);
	return state;
}
//状态更新函数
void state_update128(uint8_t *state[5], uint8_t *m) {//state[5][16] 80byte, m 16byte
	uint8_t i,j;
	uint8_t sp[5][16];//保存当前状态
	uint8_t *temp=new uint8_t[16];

	// 当前状态赋值
	for (i = 0; i < 5; i++) {
		for(j = 0;j < 16; j++)
			sp[i][j] = state[i][j];
	}

	printf("\nstate_update128:before\n");
	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 16; j++)
			printf("%x ", state[i][j]);
		printf("\n");
	}
	// 5 轮变换
	temp=add(sp[0], m);//异或 sp0^m

	//这样赋值有问题
	//state[0] = AESRound(sp[4], temp);
	//state[1] = AESRound(sp[0], sp[1]);
	//state[2] = AESRound(sp[1], sp[2]);
	//state[3] = AESRound(sp[2], sp[3]);
	//state[4] = AESRound(sp[3], sp[4]);
	
	temp = AESRound(sp[4], temp);
	for (int i = 0; i < 16; i++) {
		state[0][i] = temp[i];
	}
	temp = AESRound(sp[0], sp[1]);
	for (int i = 0; i < 16; i++) {
		state[1][i] = temp[i];
	}
	temp = AESRound(sp[1], sp[2]);
	for (int i = 0; i < 16; i++) {
		state[2][i] = temp[i];
	}
	temp = AESRound(sp[2], sp[3]);
	for (int i = 0; i < 16; i++) {
		state[3][i] = temp[i];
	}
	temp = AESRound(sp[3], sp[4]);
	for (int i = 0; i < 16; i++) {
		state[4][i] = temp[i];
	}
	
	//state = s0 || s1  || s2 || s3 || s4
	printf("\nstate_update128:after\n");
	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 16; j++)
			printf("%x ", state[i][j]);
		printf("\n");
	}

}
/*
* 数据初始化函数是为了后边的加密阶段和认证码生成阶段提供系统参数
* 
*/
void initialization(uint8_t *state[5]) {
	uint8_t *temp1 = new uint8_t[16];
	uint8_t *temp2 = new uint8_t[16];
	uint8_t *temp3 = new uint8_t[16];
	uint8_t i;
	//m2i = key; 
	//m2i1 =temp1 ;// key^IV
	fuzhi(k);

	temp1=add(key, IV);
	temp2=add(key, const0);
	temp3=add(key, const1);
	//printf("temp1:add test:\n");
	//for (int i = 0; i < 16; i++) {
	//	printf("%x ", temp1[i]);
	//}
	//printf("\n");
	state[0] = temp1;
	state[1] = const1;
	state[2] = const0;
	state[3] = temp2;
	state[4] = temp3;
	printf("\n origin state\n");
	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 16; j++)
			printf("%2x ", state[i][j]);
		printf("\n");
	}
	//以上代码正确执行
	
	for (int i = -10; i < 0; i++) {
		printf("\n 10 round for NO.%d R \n",i);
		if (i % 2 == 0)
		{
			state_update128(state, key);
		}
		else
		{
			state_update128(state, temp1);
		}
		printf("\n after update\n");
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 16; j++)
				printf("%x ", state[i][j]);
			printf("\n");
		}

	}

	printf("\n 10 round result \n");
	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 16; j++)
			printf("%x ", state[i][j]);
		printf("\n");
	}
	//用相关数据AD进行更新
	;
}
//加密
void encryption(uint8_t *state[5], uint8_t *plaintext, uint8_t *ciphertext) {
	uint8_t v = 1;  //  msglen/128
	uint8_t  *C = new uint8_t[16];
	uint8_t **p = new uint8_t *[v];//开辟行空间
	for (int i = 0; i < v; i++)
		p[i] = new uint8_t[16];    //开辟列空间

	for (int i = 0; i < v; i++) {    //赋值
		for (int j = 0; j < 16; j++) {
			p[i][j] = plaintext[i*16+j];
			printf("%x", p[i][j]);
		}
	}
	for (int i = 0; i < v; i++) {
		//Ci=Pi + Su+i,1 + Su+i,4 + (Su+i,1 & Su+i,3);
		C = add(p[i], add(state[1], add(state[4], AND(state[2], state[3]))));
		state_update128(state, p[i]);
		for (int i = 0; i < 16; i++)
			ciphertext[i] = C[i];
	}
}
//认证码生成
void authentication(uint8_t *state[5], uint8_t *tag) {
	uint8_t *temp,*tag_temp;
	//temp= adlen || msglen  连接 adlen msglen各8 bit
	for (int i = 0; i < 7; i++)
	{
		state_update128(state, temp);
	}
	tag_temp = add(state[0], add(state[1], add(state[2], add(state[3], state[4]))));
	for (int i = 0; i < 16; i++) {
		tag[i] = tag_temp[i];
	}
}